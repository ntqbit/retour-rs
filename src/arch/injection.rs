use crate::arch::x86::thunk;
use crate::error::Result;
use alloc::boxed::Box;
use core::arch::global_asm;

use crate::{allocator, pic::CodeEmitter};

use super::{
  detour::DetourBuilder,
  memory::{self, POOL},
  Detour,
};

// Only for x64
global_asm!(
  r"
    .global __retour_injection64_start, __retour_injection64_end

    __retour_injection64_start:
        pushfq

        sub qword ptr [rsp+0x20], 0x5     # Substract the branch instruction (call) length from the RIP.

        push rsp
        add qword ptr [rsp], 0x28 # restore the rsp value before entering the stub
        push rbp

        # Align the stack by 0x10 bytes. Required by calling conventions and for FPU registers
        mov rbp, rsp
        and rsp, ~0xF
        sub rsp, 0x200
        
        # Save FPU registers.
        fxsave [rsp]

        # Must be even numebr of pushes to keep the stack aligned by 0x10.
        # Save the registers.
        push qword ptr [rbp+0x10] # rflags
        push qword ptr [rbp+0x30] # rip
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push qword ptr [rbp+0x8]  # rsp
        push qword ptr [rbp]      # rbp
        push rdx
        push rcx
        push rbx
        push rax
        
        add rbp, 0x18
        sub rsp, 0x8              # Reserved
        push qword ptr [rbp+0x10] # Return address

        mov rdx, [rbp+0x8]        # Argument
        mov rcx, rsp              # Context
        call [rbp]

        pop qword ptr [rbp+0x18]  # Pop the return address.
        add rsp, 0x8              # Skip the argument.
        
        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop qword ptr [rbp]
        pop qword ptr [rbp+0x10]
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
        add rsp, 0x8              # Skip rip
        pop qword ptr [rbp+0x8]   # Pop rflags

        # Restore the FPU registers.
        fxrstor [rsp]

        # Temporarily set the new stack pointer.
        mov rsp, [rbp+0x10]

        # Push the return address on the new stack.
        push qword ptr [rbp+0x18]

        sub qword ptr [rbp+0x10], 0x8

        # Restore the stack skipping the header.
        mov rsp, rbp

        # Restore rbp
        pop rbp

        # Restore rflags.
        popfq

        # Pop the rsp.
        pop rsp

        # Return to the procedure.
        ret
    __retour_injection64_end:
"
);

extern "C" {
  fn __retour_injection64_start();
  fn __retour_injection64_end();
}

fn injection_stub() -> &'static [u8] {
  unsafe {
    core::slice::from_raw_parts(
      __retour_injection64_start as *const u8,
      (__retour_injection64_end as *const u8).offset_from(__retour_injection64_start as *const u8)
        as usize,
    )
  }
}

#[repr(packed)]
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub struct InjectionContext {
  pub return_address: usize,
  pub reserved: usize,
  pub cpu_context: CpuContext,
}

#[repr(packed)]
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
  pub rax: u64,
  pub rbx: u64,
  pub rcx: u64,
  pub rdx: u64,
  pub rbp: u64,
  pub rsp: u64,
  pub rsi: u64,
  pub rdi: u64,
  pub r8: u64,
  pub r9: u64,
  pub r10: u64,
  pub r11: u64,
  pub r12: u64,
  pub r13: u64,
  pub r14: u64,
  pub r15: u64,
  pub rip: u64,
  pub rflags: u64,
  // TODO: add fields for the saved FPU registers
}

pub type InjectionHandler = unsafe extern "C" fn(*mut InjectionContext, argument: usize);

pub struct Injection {
  stub: allocator::ExecutableMemory,
  stub_entry: allocator::ExecutableMemory,
  detour: Detour,
}

impl Injection {
  pub unsafe fn new(
    target: *const (),
    injection: InjectionHandler,
    argument: usize,
  ) -> Result<Self> {
    let (stub, mut stub_entry) = {
      let mut pool = POOL.lock().unwrap();

      let stub = {
        let mut emitter = CodeEmitter::new();
        emitter.add_thunk(Box::new(injection_stub()));
        memory::allocate_pic(&mut pool, &emitter, target)?
      };

      let stub_entry = pool.allocate(target, 0x3E)?;

      (stub, stub_entry)
    };

    let detour = DetourBuilder::new(target, stub_entry.as_ptr() as *const ())
      .branch(super::x86::BranchType::Call)
      .build()?;
    let trampoline = detour.trampoline() as *const () as u64;

    {
      let mut emitter = CodeEmitter::new();
      emitter.add_thunk(thunk::push(trampoline));
      emitter.add_thunk(thunk::push(argument as u64));
      emitter.add_thunk(thunk::push(injection as u64));
      emitter.add_thunk(thunk::jmp(stub.as_ptr() as usize));
      let code = emitter.emit(stub_entry.as_ptr() as *const _);
      stub_entry.copy_from_slice(code.as_slice());
    }

    Ok(Self {
      stub,
      stub_entry,
      detour,
    })
  }

  /// Enables the detour.
  pub unsafe fn enable(&self) -> Result<()> {
    self.detour.enable()
  }

  /// Disables the detour.
  pub unsafe fn disable(&self) -> Result<()> {
    self.detour.disable()
  }

  /// Returns whether the detour is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.detour.is_enabled()
  }

  /// Returns a reference to the generated trampoline.
  pub fn trampoline(&self) -> &() {
    self.detour.trampoline()
  }

  /// Returns the return address of the trampoline.
  pub fn trampoline_return_address(&self) -> u64 {
    self.detour.trampoline_return_address()
  }

  /// Returns the return address of the stub.
  pub fn stub_address(&self) -> u64 {
    self.stub.as_ptr() as u64
  }

  /// Returns the return address of the stub.
  pub fn stub_entry_address(&self) -> u64 {
    self.stub_entry.as_ptr() as u64
  }
}

pub struct ClosureInjection {
  closure: *mut Box<dyn FnMut(*mut InjectionContext)>,
  injection: Injection,
}

extern "C" fn __closure_injection(ctx: *mut InjectionContext, argument: usize) {
  unsafe {
    (*(argument as *mut Box<dyn FnMut(*mut InjectionContext)>))(ctx);
  }
}

impl ClosureInjection {
  pub unsafe fn new(
    target: *const (),
    closure: Box<dyn FnMut(*mut InjectionContext)>,
  ) -> Result<Self> {
    let closure_raw = Box::into_raw(Box::new(closure));

    Ok(Self {
      closure: closure_raw,
      injection: Injection::new(
        target,
        __closure_injection,
        closure_raw as *const () as usize,
      )?,
    })
  }

  /// Enables the detour.
  pub unsafe fn enable(&self) -> Result<()> {
    self.injection.enable()
  }

  /// Disables the detour.
  pub unsafe fn disable(&self) -> Result<()> {
    self.injection.disable()
  }

  /// Returns whether the detour is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.injection.is_enabled()
  }

  /// Returns a reference to the generated trampoline.
  pub fn trampoline(&self) -> &() {
    self.injection.trampoline()
  }

  /// Returns the return address of the trampoline.
  pub fn trampoline_return_address(&self) -> u64 {
    self.injection.trampoline_return_address()
  }

  /// Returns the return address of the stub.
  pub fn stub_address(&self) -> u64 {
    self.injection.stub_address()
  }

  /// Returns the return address of the stub.
  pub fn stub_entry_address(&self) -> u64 {
    self.injection.stub_entry_address()
  }
}

impl Drop for ClosureInjection {
  fn drop(&mut self) {
    unsafe {
      core::mem::drop(Box::from_raw(self.closure));
    }
  }
}
