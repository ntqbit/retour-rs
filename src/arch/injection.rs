use crate::arch::x86::thunk;
use crate::error::Result;
use alloc::boxed::Box;
use core::arch::global_asm;

use crate::{allocator, pic::CodeEmitter};

use super::{
  memory::{self, POOL},
  Detour,
};

// Only for x64
global_asm!(
  r"
    .global __retour_injection64_start, __retour_injection64_end

    __retour_injection64_start:
        pushfq
        push rbp
        mov rbp, rsp
        and rsp, ~0xF
        sub rsp, 0x200
        
        fxsave [rsp]

        push qword ptr [rbp+0x8] # rflags
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
        push qword ptr [rbp] # rbp
        push rdx
        push rcx
        push rbx
        push rax
        
        sub rsp, 0x8 # keep the stack pointer aligned by 0x10
        push qword ptr [rbp+0x18]

        mov rcx, rsp
        call [rbp+0x10]

        pop qword ptr [rbp+0x18]
        add rsp, 0x8
        
        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop qword ptr [rbp]
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
        pop qword ptr [rbp+0x10]

        fxrstor [rsp]

        mov rsp, rbp
        pop rbp
        add rsp, 0x8
        popfq
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
  pub return_address: u64,
  pub _reserved: u64,
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
  pub rflags: u64,
  // TODO: add fields for the saved FPU registers
}

pub type InjectionHandler = extern "C" fn(*mut InjectionContext);

pub struct Injection {
  stub: allocator::ExecutableMemory,
  stub_entry: allocator::ExecutableMemory,
  detour: Detour,
}

impl Injection {
  pub unsafe fn new(target: *const (), injection: InjectionHandler) -> Result<Self> {
    let (stub, mut stub_entry) = {
      let mut pool = POOL.lock().unwrap();

      let stub = {
        let mut emitter = CodeEmitter::new();
        emitter.add_thunk(Box::new(injection_stub()));
        memory::allocate_pic(&mut pool, &emitter, target)?
      };

      let stub_entry = pool.allocate(target, 0x2E)?;

      (stub, stub_entry)
    };

    let detour = Detour::new(target, stub_entry.as_ptr() as *const ())?;
    let trampoline = detour.trampoline() as *const () as u64;

    {
      let mut emitter = CodeEmitter::new();
      emitter.add_thunk(thunk::push(trampoline));
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
