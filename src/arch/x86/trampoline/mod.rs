use self::disasm::*;
use crate::arch::x86::thunk;
use crate::error::{Error, Result};
use crate::pic;
use alloc::boxed::Box;
use core::{mem, slice};
use iced_x86::{Decoder, DecoderOptions, Encoder, Instruction};

mod disasm;

/// A trampoline generator (x86/x64).
pub struct Trampoline {
  emitter: pic::CodeEmitter,
  prolog_size: usize,
  return_address: u64,
}

impl Trampoline {
  /// Constructs a new trampoline for an address.
  pub unsafe fn new(target: *const (), margin: usize) -> Result<Trampoline> {
    Builder::new(target, margin).build()
  }

  /// Returns a reference to the trampoline's code emitter.
  pub fn emitter(&self) -> &pic::CodeEmitter {
    &self.emitter
  }

  /// Returns the size of the prolog (i.e the amount of disassembled bytes).
  pub fn prolog_size(&self) -> usize {
    self.prolog_size
  }

  /// Returns the return address of the trampoline.
  pub fn return_address(&self) -> u64 {
    self.return_address
  }
}

/// A trampoline builder.
struct Builder {
  /// Target destination for a potential internal branch.
  branch_address: Option<usize>,
  /// Total amount of bytes disassembled.
  total_bytes_disassembled: usize,
  /// The preferred minimum amount of bytes disassembled.
  margin: usize,
  /// Whether disassembling has finished or not.
  finished: bool,
  /// The target the trampoline is adapted for.
  target: *const (),
}

impl Builder {
  /// Returns a trampoline builder.
  pub fn new(target: *const (), margin: usize) -> Self {
    Builder {
      branch_address: None,
      total_bytes_disassembled: 0,
      finished: false,
      target,
      margin,
    }
  }

  /// Creates a trampoline with the supplied settings.
  ///
  /// # Safety
  ///
  /// target..target+margin+15 must be valid to read as a u8 slice or behavior
  /// may be undefined
  pub unsafe fn build(mut self) -> Result<Trampoline> {
    let mut emitter = pic::CodeEmitter::new();
    let mut return_address = 0;

    // 15 = max size of x64 instruction
    // safety: we don't know the end address of a function so this could be too far
    // if the function is right at the end of the code section iced_x86 decoder
    // doesn't have a way to read one byte at a time without creating a slice in
    // advance and it's invalid to make a slice that's too long we could make a
    // new Decoder before reading every individual instruction? but it'd still need
    // to be given a 15 byte slice to handle any valid x64 instruction
    let target: *const u8 = self.target.cast();
    let slice = unsafe { slice::from_raw_parts(core::hint::black_box(target), self.margin + 15) };
    let decoder = Decoder::with_ip(
      (mem::size_of::<usize>() * 8) as u32,
      slice,
      self.target as u64,
      DecoderOptions::NONE,
    );
    for instruction in decoder {
      if instruction.is_invalid() {
        break;
      }
      self.total_bytes_disassembled += instruction.len();
      let instr_offset = instruction.ip() as usize - (self.target as usize);
      let instruction_bytes = &slice[instr_offset..instr_offset + instruction.len()];
      let thunk = self.process_instruction(&instruction, instruction_bytes)?;

      // If the trampoline displacement is larger than the target
      // function, all instructions will be displaced, and if there is
      // internal branching, it will end up at the wrong instructions.
      if self.is_instruction_in_branch(&instruction) && instruction.len() != thunk.len() {
        Err(Error::UnsupportedInstruction)?;
      } else {
        emitter.add_thunk(thunk);
      }

      // Determine whether enough bytes for the margin has been disassembled
      if self.total_bytes_disassembled >= self.margin && !self.finished {
        // Add a jump to the first instruction after the prolog
        return_address = instruction.next_ip();
        emitter.add_thunk(thunk::jmp(return_address as usize));
        self.finished = true;
      }

      if self.finished {
        break;
      }
    }

    Ok(Trampoline {
      prolog_size: self.total_bytes_disassembled,
      emitter,
      return_address,
    })
  }

  /// Returns an instruction after analysing and potentially modifies it.
  unsafe fn process_instruction(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
  ) -> Result<Box<dyn pic::Thunkable>> {
    if let Some(target) = instruction.rip_operand_target() {
      return self.handle_rip_relative_instruction(instruction, instruction_bytes, target as usize);
    } else if let Some(target) = instruction.relative_branch_target() {
      return self.handle_relative_branch(instruction, instruction_bytes, target as usize);
    } else if instruction.is_return() {
      // In case the operand is not placed in a branch, the function
      // returns unconditionally (i.e it terminates here).
      self.finished = !self.is_instruction_in_branch(instruction);
    }

    // The instruction does not use any position-dependant operands,
    // therefore the bytes can be copied directly from source.
    Ok(Box::new(instruction_bytes.to_vec()))
  }

  /// Adjusts the offsets for RIP relative operands. They are only available
  /// in x64 processes. The operands offsets needs to be adjusted for their
  /// new position. An example would be:
  ///
  /// ```asm
  /// mov eax, [rip+0x10]   ; the displacement before relocation
  /// mov eax, [rip+0x4892] ; theoretical adjustment after relocation
  /// ```
  unsafe fn handle_rip_relative_instruction(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
    target: usize,
  ) -> Result<Box<dyn pic::Thunkable>> {
    let displacement = target
      .wrapping_sub(instruction.ip() as usize)
      .wrapping_sub(instruction.len()) as isize;
    // If the instruction is an unconditional jump, processing stops here
    self.finished = instruction.is_unconditional_jump();

    // Nothing should be done if `displacement` is within the prolog.
    if (-(self.total_bytes_disassembled as isize)..0).contains(&displacement) {
      return Ok(Box::new(instruction_bytes.to_vec()));
    }

    // These need to be captured by the closure
    let instruction_len = instruction.len();
    let instruction = instruction.clone();

    Ok(Box::new(pic::UnsafeThunk::new(
      move |offset| {
        // Displacement is not always the last four bytes of the instruction.
        // Use proper instruction encoding for changing the displacement.
        let mut encoder = Encoder::new(64);

        encoder
          .encode(&instruction, offset as u64)
          .expect("could not encode instruction");
        let mut buf = encoder.take_buffer();

        if buf.len() > instruction_len {
          panic!("Encoded instruction length is greater than the original instruction.");
        }

        if buf.len() < instruction_len {
          // Add nops.
          buf.resize(instruction_len, 0x90);
        }

        buf
      },
      instruction_len,
    )))
  }

  /// Processes relative branches (e.g `call`, `loop`, `jne`).
  unsafe fn handle_relative_branch(
    &mut self,
    instruction: &Instruction,
    instruction_bytes: &[u8],
    destination_address_abs: usize,
  ) -> Result<Box<dyn pic::Thunkable>> {
    if instruction.is_call() {
      // Calls are not an issue since they return to the original address
      return Ok(thunk::call(destination_address_abs));
    }

    let prolog_range = (self.target as usize)..(self.target as usize + self.margin);

    // If the relative jump is internal, and short enough to
    // fit within the copied function prolog (i.e `margin`),
    // the jump instruction can be copied indiscriminately.
    if prolog_range.contains(&destination_address_abs) {
      // Keep track of the jump's destination address
      self.branch_address = Some(destination_address_abs);
      Ok(Box::new(instruction_bytes.to_vec()))
    } else if instruction.is_loop() {
      // Loops (e.g 'loopnz', 'jecxz') to the outside are not supported
      Err(Error::UnsupportedInstruction)
    } else if instruction.is_unconditional_jump() {
      // If the function is not in a branch, and it unconditionally jumps
      // a distance larger than the prolog, it's the same as if it terminates.
      self.finished = !self.is_instruction_in_branch(instruction);
      Ok(thunk::jmp(destination_address_abs))
    } else {
      // Conditional jumps (Jcc)
      // To extract the condition, the primary opcode is required. Short
      // jumps are only one byte, but long jccs are prefixed with 0x0F.
      let primary_opcode = instruction_bytes
        .iter()
        .find(|op| **op != 0x0F)
        .expect("retrieving conditional jump primary op code");

      // Extract the condition (i.e 0x74 is [jz rel8] ⟶ 0x74 & 0x0F == 4)
      let condition = primary_opcode & 0x0F;
      Ok(thunk::jcc(destination_address_abs, condition))
    }
  }

  /// Returns whether the current instruction is inside a branch or not.
  fn is_instruction_in_branch(&self, instruction: &Instruction) -> bool {
    self
      .branch_address
      .map_or(false, |offset| instruction.ip() < offset as u64)
  }
}
