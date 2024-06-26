use once_cell::sync::Lazy;

use crate::fstd::Mutex;
use crate::{allocator, arch, error::Result, pic};

/// Shared allocator for all detours.
pub static POOL: Lazy<Mutex<allocator::ThreadAllocator>> = Lazy::new(|| {
  // Use a range of +/- 2 GB for seeking a memory block
  Mutex::new(allocator::ThreadAllocator::new(arch::meta::DETOUR_RANGE))
});

/// Allocates PIC code at the specified address.
pub fn allocate_pic(
  pool: &mut allocator::ThreadAllocator,
  emitter: &pic::CodeEmitter,
  origin: *const (),
) -> Result<allocator::ExecutableMemory> {
  // Allocate memory close to the origin
  pool.allocate(origin, emitter.len()).map(|mut memory| {
    // Generate code for the obtained address
    let code = emitter.emit(memory.as_ptr() as *const _);
    memory.copy_from_slice(code.as_slice());
    memory
  })
}
