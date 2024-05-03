use super::memory;
use super::x86::BranchType;
use crate::error::{Error, Result};
use crate::{allocator, arch, util};
use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// An architecture-independent implementation of a base detour.
///
/// This class is never instantiated by itself, it merely exposes an API
/// available through it's descendants.
pub struct Detour {
  #[allow(dead_code)]
  relay: Option<allocator::ExecutableMemory>,
  trampoline: allocator::ExecutableMemory,
  return_address: u64,
  patcher: UnsafeCell<arch::Patcher>,
  enabled: AtomicBool,
}

pub struct DetourBuilder {
  target: *const (),
  detour: *const (),
  branch_type: arch::BranchType,
}

impl DetourBuilder {
  pub fn new(target: *const (), detour: *const ()) -> Self {
    Self {
      target,
      detour,
      branch_type: arch::BranchType::Jmp,
    }
  }

  pub fn branch(mut self, branch_type: BranchType) -> Self {
    self.branch_type = branch_type;
    self
  }

  pub unsafe fn build(self) -> Result<Detour> {
    if self.target == self.detour {
      Err(Error::SameAddress)?;
    }

    // Lock this so OS operations are not performed in parallell
    let mut pool = memory::POOL.lock().unwrap();

    if !util::is_executable_address(self.target)? || !util::is_executable_address(self.detour)? {
      Err(Error::NotExecutable)?;
    }

    // Create a trampoline generator for the target function
    let margin = arch::meta::prolog_margin(self.target);
    let trampoline = arch::Trampoline::new(self.target, margin)?;

    // A relay is used in case a normal branch cannot reach the destination
    let relay = if let Some(emitter) = arch::meta::relay_builder(self.target, self.detour)? {
      Some(memory::allocate_pic(&mut pool, &emitter, self.target)?)
    } else {
      None
    };

    // If a relay is supplied, use it instead of the detour address
    let detour = relay
      .as_ref()
      .map(|code| code.as_ptr() as *const ())
      .unwrap_or(self.detour);

    Ok(Detour {
      patcher: UnsafeCell::new(arch::Patcher::new(
        self.target,
        detour,
        trampoline.prolog_size(),
        self.branch_type,
      )?),
      trampoline: memory::allocate_pic(&mut pool, trampoline.emitter(), self.target)?,
      return_address: trampoline.return_address(),
      enabled: AtomicBool::default(),
      relay,
    })
  }
}

impl Detour {
  pub unsafe fn new(target: *const (), detour: *const ()) -> Result<Self> {
    DetourBuilder::new(target, detour).build()
  }

  /// Enables the detour.
  pub unsafe fn enable(&self) -> Result<()> {
    self.toggle(true)
  }

  /// Disables the detour.
  pub unsafe fn disable(&self) -> Result<()> {
    self.toggle(false)
  }

  /// Returns whether the detour is enabled or not.
  pub fn is_enabled(&self) -> bool {
    self.enabled.load(Ordering::Relaxed)
  }

  /// Returns a reference to the generated trampoline.
  pub fn trampoline(&self) -> &() {
    unsafe {
      (self.trampoline.as_ptr() as *const ())
        .as_ref()
        .expect("trampoline should not be null")
    }
  }

  /// Returns the return address of the trampoline.
  pub fn trampoline_return_address(&self) -> u64 {
    self.return_address
  }

  /// Enables or disables the detour.
  unsafe fn toggle(&self, enabled: bool) -> Result<()> {
    let _guard = memory::POOL.lock().unwrap();

    if self.enabled.load(Ordering::Acquire) == enabled {
      return Ok(());
    }

    // Runtime code is by default only read-execute
    let _handle = {
      let area = (*self.patcher.get()).area();
      region::protect_with_handle(
        area.as_ptr(),
        area.len(),
        region::Protection::READ_WRITE_EXECUTE,
      )
    }?;

    // Copy either the detour or the original bytes of the function
    (*self.patcher.get()).toggle(enabled);
    self.enabled.store(enabled, Ordering::Release);
    Ok(())
  }
}

impl Drop for Detour {
  /// Disables the detour, if enabled.
  fn drop(&mut self) {
    debug_assert!(unsafe { self.disable().is_ok() });
  }
}

impl fmt::Debug for Detour {
  /// Output whether the detour is enabled or not.
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(
      f,
      "Detour {{ enabled: {}, trampoline: {:?} }}",
      self.is_enabled(),
      self.trampoline()
    )
  }
}

unsafe impl Send for Detour {}
unsafe impl Sync for Detour {}
