use crate::arch::Detour;
use crate::error::Result;
use crate::{Function, HookableWith};
use core::marker::PhantomData;

/// A type-safe detour.
///
/// Due to being generated by a macro, the `GenericDetour::call` method is not
/// exposed in the documentation.  
/// It accepts the same arguments as `T`, and shares its result type:
///
/// ```c
/// /// Calls the original function regardless of whether it's hooked or not.
/// fn call(&self, T::Arguments) -> T::Output
/// ```
///
/// # Example
///
/// ```rust
/// # use retour::Result;
/// use retour::GenericDetour;
///
/// fn add5(val: i32) -> i32 {
///   val + 5
/// }
///
/// fn add10(val: i32) -> i32 {
///   val + 10
/// }
///
/// # fn main() -> Result<()> {
/// let mut hook = unsafe { GenericDetour::<fn(i32) -> i32>::new(add5, add10)? };
///
/// assert_eq!(add5(5), 10);
/// assert_eq!(hook.call(5), 10);
///
/// unsafe { hook.enable()? };
///
/// assert_eq!(add5(5), 15);
/// assert_eq!(hook.call(5), 10);
///
/// unsafe { hook.disable()? };
///
/// assert_eq!(add5(5), 10);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct GenericDetour<T: Function> {
  phantom: PhantomData<T>,
  detour: Detour,
}

impl<T: Function> GenericDetour<T> {
  /// Create a new hook given a target function and a compatible detour
  /// function.
  pub unsafe fn new<D>(target: T, detour: D) -> Result<Self>
  where
    T: HookableWith<D>,
    D: Function,
  {
    Detour::new(target.to_ptr(), detour.to_ptr()).map(|detour| GenericDetour {
      phantom: PhantomData,
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
}

unsafe impl<T: Function> Send for GenericDetour<T> {}
unsafe impl<T: Function> Sync for GenericDetour<T> {}
