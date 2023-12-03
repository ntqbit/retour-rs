#[cfg(std)]
mod imp {
  pub type Mutex<T> = ::std::sync::Mutex<T>;
  pub type Arc<T> = ::std::sync::Arc<T>;
}

#[cfg(not(std))]
mod imp {
  // Unsafe mutex and arc,
  // for single-threaded application that do not require std.

  use core::cell::UnsafeCell;

  #[cfg(not(std))]
  pub struct Mutex<T: ?Sized>(core::cell::UnsafeCell<T>);

  impl<T> Mutex<T> {
    pub fn new(val: T) -> Self {
      Self(UnsafeCell::new(val))
    }
  }

  unsafe impl<T: Send> Sync for Mutex<T> {}
  unsafe impl<T: Send> Send for Mutex<T> {}

  #[derive(Debug)]
  pub struct PoisonError<T: core::fmt::Debug> {
    _guard: T,
  }

  pub type LockResult<Guard> = Result<Guard, PoisonError<Guard>>;

  pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a Mutex<T>,
  }

  impl<T> Mutex<T> {
    pub fn lock<'a>(&'a self) -> LockResult<MutexGuard<'a, T>> {
      Ok(MutexGuard { lock: self })
    }
  }

  impl<'a, T> core::fmt::Debug for MutexGuard<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      f.debug_tuple("MutexGuard").finish()
    }
  }

  impl<T> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      f.debug_tuple("Mutex").finish()
    }
  }

  impl<T: ?Sized> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
      unsafe { &*self.lock.0.get() }
    }
  }

  impl<T: ?Sized> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
      unsafe { &mut *self.lock.0.get() }
    }
  }

  pub struct Arc<T>(::alloc::rc::Rc<T>);

  impl<T> Arc<T> {
    pub fn new(val: T) -> Self {
      Self(::alloc::rc::Rc::new(val))
    }
  }

  impl<T> Clone for Arc<T> {
    fn clone(&self) -> Self {
      Self(self.0.clone())
    }
  }

  impl<T> core::ops::Deref for Arc<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
      self.0.deref()
    }
  }

  unsafe impl<T> Send for Arc<T> {}
  unsafe impl<T> Sync for Arc<T> {}
}

pub use imp::*;
