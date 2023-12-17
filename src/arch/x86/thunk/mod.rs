#![allow(dead_code)]

/// Implements x86 operations
pub mod x86;

/// Implements x64 operations
#[cfg(target_arch = "x86_64")]
pub mod x64;

#[cfg(target_arch = "x86")]
mod arch {
  pub use super::x86::call_rel32 as call;
  pub use super::x86::jcc_rel32 as jcc;
  pub use super::x86::jmp_rel32 as jmp;
  pub use super::x64::push_32 as push;
}

#[cfg(target_arch = "x86_64")]
mod arch {
  pub use super::x64::call_abs as call;
  pub use super::x64::jcc_abs as jcc;
  pub use super::x64::jmp_abs as jmp;
  pub use super::x64::push_64 as push;
}

// Export the default architecture
pub use self::arch::*;
