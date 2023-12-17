use cfg_if::cfg_if;

mod generic;
mod raw;
mod injection;

pub use self::generic::*;
pub use self::raw::*;
pub use self::injection::*;

cfg_if! {
    if #[cfg(feature = "static-detour")] {
        #[cfg_attr(docsrs, doc(cfg(feature = "static-detour")))]
        mod statik;
        pub use self::statik::*;
    }
}
