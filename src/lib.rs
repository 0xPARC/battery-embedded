#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

pub mod aes_ctr;
pub mod tfhe;

#[cfg(any(feature = "std", feature = "alloc"))]
pub mod zkp;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

// Minimal panic handler for no_std when building as a static library for FFI.
// The test configuration links std, so this is disabled under tests.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Provide a no-op personality function to satisfy linkers when building staticlib
// with panic=abort on some Apple targets.
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// Provide a minimal global allocator so `alloc` types (Vec, Box, etc.) work in no_std.
// This is intentionally simple and can be replaced by integrators if needed.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;
