//! System C libraries loaded at run time (`dlopen`), so the hub builds without their
//! headers or a sysroot and still runs on a device that lacks them: the feature that needs
//! one just reports it missing.

use std::ffi::{CString, c_void};

pub struct Library {
    handle: *mut c_void,
}

// SAFETY: a dlopen handle may be used from any thread; dlsym and dlclose are thread-safe.
unsafe impl Send for Library {}
// SAFETY: as above; the handle is never mutated.
unsafe impl Sync for Library {}

impl Library {
    /// The first of `names` that loads. Only files that exist are handed to `dlopen`: in the
    /// cross-built (zig-linked) binary, glibc's `dlopen` crashes on its error path, so a
    /// missing library must never reach it.
    pub fn open(names: &[&str]) -> Option<Self> {
        names.iter().filter_map(|name| find(name)).find_map(|path| {
            let name = CString::new(path).ok()?;
            // SAFETY: a valid C string; RTLD_NOW resolves everything up front.
            let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            // A null handle never becomes a Library.
            (!handle.is_null()).then_some(Self { handle })
        })
    }

    /// The address of `name`, as the function pointer type `T`.
    ///
    /// # Safety
    /// `T` must be an `extern "C"` function pointer type matching the symbol's real signature.
    pub unsafe fn get<T: Copy>(&self, name: &str) -> Option<T> {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>(), "T must be a function pointer");
        let name = CString::new(name).ok()?;
        // SAFETY: the handle is open for our lifetime.
        let symbol = unsafe { libc::dlsym(self.handle, name.as_ptr()) };
        if symbol.is_null() {
            return None;
        }
        // SAFETY: same size, and the caller vouches for the type.
        Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&symbol) })
    }
}

/// Where the dynamic linker would look for `name` (a bare file name), or `name` itself if it
/// is a path; None if no such file exists.
fn find(name: &str) -> Option<String> {
    if name.contains('/') {
        return std::path::Path::new(name).exists().then(|| name.to_owned());
    }
    let mut dirs: Vec<String> = std::env::var("LD_LIBRARY_PATH").unwrap_or_default().split(':').filter(|dir| !dir.is_empty()).map(str::to_owned).collect();
    for dir in ["/usr/lib", "/lib", "/usr/local/lib", "/usr/lib64", "/lib64", "/opt/homebrew/lib"] {
        dirs.push(dir.to_owned());
    }
    for triplet in ["aarch64-linux-gnu", "arm-linux-gnueabihf", "x86_64-linux-gnu"] {
        dirs.push(format!("/usr/lib/{triplet}"));
        dirs.push(format!("/lib/{triplet}"));
    }
    dirs.into_iter().map(|dir| format!("{dir}/{name}")).find(|path| std::path::Path::new(path).exists())
}

// No `Drop`: a library stays loaded for the life of the process. The wrappers keep it in a
// `static`, and never calling `dlclose` rules out closing a handle twice or a bad one.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_library_is_none_not_a_crash() {
        assert!(Library::open(&["libkaonic-no-such-library.so.9", "/nonexistent/libx.so"]).is_none());
        assert!(find("libkaonic-no-such-library.so.9").is_none());
    }

    #[test]
    fn a_library_that_is_there_loads_and_resolves() {
        // The C library is always present (by a name dlopen accepts on each system).
        let Some(library) = Library::open(&["libc.so.6", "/usr/lib/libSystem.B.dylib"]) else { return };
        // SAFETY: strlen's real signature.
        let strlen: Option<unsafe extern "C" fn(*const std::ffi::c_char) -> usize> = unsafe { library.get("strlen") };
        // SAFETY: a valid C string.
        assert_eq!(strlen.map(|strlen| unsafe { strlen(c"abc".as_ptr()) }), Some(3));
        // SAFETY: never called.
        assert!(unsafe { library.get::<unsafe extern "C" fn()>("kaonic_no_such_symbol") }.is_none());
    }
}
