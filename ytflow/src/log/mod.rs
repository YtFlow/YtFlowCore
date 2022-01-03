#[allow(unused)]
#[cfg(windows)]
pub fn debug_log(log: impl AsRef<std::ffi::OsStr>) {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "Kernel32")]
    extern "system" {
        fn OutputDebugStringW(lp_output_string: *const u16);
    }

    let mut bytes: Vec<u16> = log.as_ref().encode_wide().collect();
    bytes.extend_from_slice(&[13, 10, 0u16][..]);
    unsafe { OutputDebugStringW(bytes.as_ptr()) };
}

#[cfg(not(windows))]
pub fn debug_log(log: impl AsRef<str>) {
    eprintln!("{}", log.as_ref());
}
