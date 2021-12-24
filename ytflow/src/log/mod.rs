#[allow(unused)]
#[cfg(windows)]
pub fn debug_log(log: impl AsRef<OsStr>) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::PWSTR;
    use windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;

    let mut bytes: Vec<u16> = log.as_ref().encode_wide().collect();
    bytes.extend_from_slice(&[13, 10, 0u16][..]);
    unsafe { OutputDebugStringW(PWSTR(bytes.as_mut_ptr())) };
}

#[cfg(not(windows))]
pub fn debug_log(log: impl AsRef<str>) {
    eprintln!("{}", log.as_ref());
}
