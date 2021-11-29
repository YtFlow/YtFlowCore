use std::ffi::OsStr;

#[allow(unused)]
pub fn debug_log(log: impl AsRef<OsStr>) {
    use crate::bindings::Windows::Win32::Foundation::PWSTR;
    use crate::bindings::Windows::Win32::System::Diagnostics::Debug::OutputDebugStringW;
    use std::os::windows::ffi::OsStrExt;

    let mut bytes: Vec<u16> = log.as_ref().encode_wide().collect();
    bytes.extend_from_slice(&[13, 10, 0u16][..]);
    unsafe { OutputDebugStringW(PWSTR(bytes.as_mut_ptr())) };
}
