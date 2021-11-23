#[cfg(windows)]
fn import_windows_metadata() {
    windows::build!(
        Windows::Networking::Connectivity::NetworkInformation,
        Windows::Storage::{ApplicationData, StorageFolder},
        Windows::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6},
        Windows::Win32::NetworkManagement::IpHelper::*,
        Windows::Win32::System::Diagnostics::Debug::*
    );
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(windows)]
    import_windows_metadata();
}
