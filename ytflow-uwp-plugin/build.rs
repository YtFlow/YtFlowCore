#[cfg(windows)]
fn uwp_main() {
    windows::core::build!(
        Windows::Foundation::Collections::*,
        Windows::Networking::HostName,
        Windows::Networking::Vpn::*,
        Windows::Networking::Sockets::{DatagramSocket, DatagramSocketInformation},
        Windows::Storage::Streams::Buffer,
        Windows::Win32::System::WinRT::IBufferByteAccess,
    );
}

fn main() {
    #[cfg(windows)]
    if std::env::var_os("CARGO_CFG_TARGET_VENDOR").map_or(false, |v| v.as_os_str() == "uwp") {
        uwp_main();
    }
}
