fn main() {
    windows::build!(
        Windows::Foundation::Collections::{IIterable, IVector, IVectorView},
        Windows::Foundation::IAsyncAction,
        Windows::Networking::HostName,
        Windows::Networking::Sockets::{DatagramSocket, DatagramSocketInformation},
        Windows::Networking::Vpn::{
            IVpnPlugIn, VpnChannel, VpnDomainNameAssignment, VpnDomainNameInfo,
            VpnPacketBuffer, VpnPacketBufferList, VpnRoute, VpnRouteAssignment
        },
        Windows::Storage::Streams::Buffer,
        Windows::Win32::Foundation::E_BOUNDS,
        Windows::Win32::System::WinRT::IBufferByteAccess,
    );
}
