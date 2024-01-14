use std::os::raw::{c_int, c_void};
use std::sync::OnceLock;

use foreign_types_shared::ForeignType;
use openssl::ssl::SslConnectorBuilder;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::X509;
use windows::core::ComInterface;
use windows::Security::Cryptography::Certificates;
use windows::Storage::Streams::IBuffer;
use windows::Win32::System::WinRT::IBufferByteAccess;

static CERT_STORE: OnceLock<X509Store> = OnceLock::new();

pub(crate) fn query_slice_from_ibuffer_mut(buf: &mut IBuffer) -> &mut [u8] {
    let len = buf.Length().unwrap() as _;
    let byte_access: IBufferByteAccess = buf.cast().unwrap();
    #[allow(unused_unsafe)]
    unsafe {
        let ptr = byte_access.Buffer().unwrap();
        std::slice::from_raw_parts_mut(ptr, len)
    }
}

fn load_store() -> X509Store {
    let cert_query = Certificates::CertificateQuery::new().unwrap();
    cert_query.SetStoreName(&"ROOT".into()).unwrap();
    let all_certs = Certificates::CertificateStores::FindAllWithQueryAsync(&cert_query)
        .unwrap()
        .get()
        .unwrap();
    let mut builder = X509StoreBuilder::new().unwrap();
    for cert in all_certs {
        let mut buf = cert.GetCertificateBlob().unwrap();
        let buf = query_slice_from_ibuffer_mut(&mut buf);
        let cert = X509::from_der(buf).unwrap();
        builder.add_cert(cert).unwrap();
    }
    builder.build()
}

extern "C" {
    fn X509_STORE_up_ref(v: *mut c_void) -> c_int;
}

pub(super) fn load(builder: &mut SslConnectorBuilder) {
    let store_ref = CERT_STORE.get_or_init(load_store);
    let store_ptr = store_ref.as_ptr();
    let store = unsafe {
        if unsafe { X509_STORE_up_ref(store_ptr as _) } != 1 {
            panic!("Failed to clone x509 store ref");
        }
        X509Store::from_ptr(store_ptr)
    };
    builder.set_cert_store(store);
}
