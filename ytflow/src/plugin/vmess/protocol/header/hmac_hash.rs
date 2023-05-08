use std::cell::RefCell;
use std::marker::PhantomData;
use std::thread::LocalKey;

use cipher::Unsigned;
use hmac::digest::crypto_common::{BlockSizeUser, Output, OutputSizeUser};
use hmac::digest::{Digest, FixedOutput, HashMarker, Update};
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;

use super::aead::{AUTH_ID_LEN, NONCE_LEN};
use super::{CMD_KEY_LEN, HEADER_IV_LEN, HEADER_KEY_LEN};

const OUTPUT_SIZE: usize = <Sha256 as OutputSizeUser>::OutputSize::USIZE;

pub trait StaticKey {
    fn with_key<T>(cb: impl FnOnce(&[u8]) -> T) -> T;
}

struct HmacFixedKeyHash<K, D: Digest + BlockSizeUser> {
    hmac: SimpleHmac<D>,
    key_phantom: PhantomData<K>,
}

impl<K, D: Digest + BlockSizeUser> OutputSizeUser for HmacFixedKeyHash<K, D> {
    type OutputSize = <SimpleHmac<D> as OutputSizeUser>::OutputSize;
}

impl<K, D: Digest + BlockSizeUser> BlockSizeUser for HmacFixedKeyHash<K, D> {
    type BlockSize = D::BlockSize;
}

impl<K: StaticKey, D: Digest + BlockSizeUser> Default for HmacFixedKeyHash<K, D> {
    fn default() -> Self {
        K::with_key(|key| Self {
            hmac: SimpleHmac::new_from_slice(key).unwrap(),
            key_phantom: PhantomData,
        })
    }
}

impl<K: StaticKey, D: Digest + BlockSizeUser> FixedOutput for HmacFixedKeyHash<K, D> {
    fn finalize_into(self, out: &mut Output<Self>) {
        self.hmac.finalize_into(out);
    }
}

impl<K: StaticKey, D: Digest + BlockSizeUser> HashMarker for HmacFixedKeyHash<K, D> {}

impl<K: StaticKey, D: Digest + BlockSizeUser> Update for HmacFixedKeyHash<K, D> {
    fn update(&mut self, data: &[u8]) {
        Mac::update(&mut self.hmac, data.as_ref());
    }
}

trait AssertDigest: Digest {}
impl<K: StaticKey, D: Digest + BlockSizeUser> AssertDigest for HmacFixedKeyHash<K, D> {}

macro_rules! define_static_key_literal(
    ($name:ident, $key:expr) => {
        struct $name;

        impl StaticKey for $name {
            fn with_key<T>(cb: impl FnOnce(&[u8]) -> T) -> T {
                cb($key)
            }
        }
    };
);

struct GlobalPathSegmentGuard;

impl GlobalPathSegmentGuard {
    fn get_tls() -> &'static LocalKey<RefCell<Option<[&'static [u8]; 4]>>> {
        thread_local! {
            static PATH_SEGMENTS: RefCell<Option<[&'static [u8]; 4]>> = RefCell::new(None);
        }
        &PATH_SEGMENTS
    }

    unsafe fn put(&self, segments: [&[u8]; 4]) {
        Self::get_tls().with(|c| unsafe {
            *c.borrow_mut() = Some(std::mem::transmute::<_, [&'static [u8]; 4]>(segments));
        });
    }

    unsafe fn with_segments<T>(segments: [&[u8]; 4], cb: impl FnOnce() -> T) -> T {
        let guard = Self;
        unsafe {
            guard.put(segments);
        }
        cb()
    }

    fn hash_with_segments<H: Update + FixedOutput + Default>(
        segments: [&[u8]; 4],
        cmd_key: &[u8; CMD_KEY_LEN],
    ) -> [u8; OUTPUT_SIZE] {
        unsafe {
            Self::with_segments(segments, || {
                let mut output = [0u8; OUTPUT_SIZE];
                let mut hasher = H::default();
                Update::update(&mut hasher, &cmd_key[..]);
                let finalized = FixedOutput::finalize_fixed(hasher);
                output.copy_from_slice(&finalized);
                output
            })
        }
    }
}

impl Drop for GlobalPathSegmentGuard {
    fn drop(&mut self) {
        Self::get_tls().with(|segments| {
            *segments.borrow_mut() = None;
        });
    }
}

macro_rules! define_static_key_global_slot(
    ($name:ident, $slot:expr) => {
        struct $name;

        impl StaticKey for $name {
            fn with_key<T>(cb: impl FnOnce(&[u8]) -> T) -> T {
                GlobalPathSegmentGuard::get_tls().with(|segments| {
                    let segments = segments.borrow();
                    cb(segments.as_ref().unwrap()[$slot])
                })
            }
        }
    }
);

define_static_key_literal!(VMessAuthIDEncKey, b"AES Auth ID Encryption");
define_static_key_literal!(VMessAEADKDFPathKey, b"VMess AEAD KDF");
define_static_key_literal!(
    VMessHeaderPayloadLengthAEADKey,
    b"VMess Header AEAD Key_Length"
);
define_static_key_literal!(
    VMessHeaderPayloadLengthAEADIv,
    b"VMess Header AEAD Nonce_Length"
);
define_static_key_literal!(VMessHeaderPayloadAEADKey, b"VMess Header AEAD Key");
define_static_key_literal!(VMessHeaderPayloadAEADIv, b"VMess Header AEAD Nonce");
define_static_key_literal!(VMessResLengthAEADKey, b"AEAD Resp Header Len Key");
define_static_key_literal!(VMessResLengthAEADIv, b"AEAD Resp Header Len IV");
define_static_key_literal!(VMessResAEADKey, b"AEAD Resp Header Key");
define_static_key_literal!(VMessResAEADIv, b"AEAD Resp Header IV");
define_static_key_literal!(VMessAEADKDFAuthLenKey, b"auth_len");
define_static_key_global_slot!(GlobalSlot0, 0);
define_static_key_global_slot!(GlobalSlot1, 1);
define_static_key_global_slot!(GlobalSlot2, 2);
define_static_key_global_slot!(GlobalSlot3, 3);

type HmacHashVMessBase = HmacFixedKeyHash<VMessAEADKDFPathKey, Sha256>;

pub fn derive_auth_id_key(cmd_key: &[u8; CMD_KEY_LEN]) -> [u8; OUTPUT_SIZE] {
    type AuthIdBase = HmacFixedKeyHash<VMessAuthIDEncKey, HmacHashVMessBase>;
    GlobalPathSegmentGuard::hash_with_segments::<AuthIdBase>([&[][..]; 4], cmd_key)
}

pub fn derive_aead_header_size_key(
    cmd_key: &[u8; CMD_KEY_LEN],
    auth_id: &[u8; AUTH_ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; OUTPUT_SIZE] {
    type SizeKeyBase = HmacFixedKeyHash<VMessHeaderPayloadLengthAEADKey, HmacHashVMessBase>;
    type AuthIdBase = HmacFixedKeyHash<GlobalSlot0, SizeKeyBase>;
    type NonceBase = HmacFixedKeyHash<GlobalSlot1, AuthIdBase>;
    GlobalPathSegmentGuard::hash_with_segments::<NonceBase>(
        [&auth_id[..], &nonce[..], &[][..], &[][..]],
        cmd_key,
    )
}

pub fn derive_aead_header_size_iv(
    cmd_key: &[u8; CMD_KEY_LEN],
    auth_id: &[u8; AUTH_ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; OUTPUT_SIZE] {
    type SizeIvBase = HmacFixedKeyHash<VMessHeaderPayloadLengthAEADIv, HmacHashVMessBase>;
    type AuthIdBase = HmacFixedKeyHash<GlobalSlot0, SizeIvBase>;
    type NonceBase = HmacFixedKeyHash<GlobalSlot1, AuthIdBase>;
    GlobalPathSegmentGuard::hash_with_segments::<NonceBase>(
        [&auth_id[..], &nonce[..], &[][..], &[][..]],
        cmd_key,
    )
}

pub fn derive_aead_header_key(
    cmd_key: &[u8; CMD_KEY_LEN],
    auth_id: &[u8; AUTH_ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; OUTPUT_SIZE] {
    type SizeKeyBase = HmacFixedKeyHash<VMessHeaderPayloadAEADKey, HmacHashVMessBase>;
    type AuthIdBase = HmacFixedKeyHash<GlobalSlot0, SizeKeyBase>;
    type NonceBase = HmacFixedKeyHash<GlobalSlot1, AuthIdBase>;
    GlobalPathSegmentGuard::hash_with_segments::<NonceBase>(
        [&auth_id[..], &nonce[..], &[][..], &[][..]],
        cmd_key,
    )
}

pub fn derive_aead_header_iv(
    cmd_key: &[u8; CMD_KEY_LEN],
    auth_id: &[u8; AUTH_ID_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; OUTPUT_SIZE] {
    type SizeIvBase = HmacFixedKeyHash<VMessHeaderPayloadAEADIv, HmacHashVMessBase>;
    type AuthIdBase = HmacFixedKeyHash<GlobalSlot0, SizeIvBase>;
    type NonceBase = HmacFixedKeyHash<GlobalSlot1, AuthIdBase>;
    GlobalPathSegmentGuard::hash_with_segments::<NonceBase>(
        [&auth_id[..], &nonce[..], &[][..], &[][..]],
        cmd_key,
    )
}

pub fn derive_aead_res_size_key(res_key: &[u8; HEADER_KEY_LEN]) -> [u8; OUTPUT_SIZE] {
    type SizeKeyBase = HmacFixedKeyHash<VMessResLengthAEADKey, HmacHashVMessBase>;
    GlobalPathSegmentGuard::hash_with_segments::<SizeKeyBase>([&[][..]; 4], res_key)
}

pub fn derive_aead_res_size_iv(res_iv: &[u8; HEADER_IV_LEN]) -> [u8; OUTPUT_SIZE] {
    type SizeIvBase = HmacFixedKeyHash<VMessResLengthAEADIv, HmacHashVMessBase>;
    GlobalPathSegmentGuard::hash_with_segments::<SizeIvBase>([&[][..]; 4], res_iv)
}

pub fn derive_aead_res_key(res_key: &[u8; HEADER_KEY_LEN]) -> [u8; OUTPUT_SIZE] {
    type SizeKeyBase = HmacFixedKeyHash<VMessResAEADKey, HmacHashVMessBase>;
    GlobalPathSegmentGuard::hash_with_segments::<SizeKeyBase>([&[][..]; 4], res_key)
}

pub fn derive_aead_res_iv(res_iv: &[u8; HEADER_IV_LEN]) -> [u8; OUTPUT_SIZE] {
    type SizeIvBase = HmacFixedKeyHash<VMessResAEADIv, HmacHashVMessBase>;
    GlobalPathSegmentGuard::hash_with_segments::<SizeIvBase>([&[][..]; 4], res_iv)
}
