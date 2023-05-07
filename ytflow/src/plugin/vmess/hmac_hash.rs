use std::cell::RefCell;
use std::marker::PhantomData;
use std::thread::LocalKey;

use hmac::digest::crypto_common::{BlockSizeUser, Output, OutputSizeUser};
use hmac::digest::{Digest, FixedOutput, HashMarker, Update};
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;

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

    fn with_segments<T>(segments: [&[u8]; 4], cb: impl FnOnce() -> T) -> T {
        let guard = Self;
        unsafe {
            guard.put(segments);
        }
        cb()
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

define_static_key_literal!(VMessAEADKDFPathKey, b"VMess AEAD KDF");
define_static_key_literal!(
    VMessHeaderPayloadLengthAEADKey,
    b"VMess Header AEAD Key_Length"
);
define_static_key_literal!(VMessAEADKDFAuthLenKey, b"auth_len");
define_static_key_global_slot!(GlobalSlot0, 0);
define_static_key_global_slot!(GlobalSlot1, 1);
define_static_key_global_slot!(GlobalSlot2, 2);
define_static_key_global_slot!(GlobalSlot3, 3);

type HmacHashVMessBase = HmacFixedKeyHash<VMessAEADKDFPathKey, Sha256>;
