use std::convert::TryInto;
use std::num::NonZeroUsize;

use crypto2::mac::Poly1305;
use crypto2::mem::constant_time_eq;

use super::util::increase_num_buf;
use super::xchacha20::XChacha20;

pub trait ShadowCrypto: Send + Sync + Unpin + 'static {
    const KEY_LEN: usize;
    const IV_LEN: usize;
    const PRE_CHUNK_OVERHEAD: usize;
    const POST_CHUNK_OVERHEAD: usize;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self;
    fn encrypt(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        data: &mut [u8],
        post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    );
    fn decrypt_size(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize>;
    #[must_use]
    fn decrypt(&mut self, data: &mut [u8], post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD])
        -> bool;
}

pub struct Plain {}

impl ShadowCrypto for Plain {
    const KEY_LEN: usize = 0;
    const IV_LEN: usize = 0;
    const PRE_CHUNK_OVERHEAD: usize = 0;
    const POST_CHUNK_OVERHEAD: usize = 0;

    fn create_crypto(_key: &[u8; Self::KEY_LEN], _iv: &[u8; Self::IV_LEN]) -> Self {
        Plain {}
    }

    fn encrypt(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        _data: &mut [u8],
        _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
    }

    fn decrypt_size(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        None
    }

    #[must_use]
    fn decrypt(
        &mut self,
        _data: &mut [u8],
        _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        true
    }
}

pub(super) struct XChacha20IetfPoly1305 {
    chacha20: XChacha20,
    nonce: [u8; 24],
}

impl XChacha20IetfPoly1305 {
    pub const BLOCK_LEN: usize = XChacha20::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = XChacha20::NONCE_LEN; // 24 bytes
    pub const TAG_LEN: usize = Poly1305::TAG_LEN; // 16 bytes

    #[cfg(target_pointer_width = "64")]
    pub const A_MAX: usize = u64::MAX as usize; // 2^64 - 1
    #[cfg(target_pointer_width = "32")]
    pub const A_MAX: usize = usize::MAX; // 2^32 - 1

    #[cfg(target_pointer_width = "64")]
    pub(super) const P_MAX: usize = 274877906880; // (2^32 - 1) * BLOCK_LEN
    #[cfg(target_pointer_width = "32")]
    pub(super) const P_MAX: usize = usize::MAX; // 2^32 - 1

    #[allow(dead_code)]
    #[cfg(target_pointer_width = "64")]
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    #[allow(dead_code)]
    #[cfg(target_pointer_width = "32")]
    pub const C_MAX: usize = Self::P_MAX - Self::TAG_LEN; // 4294967279

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
    }

    pub fn _decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;
        let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);

        self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, tag_in)
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let plen = plaintext_in_ciphertext_out.len();
        let tlen = tag_out.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(plen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, nonce, &mut keystream);

            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };

        // NOTE: 初始 BlockCounter = 1;
        self.chacha20
            .encrypt_slice(1, nonce, plaintext_in_ciphertext_out);

        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(plaintext_in_ciphertext_out);

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(plen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8],
    ) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let clen = ciphertext_in_plaintext_out.len();
        let tlen = tag_in.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(clen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, nonce, &mut keystream);

            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };

        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(ciphertext_in_plaintext_out);

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(clen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        // Verify
        let is_match = constant_time_eq(tag_in, &tag[..Self::TAG_LEN]);

        if is_match {
            // NOTE: 初始 BlockCounter = 1;
            self.chacha20
                .decrypt_slice(1, nonce, ciphertext_in_plaintext_out);
        }

        is_match
    }
}

impl ShadowCrypto for XChacha20IetfPoly1305 {
    const KEY_LEN: usize = XChacha20::KEY_LEN;
    const IV_LEN: usize = 32;
    const PRE_CHUNK_OVERHEAD: usize = 2 + 16;
    const POST_CHUNK_OVERHEAD: usize = 16;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
        use crypto2::kdf::HkdfSha1;

        // Gen SubKey
        let mut okm = [0u8; Self::KEY_LEN];
        HkdfSha1::oneshot(&iv[..], &key[..], b"ss-subkey", &mut okm[..]);

        Self {
            chacha20: XChacha20::new(&okm[..]),
            nonce: Default::default(),
        }
    }

    fn encrypt(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        data: &mut [u8],
        post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
        pre_overhead[0..2].copy_from_slice((data.len() as u16).to_be_bytes().as_ref());
        self.encrypt_slice(&self.nonce[..], &[], pre_overhead);
        increase_num_buf(&mut self.nonce);
        self.encrypt_slice_detached(&self.nonce[..], &[], data, post_overhead);
        increase_num_buf(&mut self.nonce);
    }

    fn decrypt_size(
        &mut self,
        pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        let (size_buf, size_tag) = pre_overhead.split_at_mut(2);
        if !self.decrypt_slice_detached(&self.nonce, &[], size_buf, size_tag) {
            return None;
        }
        increase_num_buf(&mut self.nonce);
        let size = u16::from_be_bytes((&size_buf[..]).try_into().unwrap()) & 0x3fff;
        NonZeroUsize::new(size as usize)
    }

    fn decrypt(
        &mut self,
        data: &mut [u8],
        post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        (
            self.decrypt_slice_detached(&self.nonce[..], &[], data, post_overhead),
            increase_num_buf(&mut self.nonce),
        )
            .0
    }
}

// TODO: replace with RustCrypto implementations
// https://github.com/shadowsocks/shadowsocks-crypto/blob/main/src/v1/streamcipher/cfb.rs
macro_rules! impl_cfb128 {
    ($name: tt, $cipher: ident) => {
        pub struct $name {
            last_input_block: [u8; Self::IV_LEN],
            keystream: [u8; Self::IV_LEN],
            offset: usize,
            inner: crypto2::blockcipher::$cipher,
        }
        impl ShadowCrypto for $name {
            const KEY_LEN: usize = crypto2::blockcipher::$cipher::KEY_LEN;
            const IV_LEN: usize = crypto2::blockcipher::$cipher::BLOCK_LEN;
            const PRE_CHUNK_OVERHEAD: usize = 0;
            const POST_CHUNK_OVERHEAD: usize = 0;

            fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
                let inner = crypto2::blockcipher::$cipher::new(key);

                let last_input_block = iv.clone();

                let mut keystream = last_input_block.clone();
                inner.encrypt(&mut keystream);

                Self {
                    inner,
                    last_input_block,
                    keystream,
                    offset: 0,
                }
            }
            fn encrypt(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
                data: &mut [u8],
                _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
            ) {
                for i in 0..data.len() {
                    if self.offset == Self::IV_LEN {
                        self.keystream = self.last_input_block.clone();
                        self.inner.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    data[i] ^= self.keystream[self.offset];
                    self.last_input_block[self.offset] = data[i];

                    self.offset += 1;
                }
            }
            fn decrypt_size(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
            ) -> Option<NonZeroUsize> {
                None
            }
            fn decrypt(
                &mut self,
                data: &mut [u8],
                _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
            ) -> bool {
                for i in 0..data.len() {
                    if self.offset == Self::IV_LEN {
                        self.keystream = self.last_input_block.clone();
                        self.inner.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    self.last_input_block[self.offset] = data[i];
                    data[i] ^= self.keystream[self.offset];

                    self.offset += 1;
                }
                true
            }
        }
    };
}

// https://github.com/shadowsocks/shadowsocks-crypto/blob/main/src/v1/streamcipher/ctr.rs
macro_rules! impl_ctr {
    ($name:tt, $cipher:ident) => {
        pub struct $name {
            inner: crypto2::blockcipher::$cipher,
            counter_block: [u8; Self::IV_LEN],
            keystream: [u8; Self::IV_LEN],
            offset: usize,
        }

        impl $name {
            // NOTE: OpenSSL 的 CTR 模式把整个 Block 当作计数器。也就是 u128。
            #[inline]
            fn ctr128(counter_block: &mut [u8; Self::IV_LEN]) {
                let octets = u128::from_be_bytes(*counter_block)
                    .wrapping_add(1)
                    .to_be_bytes();
                counter_block.copy_from_slice(&octets)
            }
            #[inline]
            fn process(&mut self, plaintext_or_ciphertext: &mut [u8]) {
                for i in 0..plaintext_or_ciphertext.len() {
                    if self.offset == Self::IV_LEN {
                        self.keystream = self.counter_block.clone();
                        self.inner.encrypt(&mut self.keystream);
                        Self::ctr128(&mut self.counter_block);

                        self.offset = 0;
                    }

                    plaintext_or_ciphertext[i] ^= self.keystream[self.offset];
                    self.offset += 1;
                }
            }
        }

        impl ShadowCrypto for $name {
            const KEY_LEN: usize = crypto2::blockcipher::$cipher::KEY_LEN;
            const IV_LEN: usize = crypto2::blockcipher::$cipher::BLOCK_LEN;
            const PRE_CHUNK_OVERHEAD: usize = 0;
            const POST_CHUNK_OVERHEAD: usize = 0;

            fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
                let inner = crypto2::blockcipher::$cipher::new(key);

                let mut counter_block = iv.clone();

                let mut keystream = counter_block.clone();
                inner.encrypt(&mut keystream);
                Self::ctr128(&mut counter_block);

                Self {
                    inner,
                    counter_block,
                    keystream,
                    offset: 0usize,
                }
            }

            fn encrypt(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
                data: &mut [u8],
                _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
            ) {
                self.process(data);
            }
            fn decrypt_size(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
            ) -> Option<NonZeroUsize> {
                None
            }
            fn decrypt(
                &mut self,
                data: &mut [u8],
                _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
            ) -> bool {
                self.process(data);
                true
            }
        }
    };
}

macro_rules! impl_aead_cipher {
    ($name: tt, $cipher: tt, $salt: tt) => {
        pub struct $name {
            inner: crypto2::aeadcipher::$cipher,
            nonce: [u8; 12],
        }

        impl ShadowCrypto for $name {
            const KEY_LEN: usize = crypto2::aeadcipher::$cipher::KEY_LEN;
            const IV_LEN: usize = $salt;
            const PRE_CHUNK_OVERHEAD: usize = 2 + 16;
            const POST_CHUNK_OVERHEAD: usize = 16;

            fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
                use crypto2::kdf::HkdfSha1;

                // Gen SubKey
                let mut okm = [0u8; Self::KEY_LEN];
                HkdfSha1::oneshot(&iv[..], &key[..], b"ss-subkey", &mut okm[..]);

                Self {
                    inner: crypto2::aeadcipher::$cipher::new(&okm[..]),
                    nonce: Default::default(),
                }
            }

            fn encrypt(
                &mut self,
                pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
                data: &mut [u8],
                post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
            ) {
                pre_overhead[0..2].copy_from_slice((data.len() as u16).to_be_bytes().as_ref());
                self.inner.encrypt_slice(&self.nonce[..], &[], pre_overhead);
                increase_num_buf(&mut self.nonce);
                self.inner
                    .encrypt_slice_detached(&self.nonce[..], &[], data, post_overhead);
                increase_num_buf(&mut self.nonce);
            }

            fn decrypt_size(
                &mut self,
                pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
            ) -> Option<NonZeroUsize> {
                let (size_buf, size_tag) = pre_overhead.split_at_mut(2);
                if !self
                    .inner
                    .decrypt_slice_detached(&self.nonce, &[], size_buf, size_tag)
                {
                    return None;
                }
                increase_num_buf(&mut self.nonce);
                let size = u16::from_be_bytes((&size_buf[..]).try_into().unwrap()) & 0x3fff;
                NonZeroUsize::new(size as usize)
            }

            fn decrypt(
                &mut self,
                data: &mut [u8],
                post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
            ) -> bool {
                (
                    self.inner
                        .decrypt_slice_detached(&self.nonce[..], &[], data, post_overhead),
                    increase_num_buf(&mut self.nonce),
                )
                    .0
            }
        }
    };
}

macro_rules! impl_rc4_cipher {
    ($name: tt, $salt: tt, $key_func: expr) => {
        pub struct $name {
            inner: crypto2::streamcipher::Rc4,
        }

        impl ShadowCrypto for $name {
            const KEY_LEN: usize = 16;
            const IV_LEN: usize = $salt;
            const PRE_CHUNK_OVERHEAD: usize = 0;
            const POST_CHUNK_OVERHEAD: usize = 0;

            fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
                Self {
                    inner: crypto2::streamcipher::Rc4::new(&$key_func(key, iv)),
                }
            }

            fn encrypt(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
                data: &mut [u8],
                _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
            ) {
                self.inner.encrypt_slice(data);
            }

            fn decrypt_size(
                &mut self,
                _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
            ) -> Option<NonZeroUsize> {
                None
            }

            fn decrypt(
                &mut self,
                data: &mut [u8],
                _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
            ) -> bool {
                self.inner.decrypt_slice(data);
                true
            }
        }
    };
}

pub struct Chacha20Ietf {
    inner: crypto2::streamcipher::Chacha20,
    nonce: [u8; 12],
    len: u64,
}

impl Chacha20Ietf {
    const BLOCK_LEN: usize = crypto2::streamcipher::Chacha20::BLOCK_LEN;

    #[inline]
    fn in_place(&mut self, m: &mut [u8]) {
        let mlen = m.len();

        // padding
        let pad_len = (self.len % Self::BLOCK_LEN as u64) as usize;

        let mut buf = m.to_vec();
        for _ in 0..pad_len {
            buf.insert(0, 0);
        }

        let block_counter = if cfg!(any(
            target_pointer_width = "32",
            target_pointer_width = "64"
        )) {
            self.len / Self::BLOCK_LEN as u64
        } else {
            unreachable!()
        };
        assert!(block_counter <= u32::MAX as u64);
        let block_counter = block_counter as u32;

        self.inner
            .encrypt_slice(block_counter, &self.nonce, &mut buf);

        m.copy_from_slice(&buf[pad_len..]);

        if cfg!(any(
            target_pointer_width = "32",
            target_pointer_width = "64"
        )) {
            self.len += mlen as u64;
        } else {
            unreachable!()
        }
    }
}

impl ShadowCrypto for Chacha20Ietf {
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 12;
    const PRE_CHUNK_OVERHEAD: usize = 0;
    const POST_CHUNK_OVERHEAD: usize = 0;

    fn create_crypto(key: &[u8; Self::KEY_LEN], iv: &[u8; Self::IV_LEN]) -> Self {
        Self {
            inner: crypto2::streamcipher::Chacha20::new(key),
            nonce: *iv,
            len: 0,
        }
    }
    fn encrypt(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
        data: &mut [u8],
        _post_overhead: &mut [u8; Self::POST_CHUNK_OVERHEAD],
    ) {
        self.in_place(data);
    }
    fn decrypt_size(
        &mut self,
        _pre_overhead: &mut [u8; Self::PRE_CHUNK_OVERHEAD],
    ) -> Option<NonZeroUsize> {
        None
    }
    fn decrypt(
        &mut self,
        data: &mut [u8],
        _post_overhead: &[u8; Self::POST_CHUNK_OVERHEAD],
    ) -> bool {
        self.in_place(data);
        true
    }
}

fn md5_key_salt(key: &[u8; 16], salt: &[u8]) -> [u8; 16] {
    let mut md5 = crypto2::hash::Md5::new();
    md5.update(key);
    md5.update(salt);
    md5.finalize()
}

fn noop_key_salt(key: &[u8; 16], _salt: &[u8]) -> [u8; 16] {
    *key
}

impl_cfb128!(Aes128Cfb, Aes128);
impl_cfb128!(Aes192Cfb, Aes192);
impl_cfb128!(Aes256Cfb, Aes256);
impl_cfb128!(Camellia128Cfb, Camellia128);
impl_cfb128!(Camellia192Cfb, Camellia192);
impl_cfb128!(Camellia256Cfb, Camellia256);

impl_ctr!(Aes128Ctr, Aes128);
impl_ctr!(Aes192Ctr, Aes192);
impl_ctr!(Aes256Ctr, Aes256);

impl_aead_cipher!(Aes128Gcm, Aes128Gcm, 16);
impl_aead_cipher!(Aes256Gcm, Aes256Gcm, 32);
impl_aead_cipher!(Chacha20IetfPoly1305, Chacha20Poly1305, 32);

impl_rc4_cipher!(Rc4, 0, noop_key_salt);
impl_rc4_cipher!(Rc4Md5, 16, md5_key_salt);
