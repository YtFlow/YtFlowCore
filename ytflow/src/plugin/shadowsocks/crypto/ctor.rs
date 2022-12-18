use cipher::crypto_common::OutputSizeUser;

use super::*;

pub trait StreamCryptoCtor {
    type Output;
    fn create_crypto(key: &[u8], iv: &[u8]) -> Self::Output;
}

pub struct KeyOnlyCtor<T>(PhantomData<T>);

impl<T> StreamCryptoCtor for KeyOnlyCtor<T>
where
    T: KeyInit,
{
    type Output = T;
    fn create_crypto(key: &[u8], _iv: &[u8]) -> Self::Output {
        T::new_from_slice(key).unwrap()
    }
}

pub struct KeyIvCtor<T>(PhantomData<T>);

impl<T> StreamCryptoCtor for KeyIvCtor<T>
where
    T: KeyIvInit,
{
    type Output = T;
    fn create_crypto(key: &[u8], iv: &[u8]) -> Self::Output {
        T::new_from_slices(key, iv).unwrap()
    }
}

pub struct Rc4Md5Ctor<T>(PhantomData<T>);

impl<T> StreamCryptoCtor for Rc4Md5Ctor<T>
where
    T: KeyInit + KeySizeUser<KeySize = <md5::Md5Core as OutputSizeUser>::OutputSize>,
{
    type Output = T;
    fn create_crypto(key: &[u8], iv: &[u8]) -> Self::Output {
        use md5::digest::Digest;
        let mut hash = md5::Md5::new();
        hash.update(key);
        hash.update(iv);
        let key = hash.finalize();
        T::new(&key)
    }
}
