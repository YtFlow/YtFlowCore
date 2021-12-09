use std::convert::TryInto;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;

use super::crypto::*;
use crate::flow::*;

pub enum RxCryptoState<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    ReadingIv { key: [u8; C::KEY_LEN] },
    Ready(C),
}

pub struct ShadowsocksStream<C: ShadowCrypto>
where
    [(); C::KEY_LEN]:,
{
    pub reader: StreamReader,
    pub rx_buf: Option<(Vec<u8>, usize)>,
    pub rx_chunk_size: NonZeroUsize,
    pub rx_crypto: RxCryptoState<C>,
    pub tx_crypto: C,
    pub tx_offset: usize,
    pub lower: Pin<Box<dyn Stream>>,
}

impl<C: ShadowCrypto + Unpin> Stream for ShadowsocksStream<C>
where
    [(); C::KEY_LEN]:,
    [(); C::IV_LEN]:,
    [(); C::PRE_CHUNK_OVERHEAD]:,
    [(); C::POST_CHUNK_OVERHEAD]:,
{
    fn poll_request_size(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<FlowResult<SizeHint>> {
        let Self {
            lower,
            rx_crypto: crypto,
            rx_chunk_size,
            reader,
            ..
        } = &mut *self;
        loop {
            match crypto {
                RxCryptoState::ReadingIv { key } => {
                    let mut iv = [0; C::IV_LEN];
                    ready!(
                        reader.poll_read_exact(cx, lower.as_mut(), C::IV_LEN, |buf| iv
                            .copy_from_slice(buf))
                    )?;
                    *crypto =
                        RxCryptoState::Ready(C::create_crypto(key, (&iv).try_into().unwrap()));
                }
                RxCryptoState::Ready(_) if C::PRE_CHUNK_OVERHEAD == 0 => {
                    return Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }));
                }
                RxCryptoState::Ready(crypto) => {
                    // Retrieve size of next chunk (AEAD only)
                    let size = ready!(reader.poll_read_exact(
                        cx,
                        lower.as_mut(),
                        C::PRE_CHUNK_OVERHEAD,
                        |buf| crypto.decrypt_size(buf.try_into().unwrap())
                    ))?
                    .ok_or(FlowError::UnexpectedData)?;
                    *rx_chunk_size = size;
                    return Poll::Ready(Ok(SizeHint::AtLeast(size.get() + C::POST_CHUNK_OVERHEAD)));
                }
            }
        }
    }

    fn commit_rx_buffer(
        mut self: Pin<&mut Self>,
        buffer: Buffer,
        offset: usize,
    ) -> Result<(), (Buffer, FlowError)> {
        self.as_mut().rx_buf = Some((buffer, offset));
        Ok(())
    }

    fn poll_rx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Buffer, (Buffer, FlowError)>> {
        let Self {
            lower,
            rx_buf: rx_buf_opt,
            rx_chunk_size,
            rx_crypto: crypto,
            reader,
            ..
        } = &mut *self;
        let crypto = match crypto {
            RxCryptoState::ReadingIv { .. } => panic!("Polling rx buffer when IV not ready"),
            RxCryptoState::Ready(c) => c,
        };
        let (rx_buf, offset) = match rx_buf_opt.as_mut() {
            Some((buf, offset)) => (buf, *offset),
            None => panic!("Polling rx buffer without committing"),
        };
        let res = if C::POST_CHUNK_OVERHEAD == 0 {
            // Stream cipher
            let res = ready!(reader.poll_peek_at_least(cx, lower.as_mut(), 1, |buf| {
                let to_write = buf.len().min(rx_buf.len() - offset);
                let buf = &mut buf[..to_write];
                let _ = crypto.decrypt(buf, &[0; C::POST_CHUNK_OVERHEAD]);
                rx_buf[offset..(offset + to_write)].copy_from_slice(buf);
                to_write
            }));
            if let Ok(written) = &res {
                let _ = reader.advance(*written);
            }
            res
        } else {
            // AEAD cipher
            let chunk_size = rx_chunk_size.get();
            let res = ready!(reader.poll_read_exact(
                cx,
                lower.as_mut(),
                chunk_size + C::POST_CHUNK_OVERHEAD,
                |buf| {
                    let (buf, post_overhead) = buf.split_at_mut(chunk_size);
                    if !crypto.decrypt(buf, (&*post_overhead).try_into().unwrap()) {
                        return false;
                    }
                    rx_buf[offset..(offset + chunk_size)].copy_from_slice(buf);
                    true
                }
            ));
            res.and_then(|dec_success| {
                dec_success
                    .then_some(chunk_size)
                    .ok_or(FlowError::UnexpectedData)
            })
        };
        let mut buf = rx_buf_opt.take().unwrap().0;
        Poll::Ready(match res {
            Ok(len) => {
                buf.truncate(len + offset);
                Ok(buf)
            }
            Err(e) => Err((buf, e)),
        })
    }

    fn poll_tx_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        size: NonZeroUsize,
    ) -> Poll<FlowResult<(Buffer, usize)>> {
        let (buf, offset) = ready!(self.lower.as_mut().poll_tx_buffer(
            cx,
            (size.get() + C::PRE_CHUNK_OVERHEAD + C::POST_CHUNK_OVERHEAD)
                .try_into()
                .unwrap()
        ))?;
        self.tx_offset = offset;
        Poll::Ready(Ok((buf, offset + C::PRE_CHUNK_OVERHEAD)))
    }

    fn commit_tx_buffer(mut self: Pin<&mut Self>, mut buffer: Buffer) -> FlowResult<()> {
        let Self {
            lower,
            tx_crypto: crypto,
            tx_offset,
            ..
        } = &mut *self;
        let mut post_overhead = [0; C::POST_CHUNK_OVERHEAD];
        let part = &mut buffer[*tx_offset..];
        let (pre_overhead, chunk) = part.split_at_mut(C::PRE_CHUNK_OVERHEAD);
        crypto.encrypt(
            pre_overhead.try_into().unwrap(),
            chunk,
            (&mut post_overhead[..]).try_into().unwrap(),
        );
        buffer.extend_from_slice(post_overhead.as_ref());
        lower.as_mut().commit_tx_buffer(buffer)
    }

    fn poll_close_tx(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FlowResult<()>> {
        self.lower.as_mut().poll_close_tx(cx)
    }
}
