use std::convert::TryInto;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::ready;

use super::crypto::*;
use crate::flow::*;

pub enum RxCryptoState<C: ShadowCrypto>
where
    [(); C::KEY_LEN]: ,
{
    ReadingIv { key: [u8; C::KEY_LEN] },
    Ready(C),
}

pub struct ShadowsocksStream<C: ShadowCrypto>
where
    [(); C::KEY_LEN]: ,
{
    pub internal_rx_buf: Option<Vec<u8>>,
    pub rx_buf: Option<(Vec<u8>, usize)>,
    pub rx_chunk_size: NonZeroUsize,
    pub tx_offset: usize,
    pub rx_crypto: RxCryptoState<C>,
    pub tx_crypto: C,
    pub lower: Pin<Box<dyn Stream>>,
}

impl<C: ShadowCrypto + Unpin> Stream for ShadowsocksStream<C>
where
    [(); C::KEY_LEN]: ,
    [(); C::IV_LEN]: ,
    [(); C::PRE_CHUNK_OVERHEAD]: ,
    [(); C::POST_CHUNK_OVERHEAD]: ,
{
    fn poll_request_size(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<FlowResult<SizeHint>> {
        let Self {
            internal_rx_buf,
            lower,
            rx_crypto: crypto,
            rx_chunk_size,
            ..
        } = &mut *self;
        // Retrieve IV
        let crypto = loop {
            let key = match crypto {
                RxCryptoState::Ready(c) => break c,
                RxCryptoState::ReadingIv { key } => *key,
            };
            let chunk = match internal_rx_buf.as_mut() {
                Some(c) => c,
                None => {
                    let buf = ready!(lower.as_mut().poll_rx_buffer(cx)).map_err(|(buf, err)| {
                        *internal_rx_buf = Some(buf);
                        err
                    })?;
                    internal_rx_buf.insert(buf)
                }
            };
            let iv = match chunk.get_mut(..C::IV_LEN) {
                Some(o) => o,
                None => {
                    // Need more data for size
                    let size_hint = ready!(lower.as_mut().poll_request_size(cx))?;
                    let size_hint = size_hint.with_min_content(4096);
                    let offset = chunk.len();
                    let desired_size = size_hint + offset;
                    chunk.resize(desired_size, 0);
                    lower
                        .as_mut()
                        .commit_rx_buffer(internal_rx_buf.take().unwrap(), offset)
                        .map_err(|(b, err)| {
                            *internal_rx_buf = Some(b);
                            err
                        })?;
                    continue;
                }
            };
            *crypto = RxCryptoState::Ready(C::create_crypto(&key, (&*iv).try_into().unwrap()));
            chunk.drain(..C::IV_LEN);
        };
        if C::PRE_CHUNK_OVERHEAD == 0 {
            return Poll::Ready(Ok(SizeHint::Unknown { overhead: 0 }));
        }
        // Retrieve size of next chunk (AEAD only)
        loop {
            let chunk = match internal_rx_buf.as_mut() {
                Some(c) => c,
                None => {
                    *internal_rx_buf = Some(ready!(lower.as_mut().poll_rx_buffer(cx)).map_err(
                        |(buf, err)| {
                            *internal_rx_buf = Some(buf);
                            err
                        },
                    )?);
                    continue;
                }
            };
            let overhead = match chunk.get_mut(..C::PRE_CHUNK_OVERHEAD) {
                Some(o) => o,
                None => {
                    // Need more data for size
                    let size_hint = ready!(lower.as_mut().poll_request_size(cx))?;
                    let size_hint = size_hint.with_min_content(4096);
                    let offset = chunk.len();
                    let desired_size = size_hint + offset;
                    chunk.resize(desired_size, 0);
                    lower
                        .as_mut()
                        .commit_rx_buffer(internal_rx_buf.take().unwrap(), offset)
                        .map_err(|(b, err)| {
                            *internal_rx_buf = Some(b);
                            err
                        })?;
                    continue;
                }
            };
            let ret = Poll::Ready(
                crypto
                    .decrypt_size(overhead.try_into().unwrap())
                    .map(|s| {
                        *rx_chunk_size = s;
                        SizeHint::AtLeast(s.get())
                    })
                    .ok_or(FlowError::UnexpectedData),
            );
            chunk.drain(..C::PRE_CHUNK_OVERHEAD);
            break ret;
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
            internal_rx_buf: internal_rx_buf_opt,
            lower,
            rx_buf,
            rx_chunk_size,
            rx_crypto: crypto,
            ..
        } = &mut *self;
        let crypto = match crypto {
            RxCryptoState::ReadingIv { .. } => panic!("Polling rx buffer when IV not ready"),
            RxCryptoState::Ready(c) => c,
        };
        loop {
            let internal_rx_buf = match internal_rx_buf_opt {
                Some(b) => b,
                None => {
                    let buf = ready!(lower.as_mut().poll_rx_buffer(cx))
                        .map_err(|(buf, e)| (rx_buf.take().unwrap().0, e))?;
                    internal_rx_buf_opt.insert(buf)
                }
            };
            let chunk_size = if C::POST_CHUNK_OVERHEAD == 0 {
                // For stream cipher, decode as much as possible
                internal_rx_buf.len()
            } else {
                // For AEAD cipher, decode an exact chunk
                rx_chunk_size.get()
            };
            let total_chunk_size = chunk_size + C::POST_CHUNK_OVERHEAD;
            if let Some(chunk) = internal_rx_buf
                .get_mut(..total_chunk_size)
                .filter(|s| !s.is_empty())
            {
                let (chunk, post_overhead) = chunk.split_at_mut(chunk_size);
                let (mut rx_buf, rx_buf_offset) = rx_buf.take().unwrap();
                if !crypto.decrypt(chunk, (&post_overhead[..]).try_into().unwrap()) {
                    break Poll::Ready(Err((rx_buf, FlowError::UnexpectedData)));
                }
                rx_buf.truncate(rx_buf_offset + chunk_size);
                rx_buf[rx_buf_offset..].copy_from_slice(chunk);
                internal_rx_buf.drain(..total_chunk_size);
                break Poll::Ready(Ok(rx_buf));
            }
            let size_hint = ready!(lower.as_mut().poll_request_size(cx))
                .map_err(|e| (rx_buf.take().unwrap().0, e))?;
            let size_hint = size_hint.with_min_content(if C::POST_CHUNK_OVERHEAD == 0 {
                // Stream cipher
                4096
            } else {
                // AEAD cipher
                chunk_size + C::POST_CHUNK_OVERHEAD
            });
            let offset = internal_rx_buf.len();
            let desired_size = size_hint + offset;
            internal_rx_buf.resize(desired_size, 0);
            lower
                .as_mut()
                .commit_rx_buffer(internal_rx_buf_opt.take().unwrap(), offset)
                .map_err(|(b, e)| {
                    *internal_rx_buf_opt = Some(b);
                    (rx_buf.take().unwrap().0, e)
                })?;
        }
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
