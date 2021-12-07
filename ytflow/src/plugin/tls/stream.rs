use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::Poll;

use async_trait::async_trait;
use futures::future::poll_fn;
use openssl::ssl;
use parking_lot::const_mutex;
use tokio::io::AsyncWriteExt;

use super::initial_data_extract_stream::InitialDataExtractStream;
use crate::flow::*;

pub struct SslStreamFactory {
    ctx: ssl::SslConnector,
    sni: Option<String>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl SslStreamFactory {
    pub fn new(next: Weak<dyn StreamOutboundFactory>, sni: Option<String>) -> Self {
        // TODO: sni, alpn, ...
        Self {
            ctx: ssl::SslConnector::builder(ssl::SslMethod::tls())
                .expect("Failed to create SSL Context builder")
                .build(),
            sni,
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for SslStreamFactory {
    async fn create_outbound(
        &self,
        context: Box<FlowContext>,
        initial_data: &'_ [u8],
    ) -> FlowResult<Pin<Box<dyn Stream>>> {
        let Self { ctx, sni, next } = self;
        let outbound_factory = next.upgrade().ok_or(FlowError::NoOutbound)?;

        let ssl_config = ctx.configure().expect("Cannot create SSL config");
        let ssl = if let Some(sni) = sni.as_ref() {
            ssl_config.into_ssl(sni)
        } else {
            let host = context.remote_peer.dest.to_string();
            ssl_config.into_ssl(&host)
        }
        .expect("Cannot create SSL");

        // Extract initial data from handshake to sent to lower
        let initial_data_container = Arc::new(const_mutex(Some(Buffer::with_capacity(4096))));
        let mut ssl_stream = tokio_openssl::SslStream::new(
            ssl,
            CompactStream {
                reader: StreamReader::new(4096),
                inner: Box::pin(InitialDataExtractStream {
                    data: initial_data_container.clone(),
                }),
            },
        )
        .expect("SslStream: Cannot set BIO");
        // Poll once.
        poll_fn(|cx| {
            let p = Pin::new(&mut ssl_stream).poll_do_handshake(cx);
            if p.is_pending() {
                Poll::Ready(Ok(()))
            } else {
                p
            }
        })
        .await
        .map_err(|_| {
            // TODO: log error
            FlowError::UnexpectedData
        })?;
        {
            let initial_data_container = initial_data_container;
            let initial_data = initial_data_container.lock().take().unwrap_or_default();
            let lower = outbound_factory
                .create_outbound(context, &initial_data)
                .await?;
            *ssl_stream.get_mut() = CompactStream {
                reader: StreamReader::new(4096),
                inner: lower,
            };
        }

        Pin::new(&mut ssl_stream)
            .do_handshake()
            .await
            .map_err(|_| {
                // TODO: log error
                FlowError::UnexpectedData
            })?;

        Pin::new(&mut ssl_stream).write(initial_data).await?;

        Ok(Box::pin(CompactFlow {
            inner: ssl_stream,
            rx_buf: None,
            tx_buf: Some((vec![0; 4096], 4096)),
            waker: None,
        }))
    }
}
