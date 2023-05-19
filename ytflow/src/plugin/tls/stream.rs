use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use async_trait::async_trait;
use futures::future::poll_fn;
use openssl::ssl;
use tokio::io::AsyncWriteExt;

use super::initial_data_extract_stream::InitialDataExtractStream;
use crate::flow::*;

pub struct SslStreamFactory {
    ctx: ssl::SslConnector,
    sni: Option<String>,
    next: Weak<dyn StreamOutboundFactory>,
}

impl SslStreamFactory {
    pub fn new(
        next: Weak<dyn StreamOutboundFactory>,
        alpn: Vec<&str>,
        skip_cert_check: bool,
        sni: Option<String>,
    ) -> Self {
        let alpn = {
            let mut alpn_buf = Vec::with_capacity(alpn.iter().map(|a| a.len() + 1).sum());
            for alpn in alpn {
                let len = alpn.len().min(255);
                alpn_buf.push(len as u8);
                alpn_buf.extend_from_slice(&alpn.as_bytes()[..len]);
            }
            alpn_buf
        };
        let mut builder = ssl::SslConnector::builder(ssl::SslMethod::tls())
            .expect("Failed to create SSL Context builder");
        if !alpn.is_empty() {
            builder.set_alpn_protos(&alpn).expect("Failed to set ALPN");
        }
        if skip_cert_check {
            builder.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |_, _| true);
        }
        Self {
            ctx: builder.build(),
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
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let Self { ctx, sni, next } = self;
        let outbound_factory = next.upgrade().ok_or(FlowError::NoOutbound)?;

        let ssl_config = ctx.configure().expect("Cannot create SSL config");
        let ssl = if let Some(sni) = sni.as_ref() {
            ssl_config.into_ssl(sni)
        } else {
            let host = context.remote_peer.host.to_string();
            ssl_config.into_ssl(&host)
        }
        .expect("Cannot create SSL");

        // Extract initial data from handshake to sent to lower
        let initial_data_container = Arc::new(Mutex::new(Some(Buffer::new())));
        let mut ssl_stream = tokio_openssl::SslStream::new(
            ssl,
            CompatStream {
                reader: StreamReader::new(4096, Buffer::new()),
                inner: Box::new(InitialDataExtractStream {
                    data: initial_data_container.clone(),
                }),
            },
        )
        .expect("SslStream: Cannot set BIO");
        // Poll once.
        poll_fn(|cx| {
            let p = Pin::new(&mut ssl_stream).poll_connect(cx);
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
            let initial_data = initial_data_container
                .lock()
                .unwrap()
                .take()
                .unwrap_or_default();
            let (lower, initial_res) = outbound_factory
                .create_outbound(context, &initial_data)
                .await?;
            *ssl_stream.get_mut() = CompatStream {
                reader: StreamReader::new(4096, initial_res),
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

        Ok((Box::new(CompatFlow::new(ssl_stream, 4096)), Buffer::new()))
    }
}
