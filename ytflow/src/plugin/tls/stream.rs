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
    alpn_set: bool,
    next: Weak<dyn StreamOutboundFactory>,
}

fn encode_alpn(alpn: &[&str]) -> Vec<u8> {
    let mut alpn_buf = Vec::with_capacity(alpn.iter().map(|a| a.len() + 1).sum());
    for alpn in alpn {
        let len = alpn.len().min(255);
        alpn_buf.push(len as u8);
        alpn_buf.extend_from_slice(&alpn.as_bytes()[..len]);
    }
    alpn_buf
}

impl SslStreamFactory {
    pub fn new(
        next: Weak<dyn StreamOutboundFactory>,
        alpn: Vec<&str>,
        skip_cert_check: bool,
        sni: Option<String>,
    ) -> Self {
        let alpn = encode_alpn(&alpn);
        let mut alpn_set = false;
        let mut builder = ssl::SslConnector::builder(ssl::SslMethod::tls())
            .expect("Failed to create SSL Context builder");
        if !alpn.is_empty() {
            builder.set_alpn_protos(&alpn).expect("Failed to set ALPN");
            alpn_set = true;
        }
        if skip_cert_check {
            builder.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |_, _| true);
        }
        #[cfg(windows)]
        if !skip_cert_check {
            super::load_certs_windows::load(&mut builder);
        }
        Self {
            ctx: builder.build(),
            sni,
            alpn_set,
            next,
        }
    }
}

#[async_trait]
impl StreamOutboundFactory for SslStreamFactory {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let Self {
            ctx,
            sni,
            alpn_set,
            next,
        } = self;
        let outbound_factory = next.upgrade().ok_or(FlowError::NoOutbound)?;

        let ssl_config = ctx.configure().expect("Cannot create SSL config");
        let mut ssl = if let Some(sni) = sni.as_ref() {
            ssl_config.into_ssl(sni)
        } else {
            let host = context.remote_peer.host.to_string();
            ssl_config.into_ssl(&host)
        }
        .expect("Cannot create SSL");
        if !alpn_set {
            let alpn = encode_alpn(&context.application_layer_protocol);
            if !alpn.is_empty() {
                ssl.set_alpn_protos(&alpn).expect("Failed to set ALPN");
            }
        }

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

        if let Some(alpn) = ssl_stream.ssl().selected_alpn_protocol() {
            context
                .application_layer_protocol
                .retain(|a| a.as_bytes() == alpn);
        }

        Pin::new(&mut ssl_stream).write_all(initial_data).await?;

        Ok((Box::new(CompatFlow::new(ssl_stream, 4096)), Buffer::new()))
    }
}
