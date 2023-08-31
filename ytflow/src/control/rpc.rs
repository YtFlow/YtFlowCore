use std::collections::BTreeMap;
use std::io;

use cbor4ii::serde::{from_slice, to_writer, EncodeError};
use futures::{
    sink::{Sink, SinkExt},
    stream::{TryStream, TryStreamExt},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::plugin;

#[derive(Deserialize)]
enum ControlHubRequest {
    #[serde(rename = "c")]
    CollectAllPluginInfo {
        #[serde(rename = "h")]
        hashcodes: BTreeMap<u32, u32>,
    },
    #[serde(rename = "p")]
    SendRequestToPlugin {
        id: u32,
        #[serde(rename = "fn")]
        func: String,
        #[serde(rename = "p")]
        params: ByteBuf,
    },
}

#[derive(Serialize)]
#[serde(tag = "c")]
enum ControlHubResponse<T, E> {
    Ok {
        #[serde(rename = "d")]
        data: T,
    },
    Err {
        #[serde(rename = "e")]
        error: E,
    },
}

impl<T, E> From<Result<T, E>> for ControlHubResponse<T, E> {
    fn from(res: Result<T, E>) -> Self {
        match res {
            Ok(data) => ControlHubResponse::Ok { data },
            Err(error) => ControlHubResponse::Err { error },
        }
    }
}

#[derive(Clone)]
pub struct ControlHubService<'h>(pub &'h super::ControlHub);

impl<'h> ControlHubService<'h> {
    pub fn execute_request<W: io::Write>(
        &mut self,
        req: &[u8],
        res: &mut W,
    ) -> Result<(), EncodeError<io::Error>> {
        let req: ControlHubRequest = match from_slice(req) {
            Ok(req) => req,
            Err(e) => {
                return Ok(to_writer(
                    res,
                    &ControlHubResponse::<(), _>::Err {
                        error: e.to_string(),
                    },
                )?);
            }
        };

        Ok(match req {
            ControlHubRequest::CollectAllPluginInfo { hashcodes } => {
                let data = self.collect_all_plugin_info(hashcodes);
                to_writer(res, &ControlHubResponse::<_, ()>::Ok { data })
            }
            ControlHubRequest::SendRequestToPlugin { id, func, params } => {
                let response: ControlHubResponse<_, _> = self
                    .send_request_to_plugin(id, &func, &params)
                    .map(ByteBuf::from)
                    .into();
                to_writer(res, &response)
            }
        }?)
    }

    fn collect_all_plugin_info(&mut self, hashcodes: BTreeMap<u32, u32>) -> Vec<super::PluginInfo> {
        self.0
            .plugins
            .iter()
            .filter_map(|p| p.collect_info(hashcodes.get(&p.id).cloned().unwrap_or_default()))
            .collect()
    }

    fn send_request_to_plugin(
        &mut self,
        id: u32,
        func: &str,
        params: &[u8],
    ) -> super::PluginRequestResult<Vec<u8>> {
        self.0
            .plugins
            .iter()
            .find(|p| p.id == id)
            .ok_or(plugin::PluginRequestError::NoSuchPlugin)
            .and_then(|p| p.responder.on_request(&func, &params))
    }
}

pub async fn serve_stream<S>(service: &mut ControlHubService<'_>, mut io: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let size = io.read_u32().await?;
        if size > 1024 * 1024 * 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request size too large",
            ));
        }
        if size == 0 {
            continue;
        }
        let mut buf = vec![0; size as usize];
        io.read_exact(&mut buf[..]).await?;
        let mut res = Vec::with_capacity(128);
        res.extend_from_slice(&[0; 4]);
        service
            .execute_request(&buf[..], &mut res)
            .expect("Cannot write service response");
        let len_bytes: [u8; 4] = ((res.len() - 4) as u32).to_be_bytes();
        res[..4].copy_from_slice(&len_bytes);
        io.write_all(&res).await?;
    }
}

pub async fn serve_datagram<D, E>(service: &mut ControlHubService<'_>, mut io: D) -> Result<(), E>
where
    D: Sink<Vec<u8>, Error = E> + TryStream<Ok = Vec<u8>, Error = E> + Unpin,
{
    while let Some(req) = io.try_next().await? {
        if req.len() == 0 {
            continue;
        }
        let mut res = Vec::with_capacity(128);
        service
            .execute_request(&req, &mut res)
            .expect("Cannot write service response");
        io.send(res).await?;
    }
    Ok(())
}
