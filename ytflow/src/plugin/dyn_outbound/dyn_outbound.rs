use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use itertools::Itertools;

use crate::data::{self, DataResult, Database, PluginCache};
use crate::flow::*;

pub struct FixedOutbound {
    pub name: String,
    pub tcp_next: Weak<dyn StreamOutboundFactory>,
    pub udp_next: Weak<dyn DatagramSessionFactory>,
}
pub struct DynOutbound {
    pub(super) db: Database,
    pub(super) plugin_cache: PluginCache,
    pub(super) fixed_outbounds: Vec<FixedOutbound>,
    pub(super) proxy_list: ArcSwap<(
        Vec<(data::Proxy, data::ProxyGroupId)>,
        Vec<data::ProxyGroup>,
    )>,
    pub(super) current: ArcSwap<Option<super::select::Selection>>,
    pub(super) tcp_next: Weak<dyn StreamOutboundFactory>,
    pub(super) udp_next: Weak<dyn DatagramSessionFactory>,
}

impl DynOutbound {
    pub fn new(
        db: Database,
        plugin_cache: PluginCache,
        fixed_outbounds: Vec<FixedOutbound>,
        tcp_next: Weak<dyn StreamOutboundFactory>,
        udp_next: Weak<dyn DatagramSessionFactory>,
    ) -> Self {
        Self {
            db,
            plugin_cache,
            fixed_outbounds,
            proxy_list: ArcSwap::new(Default::default()),
            current: ArcSwap::new(Arc::new(None)),
            tcp_next,
            udp_next,
        }
    }

    pub fn load_proxies(&self) -> DataResult<()> {
        let conn = self.db.connect()?;
        let groups = data::ProxyGroup::query_all(&conn)?;
        let all_proxies = groups
            .iter()
            .map(|g| {
                data::Proxy::query_all_by_group(g.id, &conn)
                    .map(|ps| ps.into_iter().map(|p| (p, g.id)).collect_vec())
            })
            .collect::<DataResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect_vec();
        self.proxy_list.store(Arc::new((all_proxies, groups)));
        Ok(())
    }
}

#[async_trait]
impl StreamOutboundFactory for DynOutbound {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &'_ [u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let next = (**self.current.load())
            .as_ref()
            .ok_or(FlowError::NoOutbound)?
            .tcp
            .clone();
        next.create_outbound(context, initial_data).await
    }
}

#[async_trait]
impl DatagramSessionFactory for DynOutbound {
    async fn bind(&self, context: Box<FlowContext>) -> FlowResult<Box<dyn DatagramSession>> {
        let next = (**self.current.load())
            .as_ref()
            .ok_or(FlowError::NoOutbound)?
            .udp
            .clone();
        next.bind(context).await
    }
}
