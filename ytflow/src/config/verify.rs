use serde::Serialize;

use super::factory::{DemandDescriptor, ParsedPlugin, ProvideDescriptor};
use super::plugin::Plugin;
use super::ConfigResult;

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult<'a> {
    #[serde(borrow)]
    requires: Vec<DemandDescriptor<'a>>,
    provides: Vec<ProvideDescriptor>,
}
pub fn verify_plugin(plugin: &'_ Plugin) -> ConfigResult<VerifyResult<'_>> {
    let ParsedPlugin {
        provides, requires, ..
    } = super::factory::create_factory_from_plugin(plugin)?;
    Ok(VerifyResult { provides, requires })
}
