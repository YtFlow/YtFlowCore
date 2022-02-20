use super::plugin;

#[derive(Default)]
pub struct ControlHub {
    pub(super) plugins: Vec<plugin::PluginController>,
}

impl ControlHub {
    pub fn create_plugin_control(
        &mut self,
        name: String,
        plugin: &'static str,
        responder: impl plugin::PluginResponder,
    ) -> plugin::PluginControlHandle {
        self.plugins.push(plugin::PluginController {
            id: self.plugins.len() as u32 + 1,
            name,
            plugin,
            responder: Box::new(responder),
        });
        plugin::PluginControlHandle {}
    }
}
