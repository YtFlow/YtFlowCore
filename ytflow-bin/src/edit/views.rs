use anyhow::Result;
use tui::style::Color;

mod input;
mod main;
mod new_profile;
mod new_proxy_group;
mod plugin_type;
mod profile;
mod proxy_group;
mod proxy_type;
mod utils;

pub use input::run_input_view;
pub use main::run_main_view;
pub use new_profile::run_new_profile_view;
pub use new_proxy_group::run_new_proxy_group_view;
pub use plugin_type::run_plugin_type_view;
pub use profile::run_profile_view;
pub use proxy_group::run_proxy_group_view;
pub use proxy_type::run_proxy_type_view;
use ytflow::data::{Plugin, ProfileId, ProxyGroupId};

const BG: Color = Color::Black;
const FG: Color = Color::White;
const DIM_FG: Color = Color::Indexed(245);

const fn bg_rev(focus: bool) -> Color {
    if focus {
        FG
    } else {
        DIM_FG
    }
}

pub struct InputRequest {
    item: String,
    desc: String,
    initial_value: String,
    max_len: usize,
    action: Box<dyn FnMut(&mut super::AppContext, String) -> Result<()>>,
}

pub enum NavChoice {
    MainView,
    NewProfileView,
    ProfileView(ProfileId),
    PluginTypeView(ProfileId, Option<Plugin>),
    NewProxyGroupView,
    ProxyGroupView(ProxyGroupId),
    ProxyTypeView(ProxyGroupId),
    InputView(InputRequest),
    Back,
}
