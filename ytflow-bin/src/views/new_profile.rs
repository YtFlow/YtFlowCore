use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::{Block, Borders, List, ListItem, ListState},
};

use super::{bg_rev, NavChoice, BG};
use crate::gen::profiles as gen_profiles;

pub fn run_new_profile_view(ctx: &mut crate::AppContext) -> Result<NavChoice> {
    let mut template_state = ListState::default();
    template_state.select(Some(0));
    loop {
        let size = ctx.term.size()?;
        let main_chunk = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0)].as_ref())
            .split(size)[0];
        let template_list = List::new([
            ListItem::new("SOCKS5 (9080) inbound + Shadowsocks outbound"),
            // ListItem::new("SOCKS5 (9080) inbound + Trojan (via TLS) outbound"),
            // ListItem::new("SOCKS5 (9080) inbound + HTTP (CONNECT) outbound"),
        ])
        .block(
            Block::default()
                .title("Choose a Template")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().bg(bg_rev(true)).fg(BG));
        ctx.term.draw(|f| {
            f.render_stateful_widget(template_list, main_chunk, &mut template_state);
        })?;
        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(NavChoice::Back),
                KeyCode::Down => {
                    template_state.select(template_state.selected().map(|i| (i + 1) % 1));
                }
                KeyCode::Up => {
                    template_state.select(template_state.selected().map(|i| {
                        if i == 0 {
                            0
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Enter => {
                    let profile_id = gen_profiles::create_profile(&ctx.conn)
                        .context("Could not create profile")?;
                    let selected = template_state.selected().unwrap_or_default();
                    match selected {
                        0 => {
                            let plugins = gen_profiles::generate_shadowsocks_plugins();
                            gen_profiles::save_plugins(plugins, profile_id, &ctx.conn)
                                .context("Failed to save plugins")?;
                        }
                        _ => {}
                    }
                    return Ok(NavChoice::Back);
                }
                _ => {}
            }
        };
    }
}
