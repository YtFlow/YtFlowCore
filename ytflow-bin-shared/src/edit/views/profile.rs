use anyhow::{anyhow, Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use super::{utils::open_editor_for_cbor, InputRequest, NavChoice, BG, FG};
use crate::edit;
use ytflow::data::{Plugin, Profile, ProfileId};

pub fn run_profile_view(ctx: &mut edit::AppContext, id: ProfileId) -> Result<NavChoice> {
    let profile = Profile::query_by_id(id.0 as _, &ctx.conn)
        .context("Could not query selected profile")?
        .ok_or_else(|| anyhow!("Profile not found"))?;
    let mut plugins = Plugin::query_all_by_profile(profile.id, &ctx.conn)
        .context("Failed to query all plugins")?;
    let mut entry_plugins = Plugin::query_entry_by_profile(profile.id, &ctx.conn)
        .context("Failed to query entry plugins")?;
    let mut delete_confirm = false;
    let mut action_state = ListState::default();
    let mut plugin_state = ListState::default();
    if !plugins.is_empty() {
        action_state.select(Some(0));
    }

    'main_loop: loop {
        let size = ctx.term.size()?;
        let vchunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(2),
                    Constraint::Min(0),
                    Constraint::Length(2),
                ]
                .as_ref(),
            )
            .split(size);
        let status_bar_chunk = vchunks[2];
        let header_chunk = vchunks[0];
        let main_chunk = vchunks[1];

        ctx.term.draw(|f| {
            let header = Paragraph::new(Spans(vec![
                Span {
                    content: "Editing: ".into(),
                    style: Style::default(),
                },
                Span {
                    content: profile.name.clone().into(),
                    style: Style::default(),
                },
                Span {
                    content: "  ".into(),
                    style: Style::default(),
                },
                Span {
                    content: "Rename".into(),
                    style: if plugin_state.selected().is_some() {
                        Style::default()
                    } else {
                        Style::default().fg(BG).bg(FG)
                    },
                },
            ]));
            f.render_widget(header.clone(), header_chunk);
            let items = List::new(
                plugins
                    .iter()
                    .map(|p| {
                        ListItem::new(format!(
                            "{} {}({}) - {}",
                            if entry_plugins.iter().any(|e| e.id == p.id) {
                                "(*)"
                            } else {
                                "   "
                            },
                            &p.name,
                            &p.plugin,
                            &p.desc,
                        ))
                    })
                    .collect::<Vec<_>>(),
            )
            .block(Block::default().title("Plugins").borders(Borders::ALL))
            .highlight_style(Style::default().bg(FG).fg(BG));
            f.render_stateful_widget(items, main_chunk, &mut plugin_state);
            f.render_widget(
                match (delete_confirm, plugin_state.selected()) {
                    (true, _) => Paragraph::new("y: Delete Plugin; <any key>: Cancel"),
                    (_, Some(_)) => Paragraph::new(
                        "Enter: Edit params; c: Create Plugin; d: Delete Plugin; t: Change Plugin type\r\ne: Set/Unset as entry; F2: Rename; i: Edit desc; q: Quit",
                    ),
                    (_, None) => Paragraph::new("c: Create Plugin; Enter: Rename, q: Quit"),
                },
                status_bar_chunk,
            );
        })?;
        if delete_confirm {
            loop {
                if let Event::Key(ev) = crossterm::event::read().unwrap() {
                    if ev.code == KeyCode::Char('y') {
                        let idx = plugin_state.selected().unwrap();
                        let plugin_id = plugins.remove(idx).id;
                        Plugin::delete(plugin_id.0, &ctx.conn)
                            .context("Failed to delete Plugin")?;
                        if idx == plugins.len() {
                            plugin_state.select(plugins.len().checked_sub(1));
                        }
                    }
                    delete_confirm = false;
                    continue 'main_loop;
                }
            }
        }
        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match (code, plugin_state.selected()) {
                (KeyCode::Char('q') | KeyCode::Esc, _) => break,
                (KeyCode::Char('c'), _) => {
                    return Ok(NavChoice::PluginTypeView(profile.id, None));
                }

                (KeyCode::Down, None) => plugin_state.select(plugins.first().map(|_| 0)),
                (KeyCode::Down, Some(idx)) => plugin_state.select(Some((idx + 1) % plugins.len())),

                (KeyCode::Up, None) => {
                    plugin_state.select(plugins.last().map(|_| plugins.len() - 1))
                }
                (KeyCode::Up, Some(idx)) => plugin_state.select(idx.checked_sub(1)),
                (KeyCode::Enter, None) => {
                    let profile = profile.clone();
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Profile name".into(),
                        desc: "Enter a brief and meaningful name for the selected Profile.".into(),
                        initial_value: profile.name.clone(),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            Profile::update(profile.id.0, name, profile.locale.clone(), &ctx.conn)
                                .context("Failed to update Profile")?;
                            Ok(())
                        }),
                    }));
                }
                (KeyCode::Enter, Some(idx)) => {
                    let plugin = plugins[idx].clone();
                    if let Some(new_param) = open_editor_for_cbor(ctx, &plugin.param, |val| {
                        cbor4ii::serde::to_vec(vec![], &val)
                            .context("Failed to serialize Plugin param")
                    })? {
                        Plugin::update(
                            plugin.id.0,
                            profile.id,
                            plugin.name,
                            plugin.desc,
                            plugin.plugin,
                            plugin.plugin_version,
                            new_param.clone(),
                            &ctx.conn,
                        )
                        .context("Failed to update Plugin param")?;
                        plugins[idx].param = new_param;
                    }
                    continue 'main_loop;
                }
                (KeyCode::Char('d'), Some(_)) => {
                    delete_confirm = true;
                }
                (KeyCode::Char('t'), Some(idx)) => {
                    return Ok(NavChoice::PluginTypeView(
                        profile.id,
                        Some(plugins.remove(idx)),
                    ))
                }
                (KeyCode::Char('e'), Some(idx)) => {
                    let plugin = &plugins[idx];
                    if let Some(pos) = entry_plugins.iter().position(|p| p.id == plugin.id) {
                        Plugin::unset_as_entry(profile.id, plugin.id, &ctx.conn)
                            .context("Failed to unset Plugin as entry")?;
                        entry_plugins.remove(pos);
                    } else {
                        Plugin::set_as_entry(profile.id, plugin.id, &ctx.conn)
                            .context("Failed to set Plugin as entry")?;
                        entry_plugins.push(plugin.clone());
                    }
                }
                (KeyCode::F(2), Some(idx)) => {
                    let profile_id = profile.id;
                    let plugin = plugins[idx].clone();
                    // https://github.com/rust-lang/rustfmt/issues/3135
                    let desc = "Enter a name for the plugin. A good plugin name should contain no character other than digits, letters, dashes and underscores.".into();
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Plugin name".into(),
                        desc,
                        initial_value: plugin.name.clone(),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            Plugin::update(
                                plugin.id.0,
                                profile_id,
                                name,
                                plugin.desc.clone(),
                                plugin.plugin.clone(),
                                plugin.plugin_version,
                                plugin.param.clone(),
                                &ctx.conn,
                            )
                            .context("Failed to rename Plugin")?;
                            Ok(())
                        }),
                    }));
                }
                (KeyCode::Char('i'), Some(idx)) => {
                    let profile_id = profile.id;
                    let plugin = plugins[idx].clone();
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Plugin description".into(),
                        desc: "Enter a detailed description for the plugin.".into(),
                        initial_value: plugin.desc.clone(),
                        max_len: 10240,
                        action: Box::new(move |ctx, desc| {
                            Plugin::update(
                                plugin.id.0,
                                profile_id,
                                plugin.name.clone(),
                                desc,
                                plugin.plugin.clone(),
                                plugin.plugin_version,
                                plugin.param.clone(),
                                &ctx.conn,
                            )
                            .context("Failed to change Plugin desc")?;
                            Ok(())
                        }),
                    }));
                }
                _ => {}
            }
        };
    }
    Ok(NavChoice::Back)
}
