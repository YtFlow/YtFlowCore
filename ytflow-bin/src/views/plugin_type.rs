use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use super::{NavChoice, BG, FG};
use ytflow::data::{Plugin, ProfileId};

pub fn run_plugin_type_view(
    ctx: &mut crate::AppContext,
    profile_id: ProfileId,
    plugin: &mut Option<Plugin>,
) -> Result<NavChoice> {
    use strum::{EnumMessage, IntoEnumIterator};

    let title_text = match plugin {
        Some(p) => format!("Choose a new type for Plugin {}", &p.name),
        None => "Choose a type for the new plugin".into(),
    };
    let type_names: Vec<_> = crate::gen::plugins::PluginType::iter()
        .map(|t| ListItem::new(t.to_string()))
        .collect();
    let type_descs: Vec<_> = crate::gen::plugins::PluginType::iter()
        .map(|t| t.get_detailed_message().expect("Missing detailed message"))
        .collect();
    let mut select_confirm = false;
    let mut type_state = ListState::default();
    type_state.select(Some(0));

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
        let hchunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Max(u16::MAX)].as_ref())
            .split(main_chunk);
        let right_chunk = hchunks[1];
        let left_chunk = hchunks[0];

        ctx.term.draw(|f| {
            let header = Paragraph::new(title_text.as_str());
            f.render_widget(header, header_chunk);

            let status_bar = if select_confirm {
                Paragraph::new("WARNING: changing the Plugin type will overwrite existing param. This is irreversible.\r\ny: confirm, <any key>: cancel")
                    .style(Style::default().fg(Color::Yellow))
            } else {
                Paragraph::new("Enter: Choose; q: Quit")
            };
            f.render_widget(status_bar, status_bar_chunk);

            let left_list = List::new(type_names.clone())
                .block(Block::default().borders(Borders::ALL).title("Plugin type"))
                .highlight_style(Style::default().fg(BG).bg(FG));
            f.render_stateful_widget(left_list, left_chunk, &mut type_state);

            let right_panel = Paragraph::new(type_descs[type_state.selected().unwrap()]).wrap(Wrap { trim: false });
            f.render_widget(right_panel, right_chunk);
        })?;

        if select_confirm {
            loop {
                let plugin_type = crate::gen::plugins::PluginType::iter()
                    .nth(type_state.selected().unwrap())
                    .unwrap();
                let new_plugin = plugin_type.gen_default();
                if let Some(plugin) = plugin {
                    // Overwriting existing plugin, wait for user confirm
                    let ev = if let Event::Key(ev) = crossterm::event::read().unwrap() {
                        ev
                    } else {
                        continue;
                    };
                    if ev.code != KeyCode::Char('y') {
                        select_confirm = false;
                        continue 'main_loop;
                    }
                    Plugin::update(
                        plugin.id.0,
                        profile_id,
                        plugin.name.clone(),
                        plugin.desc.clone(),
                        new_plugin.plugin,
                        new_plugin.plugin_version,
                        new_plugin.param,
                        &ctx.conn,
                    )
                    .context("Failed to change Plugin type")?;
                } else {
                    // Creating a new plugin, confirm not needed
                    Plugin::create(
                        profile_id,
                        new_plugin.name,
                        plugin_type.get_detailed_message().unwrap().into(),
                        new_plugin.plugin,
                        new_plugin.plugin_version,
                        new_plugin.param,
                        &ctx.conn,
                    )
                    .context("Failed to create Plugin")?;
                }
                return Ok(NavChoice::Back);
            }
        }

        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Enter => select_confirm = true,
                KeyCode::Down => {
                    let selected = type_state.selected().unwrap();
                    type_state.select(Some((selected + 1) % type_names.len()));
                }
                KeyCode::Up => {
                    let selected = type_state.selected().unwrap();
                    type_state.select(Some(
                        selected.checked_sub(1).unwrap_or(type_names.len() - 1),
                    ));
                }
                _ => (),
            }
        }
    }

    Ok(NavChoice::Back)
}
