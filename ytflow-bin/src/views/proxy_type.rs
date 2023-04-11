use std::cell::Cell;

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::{Block, Borders, List, ListItem, ListState},
};

use crate::views::InputRequest;

use super::{NavChoice, BG, FG};
use ytflow::data::{Proxy, ProxyGroupId};

thread_local! {
    static SHOULD_RETURN: Cell<bool> = Cell::new(false);
    static LAST_NEW_PROXY_NAME: Cell<String> = Cell::new(String::new());
}

pub fn run_proxy_type_view(
    ctx: &mut crate::AppContext,
    proxy_group_id: ProxyGroupId,
) -> Result<NavChoice> {
    use strum::IntoEnumIterator;
    if SHOULD_RETURN.with(|c| c.replace(false)) {
        return Ok(NavChoice::Back);
    }

    let type_names: Vec<_> = crate::gen::proxy_types::ProxyType::iter()
        .map(|t| ListItem::new(t.to_string()))
        .collect();
    let mut type_state = ListState::default();
    type_state.select(Some(0));

    loop {
        let size = ctx.term.size()?;
        let main_chunk = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0)].as_ref())
            .split(size)[0];

        ctx.term.draw(|f| {
            let type_list = List::new(type_names.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Choose a Proxy type"),
                )
                .highlight_style(Style::default().fg(BG).bg(FG));
            f.render_stateful_widget(type_list, main_chunk, &mut type_state);
        })?;

        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match (code, type_state.selected()) {
                (KeyCode::Char('q') | KeyCode::Esc, _) => break,
                (KeyCode::Enter, Some(idx)) => {
                    SHOULD_RETURN.with(|c| c.set(true));
                    let proxy_type = crate::gen::proxy_types::ProxyType::iter()
                        .nth(idx)
                        .expect("Cannot find corresponding proxy type");
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Proxy name".into(),
                        desc: "Name the new Proxy".into(),
                        initial_value: LAST_NEW_PROXY_NAME.with(|c| c.take()),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            LAST_NEW_PROXY_NAME.with(|c| c.set(name.clone()));
                            Proxy::create(
                                proxy_group_id,
                                name,
                                proxy_type.gen_default_proxy(),
                                0,
                                &ctx.conn,
                            )
                            .context("Failed to create proxy")?;
                            Ok(())
                        }),
                    }));
                }
                (KeyCode::Down, Some(idx)) => {
                    type_state.select(Some((idx + 1) % type_names.len()));
                }
                (KeyCode::Up, Some(idx)) => {
                    type_state.select(Some(idx.checked_sub(1).unwrap_or(type_names.len() - 1)));
                }
                _ => (),
            }
        }
    }

    Ok(NavChoice::Back)
}
