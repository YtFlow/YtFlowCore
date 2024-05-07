use std::cell::Cell;

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::{Block, Borders, List, ListItem, ListState},
};

use super::{bg_rev, InputRequest, NavChoice, BG};
use crate::edit;
use ytflow::data::proxy_group::{ProxyGroup, PROXY_GROUP_TYPE_MANUAL};

thread_local! {
    static SHOULD_RETURN: Cell<bool> = const { Cell::new(false) };
}

fn state_index_to_type(index: usize) -> Option<&'static str> {
    match index {
        0 => Some(PROXY_GROUP_TYPE_MANUAL),
        // 1 => Some(PROXY_GROUP_SUBSCRIPTION),
        _ => None,
    }
}

pub fn run_new_proxy_group_view(ctx: &mut edit::AppContext) -> Result<NavChoice> {
    if SHOULD_RETURN.with(|c| c.replace(false)) {
        return Ok(NavChoice::Back);
    }
    let mut type_state = ListState::default();
    type_state.select(Some(0));
    loop {
        let size = ctx.term.size()?;
        let main_chunk = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0)].as_ref())
            .split(size)[0];
        let template_list = List::new([
            ListItem::new("User-managed proxy group"),
            // ListItem::new("Subscription"),
        ])
        .block(
            Block::default()
                .title("Choose a type")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().bg(bg_rev(true)).fg(BG));
        ctx.term.draw(|f| {
            f.render_stateful_widget(template_list, main_chunk, &mut type_state);
        })?;
        if let Event::Key(KeyEvent {
            code,
            kind: KeyEventKind::Press,
            ..
        }) = crossterm::event::read().unwrap()
        {
            match (code, type_state.selected()) {
                (KeyCode::Char('q') | KeyCode::Esc, _) => return Ok(NavChoice::Back),
                (KeyCode::Down, _) => {
                    type_state.select(type_state.selected().map(|i| (i + 1) % 1));
                }
                (KeyCode::Up, _) => {
                    type_state.select(type_state.selected().map(
                        |i| {
                            if i == 0 {
                                0
                            } else {
                                i - 1
                            }
                        },
                    ));
                }
                (KeyCode::Enter, Some(selected_index)) => {
                    SHOULD_RETURN.with(|c| c.set(true));
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Proxy Group name".into(),
                        desc: "Create a new Proxy Group with the specified name.".into(),
                        initial_value: format!(
                            "{}-{}",
                            state_index_to_type(selected_index)
                                .expect("Invalid Proxy Group type index"),
                            nanoid::nanoid!(5)
                        ),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            ProxyGroup::create(
                                name,
                                state_index_to_type(selected_index)
                                    .expect("Invalid Proxy Group type index")
                                    .into(),
                                &ctx.conn,
                            )
                            .context("Failed to rename Profile")?;
                            Ok(())
                        }),
                    }));
                }
                _ => {}
            }
        };
    }
}
