use std::cell::RefCell;

use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyEvent};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use super::{bg_rev, InputRequest, NavChoice, BG};
use ytflow::data::{Profile, ProxyGroup};

const CATEGORY_ITEM_COUNT: usize = 3;
const CATEGORY_ITEM_INDEX_PROFILE: usize = 0;
const CATEGORY_ITEM_INDEX_PROXY_GROUP: usize = 1;
const CATEGORY_ITEM_INDEX_ABOUT: usize = 2;

enum DeleteAction {
    Profile,
    ProxyGroup,
}

struct MainViewStates {
    focus_left: bool,
    category_state: ListState,
    profile_state: ListState,
    proxy_group_state: ListState,
}

impl Default for MainViewStates {
    fn default() -> Self {
        let mut category_state = ListState::default();
        category_state.select(Some(CATEGORY_ITEM_INDEX_PROFILE));
        Self {
            focus_left: true,
            category_state,
            profile_state: ListState::default(),
            proxy_group_state: ListState::default(),
        }
    }
}

thread_local! {
    static MAIN_VIEW_STATES: RefCell<MainViewStates> = Default::default();
}

pub fn run_main_view(ctx: &mut crate::AppContext) -> Result<NavChoice> {
    MAIN_VIEW_STATES.with(|states| {
        let mut states = states.borrow_mut();
        run_main_view_with_states(ctx, &mut states)
    })
}

fn run_main_view_with_states(
    ctx: &mut crate::AppContext,
    states: &mut MainViewStates,
) -> Result<NavChoice> {
    let mut profiles = Profile::query_all(&ctx.conn).context("Could not query all profiles")?;
    let mut proxy_groups =
        ProxyGroup::query_all(&ctx.conn).context("Could not query all proxy groups")?;
    let MainViewStates {
        focus_left,
        category_state,
        profile_state,
        proxy_group_state,
    } = states;
    if profile_state.selected().is_none() && !profiles.is_empty() {
        profile_state.select(Some(0));
    }
    if proxy_group_state.selected().is_none() && !proxy_groups.is_empty() {
        proxy_group_state.select(Some(0));
    }
    let mut delete_action: Option<DeleteAction> = None;

    'main_loop: loop {
        let size = ctx.term.size()?;
        let vchunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)].as_ref())
            .split(size);
        let status_bar_chunk = vchunks[1];
        let main_chunk = vchunks[0];
        let hchunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Max(u16::MAX)].as_ref())
            .split(main_chunk);
        let right_chunk = hchunks[1];
        let left_chunk = hchunks[0];
        let category_list = List::new([
            ListItem::new("Profiles"),
            ListItem::new("Proxy Groups"),
            ListItem::new("About"),
        ])
        .block(
            Block::default()
                .title("Menu")
                .borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM),
        )
        .highlight_style(Style::default().bg(bg_rev(*focus_left)).fg(BG));
        ctx.term.draw(|f| {
            f.render_stateful_widget(category_list.clone(), left_chunk, category_state);
            match category_state.selected().unwrap_or_default() {
                CATEGORY_ITEM_INDEX_PROFILE => {
                    let items = List::new(
                        profiles
                            .iter()
                            .map(|p| ListItem::new(p.name.clone()))
                            .collect::<Vec<_>>(),
                    )
                    .block(Block::default().title("Profiles").borders(Borders::ALL))
                    .highlight_style(Style::default().bg(bg_rev(!*focus_left)).fg(BG));
                    f.render_stateful_widget(items, right_chunk, profile_state);
                    f.render_widget(
                        Paragraph::new(if delete_action.is_some() {
                            "y: delete Profile; <any key>: cancel"
                        } else {
                            "c: Create Profile; d: Delete Profile; F2: Rename Profile; q: Quit"
                        }),
                        status_bar_chunk,
                    );
                }
                CATEGORY_ITEM_INDEX_PROXY_GROUP => {
                    let items = List::new(
                        proxy_groups
                            .iter()
                            .map(|p| ListItem::new(p.name.clone()))
                            .collect::<Vec<_>>(),
                    )
                    .block(Block::default().title("Proxy Groups").borders(Borders::ALL))
                    .highlight_style(Style::default().bg(bg_rev(!*focus_left)).fg(BG));
                    f.render_stateful_widget(items, right_chunk, proxy_group_state);
                    f.render_widget(
                        Paragraph::new(if delete_action.is_some() {
                            "y: delete Proxy Group; <any key>: cancel"
                        } else {
                            "c: Create Proxy Group; d: Delete Proxy Group; F2: Rename Proxy Group; q: Quit"
                        }),
                        status_bar_chunk,
                    );
                }
                CATEGORY_ITEM_INDEX_ABOUT => {
                    let content = Paragraph::new(
                        r"
About YtFlow Editor

https://github.com/YtFlow/YtFlowCore",
                    )
                    .block(Block::default().title("About").borders(Borders::ALL));
                    f.render_widget(content, right_chunk);
                    f.render_widget(Paragraph::new("q: Quit"), status_bar_chunk);
                }
                _ => unreachable!("Unknown selected category"),
            };
        })?;
        if let Some(delete_action) = delete_action.take() {
            loop {
                let ev = if let Event::Key(ev) = crossterm::event::read().unwrap() {
                    ev
                } else {
                    continue;
                };
                if ev.code == KeyCode::Char('y') {
                    match delete_action {
                        DeleteAction::Profile => {
                            let idx = profile_state.selected().unwrap();
                            let profile_id = profiles.remove(idx).id;
                            Profile::delete(profile_id.0, &ctx.conn)
                                .context("Failed to delete profile")?;
                            if profiles.len() == idx {
                                profile_state.select(profiles.len().checked_sub(1));
                            }
                        }
                        DeleteAction::ProxyGroup => {
                            let idx = proxy_group_state.selected().unwrap();
                            let proxy_group_id = proxy_groups.remove(idx).id;
                            ProxyGroup::delete(proxy_group_id.0, &ctx.conn)
                                .context("Failed to delete proxy group")?;
                            if proxy_groups.len() == idx {
                                proxy_group_state.select(proxy_groups.len().checked_sub(1));
                            }
                        }
                    }
                }
                continue 'main_loop;
            }
        }
        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c')
                    if category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    return Ok(NavChoice::NewProfileView);
                }
                KeyCode::Char('c')
                    if category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    return Ok(NavChoice::NewProxyGroupView);
                }
                KeyCode::Down if *focus_left => {
                    category_state.select(
                        category_state
                            .selected()
                            .map(|i| (i + 1) % CATEGORY_ITEM_COUNT),
                    );
                }
                KeyCode::Up if *focus_left => {
                    category_state.select(category_state.selected().map(|i| {
                        if i == 0 {
                            1
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Right | KeyCode::Enter if *focus_left => {
                    *focus_left = false;
                }
                KeyCode::Left => {
                    *focus_left = true;
                }
                KeyCode::Enter
                    if category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    if let Some(idx) = profile_state.selected() {
                        return Ok(NavChoice::ProfileView(profiles[idx].id));
                    }
                }
                KeyCode::Enter
                    if category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    if let Some(idx) = proxy_group_state.selected() {
                        return Ok(NavChoice::ProxyGroupView(proxy_groups[idx].id));
                    }
                }
                KeyCode::Down
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    profile_state
                        .select(profile_state.selected().map(|i| (i + 1) % profiles.len()));
                }
                KeyCode::Up
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    profile_state.select(profile_state.selected().map(|i| {
                        if i == 0 {
                            profiles.len() - 1
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Down
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    proxy_group_state.select(
                        proxy_group_state
                            .selected()
                            .map(|i| (i + 1) % proxy_groups.len()),
                    );
                }
                KeyCode::Up
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    proxy_group_state.select(proxy_group_state.selected().map(|i| {
                        if i == 0 {
                            proxy_groups.len() - 1
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Char('d')
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    if profile_state.selected().is_some() {
                        delete_action = Some(DeleteAction::Profile);
                    }
                }
                KeyCode::Char('d')
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    if proxy_group_state.selected().is_some() {
                        delete_action = Some(DeleteAction::ProxyGroup);
                    }
                }
                KeyCode::F(2)
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROFILE) =>
                {
                    if let Some(idx) = profile_state.selected() {
                        let profile = profiles[idx].clone();
                        return Ok(NavChoice::InputView(InputRequest {
                            item: "new Profile name".into(),
                            desc: "Enter a brief and meaningful name for the selected Profile."
                                .into(),
                            initial_value: profile.name.clone(),
                            max_len: 255,
                            action: Box::new(move |ctx, name| {
                                Profile::update(
                                    profile.id.0,
                                    name,
                                    profile.locale.clone(),
                                    &ctx.conn,
                                )
                                .context("Failed to rename Profile")?;
                                Ok(())
                            }),
                        }));
                    }
                }
                KeyCode::F(2)
                    if !*focus_left
                        && category_state.selected() == Some(CATEGORY_ITEM_INDEX_PROXY_GROUP) =>
                {
                    if let Some(idx) = proxy_group_state.selected() {
                        let proxy_group = proxy_groups[idx].clone();
                        return Ok(NavChoice::InputView(InputRequest {
                            item: "new Proxy Group name".into(),
                            desc: "Enter a unique name for the selected Proxy Group.".into(),
                            initial_value: proxy_group.name.clone(),
                            max_len: 255,
                            action: Box::new(move |ctx, name| {
                                ProxyGroup::rename(proxy_group.id.0, name, &ctx.conn)
                                    .context("Failed to rename Proxy Group")?;
                                Ok(())
                            }),
                        }));
                    }
                }
                _ => {}
            }
        };
    }
    Ok(NavChoice::Back)
}
