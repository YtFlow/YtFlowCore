use anyhow::{anyhow, bail, Context, Result};
use cbor4ii::core::Value as CborValue;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tui::{
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use super::{InputRequest, NavChoice, BG, FG};
use crate::edit;
use ytflow::data::{Proxy, ProxyGroup, ProxyGroupId};

pub fn run_proxy_group_view(ctx: &mut edit::AppContext, id: ProxyGroupId) -> Result<NavChoice> {
    let proxy_group = ProxyGroup::query_by_id(id.0 as _, &ctx.conn)
        .context("Could not query selected proxy group")?
        .ok_or_else(|| anyhow!("Profile not found"))?;
    let mut proxies = Proxy::query_all_by_group(proxy_group.id, &ctx.conn)
        .context("Failed to query all proxies")?;
    let mut delete_confirm = false;
    let mut action_state = ListState::default();
    let mut proxy_state = ListState::default();
    if !proxies.is_empty() {
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
                    content: proxy_group.name.clone().into(),
                    style: Style::default(),
                },
                Span {
                    content: "  ".into(),
                    style: Style::default(),
                },
                Span {
                    content: "Rename".into(),
                    style: if proxy_state.selected().is_some() {
                        Style::default()
                    } else {
                        Style::default().fg(BG).bg(FG)
                    },
                },
            ]));
            f.render_widget(header.clone(), header_chunk);
            let items = List::new(
                proxies
                    .iter()
                    .map(|p| {
                        ListItem::new(&*p.name)
                    })
                    .collect::<Vec<_>>(),
            )
            .block(Block::default().title("Proxies").borders(Borders::ALL))
            .highlight_style(Style::default().bg(FG).fg(BG));
            f.render_stateful_widget(items, main_chunk, &mut proxy_state);
            f.render_widget(
                match (delete_confirm, proxy_state.selected()) {
                    (true, _) => Paragraph::new("y: Delete Proxy; <any key>: Cancel"),
                    (_, Some(_)) => Paragraph::new(
                        "Enter: Edit Proxy; c: Create Proxy; d: Delete Plugin\r\n+/-: Reorder; F2: Rename; q: Quit",
                    ),
                    (_, None) => Paragraph::new("c: Create Proxy; Enter: Rename, q: Quit"),
                },
                status_bar_chunk,
            );
        })?;
        if delete_confirm {
            loop {
                if let Event::Key(ev) = crossterm::event::read().unwrap() {
                    if ev.code == KeyCode::Char('y') {
                        let idx = proxy_state.selected().unwrap();
                        let proxy_id = proxies.remove(idx).id;
                        Proxy::delete(proxy_id.0, &ctx.conn).context("Failed to delete Proxy")?;
                        if idx == proxies.len() {
                            proxy_state.select(proxies.len().checked_sub(1));
                        }
                    }
                    delete_confirm = false;
                    continue 'main_loop;
                }
            }
        }
        if let Event::Key(KeyEvent {
            code,
            kind: KeyEventKind::Press,
            ..
        }) = crossterm::event::read().unwrap()
        {
            match (code, proxy_state.selected()) {
                (KeyCode::Char('q') | KeyCode::Esc, _) => break,
                (KeyCode::Char('c'), _) => return Ok(NavChoice::ProxyTypeView(proxy_group.id)),

                (KeyCode::Down, None) => proxy_state.select(proxies.first().map(|_| 0)),
                (KeyCode::Down, Some(idx)) => proxy_state.select(Some((idx + 1) % proxies.len())),

                (KeyCode::Up, None) => {
                    proxy_state.select(proxies.last().map(|_| proxies.len() - 1))
                }
                (KeyCode::Up, Some(idx)) => proxy_state.select(idx.checked_sub(1)),
                (KeyCode::Enter, None) => {
                    let proxy_group = proxy_group.clone();
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Proxy Group name".into(),
                        desc: "Rename the Proxy Group.".into(),
                        initial_value: proxy_group.name.clone(),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            ProxyGroup::rename(proxy_group.id.0, name, &ctx.conn)
                                .context("Failed to update Proxy Group")?;
                            Ok(())
                        }),
                    }));
                }
                (KeyCode::Enter, Some(idx)) => {
                    let proxy = proxies[idx].clone();
                    if proxy.proxy_version != 0 {
                        bail!("Proxy version {} is not supported", proxy.proxy_version)
                    }
                    if let Some(new_proxy_param) = edit_proxy(ctx, &proxy.proxy)? {
                        Proxy::update(
                            proxy.id.0,
                            proxy.name,
                            new_proxy_param.clone(),
                            proxy.proxy_version,
                            &ctx.conn,
                        )
                        .context("Failed to update Proxy")?;
                        proxies[idx].proxy = ByteBuf::from(new_proxy_param);
                    }
                    continue 'main_loop;
                }
                (KeyCode::Char('d'), Some(_)) => {
                    delete_confirm = true;
                }
                (KeyCode::F(2), Some(idx)) => {
                    let proxy = proxies[idx].clone();
                    // https://github.com/rust-lang/rustfmt/issues/3135
                    let desc = "Enter a name for the proxy.".into();
                    return Ok(NavChoice::InputView(InputRequest {
                        item: "new Proxy name".into(),
                        desc,
                        initial_value: proxy.name.clone(),
                        max_len: 255,
                        action: Box::new(move |ctx, name| {
                            Proxy::update(
                                proxy.id.0,
                                name,
                                proxy.proxy.to_vec(),
                                proxy.proxy_version,
                                &ctx.conn,
                            )
                            .context("Failed to rename Proxy")?;
                            Ok(())
                        }),
                    }));
                }
                (KeyCode::Char('+' | '='), Some(idx)) => {
                    if idx + 1 == proxies.len() {
                        continue 'main_loop;
                    }
                    let proxy = &proxies[idx];
                    Proxy::reorder(
                        proxy_group.id,
                        proxy.order_num,
                        proxy.order_num,
                        1,
                        &mut ctx.conn,
                    )
                    .context("Reordering proxy")?;
                    proxies = Proxy::query_all_by_group(proxy_group.id, &ctx.conn)
                        .context("Failed to reload all proxies")?;
                    proxy_state.select(Some(idx + 1));
                }
                (KeyCode::Char('-' | '_'), Some(idx)) => {
                    if idx == 0 {
                        continue 'main_loop;
                    }
                    let proxy = &proxies[idx];
                    Proxy::reorder(
                        proxy_group.id,
                        proxy.order_num,
                        proxy.order_num,
                        -1,
                        &mut ctx.conn,
                    )
                    .context("Reordering proxy")?;
                    proxies = Proxy::query_all_by_group(proxy_group.id, &ctx.conn)
                        .context("Failed to reload all proxies")?;
                    proxy_state.select(Some(idx - 1));
                }
                _ => {}
            }
        };
    }
    Ok(NavChoice::Back)
}

#[derive(Serialize, Deserialize)]
struct EditPlugin {
    pub name: String,
    pub plugin: String,
    pub plugin_version: u16,
    pub param: CborValue,
}

#[derive(Serialize, Deserialize)]
struct EditProxy {
    pub tcp_entry: String,
    pub udp_entry: Option<String>,
    pub plugins: Vec<EditPlugin>,
}

fn edit_proxy(ctx: &mut edit::AppContext, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    use super::utils::open_editor_for_cbor;
    use ytflow::plugin::dyn_outbound::config::v1::{Plugin, Proxy};

    let proxy: Proxy = cbor4ii::serde::from_slice(bytes).context("Failed to deserialize proxy")?;
    let plugins = proxy
        .plugins
        .into_iter()
        .map(|p| {
            let param: CborValue = cbor4ii::serde::from_slice(p.param.as_slice())
                .with_context(|| format!("Failed to deserialize param for plugin {}", p.name))?;
            Ok(EditPlugin {
                name: p.name,
                plugin: p.plugin,
                plugin_version: p.plugin_version,
                param,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let val = EditProxy {
        tcp_entry: proxy.tcp_entry,
        udp_entry: proxy.udp_entry,
        plugins,
    };

    // Serialize cborium Value into bytes using cbor4ii and deserialize into cbor4ii Value
    let buf = Vec::with_capacity(512);
    let val = cbor4ii::serde::to_vec(buf, &val).expect("Cannot serialize ciborium Value");

    open_editor_for_cbor(ctx, &val, |val| {
        let buf = Vec::with_capacity(512);
        let val: EditProxy =
            cbor4ii::serde::from_slice(&cbor4ii::serde::to_vec(buf, &val).unwrap())
                .context("Parsing Plugin")?;
        let proxy = Proxy {
            tcp_entry: val.tcp_entry,
            udp_entry: val.udp_entry,
            plugins: val
                .plugins
                .into_iter()
                .map(|p| {
                    let buf = Vec::with_capacity(96);
                    let param = cbor4ii::serde::to_vec(buf, &p.param).unwrap();
                    // TODO: verify plugin params
                    Ok(Plugin {
                        name: p.name,
                        plugin: p.plugin,
                        plugin_version: p.plugin_version,
                        param: ByteBuf::from(param),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let buf = Vec::with_capacity(512);
        Ok(cbor4ii::serde::to_vec(buf, &proxy).unwrap())
    })
}
