use std::io;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::prelude::*;
use clap::{arg, value_parser, ArgMatches};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};

mod gen;
use ytflow::data::{Connection, Database, Plugin, Profile, ProfileId};

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

fn main() -> Result<()> {
    let args = get_args();
    let conn = get_db_conn(&args)?;
    run_tui(conn)?;
    Ok(())
}

fn get_args() -> ArgMatches {
    clap::command!()
        .arg(arg!(<PATH> "Path to the database file").value_parser(value_parser!(PathBuf)))
        .get_matches()
}

fn get_db_conn(args: &ArgMatches) -> Result<Connection> {
    let db_path: &PathBuf = args.get_one("PATH").expect("Cannot get database path");
    let db = Database::open(db_path).context("Could not prepare database")?;
    let conn = db.connect().context("Could not connect to database")?;
    Ok(conn)
}

fn run_tui(conn: Connection) -> Result<()> {
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Could not create terminal")?;
    terminal.clear().unwrap();
    enable_raw_mode().unwrap();
    terminal.hide_cursor().unwrap();
    let mut ctx = AppContext {
        term: terminal,
        conn,
    };
    let res = run_main_loop(&mut ctx);
    let mut terminal = ctx.term;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .unwrap();
    terminal.show_cursor().unwrap();
    disable_raw_mode().unwrap();
    res
}

struct AppContext {
    term: Terminal<CrosstermBackend<io::Stdout>>,
    conn: Connection,
}

struct InputRequest {
    item: String,
    desc: String,
    initial_value: String,
    max_len: usize,
    action: Box<dyn FnMut(&mut AppContext, String) -> Result<()>>,
}

enum NavChoice {
    MainView,
    NewProfileView,
    ProfileView(ProfileId),
    PluginTypeView(ProfileId, Option<Plugin>),
    InputView(InputRequest),
    Back,
}

fn run_main_loop(ctx: &mut AppContext) -> Result<()> {
    let mut nav_choices = vec![NavChoice::MainView];
    loop {
        let next_nav_choice = match nav_choices.last_mut() {
            Some(NavChoice::MainView) => run_main_view(ctx)?,
            Some(NavChoice::NewProfileView) => run_new_profile_view(ctx)?,
            Some(NavChoice::ProfileView(id)) => run_profile_view(ctx, *id)?,
            Some(NavChoice::PluginTypeView(profile_id, plugin)) => {
                run_plugin_type_view(ctx, *profile_id, plugin)?
            }
            Some(NavChoice::InputView(req)) => run_input_view(ctx, req)?,
            Some(NavChoice::Back) => {
                nav_choices.pop(); // Pop "Back" out
                nav_choices.pop(); // Pop this page out
                continue;
            }
            None => break Ok(()),
        };
        nav_choices.push(next_nav_choice);
    }
}

fn run_main_view(ctx: &mut AppContext) -> Result<NavChoice> {
    let mut profiles = Profile::query_all(&ctx.conn).context("Could not query all profiles")?;
    let mut focus_left = true;
    let mut category_state = ListState::default();
    let mut profile_state = ListState::default();
    category_state.select(Some(0));
    if !profiles.is_empty() {
        profile_state.select(Some(0));
    }
    let mut delete_confirm = false;

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
        let category_list = List::new([ListItem::new("Profiles"), ListItem::new("About")])
            .block(
                Block::default()
                    .title("Menu")
                    .borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM),
            )
            .highlight_style(Style::default().bg(bg_rev(focus_left)).fg(BG));
        ctx.term.draw(|f| {
            f.render_stateful_widget(category_list.clone(), left_chunk, &mut category_state);
            match category_state.selected().unwrap_or_default() {
                0 => {
                    let items = List::new(
                        profiles
                            .iter()
                            .map(|p| ListItem::new(p.name.clone()))
                            .collect::<Vec<_>>(),
                    )
                    .block(Block::default().title("Profiles").borders(Borders::ALL))
                    .highlight_style(Style::default().bg(bg_rev(!focus_left)).fg(BG));
                    f.render_stateful_widget(items, right_chunk, &mut profile_state);
                    f.render_widget(
                        Paragraph::new(if delete_confirm {
                            "y: delete Profile; <any key>: cancel"
                        } else {
                            "c: Create Profile; d: Delete Profile; F2: Rename Profile; q: Quit"
                        }),
                        status_bar_chunk,
                    );
                }
                1 => {
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
        if delete_confirm {
            loop {
                let ev = if let Event::Key(ev) = crossterm::event::read().unwrap() {
                    ev
                } else {
                    continue;
                };
                if ev.code == KeyCode::Char('y') {
                    let idx = profile_state.selected().unwrap();
                    let profile_id = profiles.remove(idx).id;
                    Profile::delete(profile_id.0, &ctx.conn).context("Failed to delete profile")?;
                    if profiles.len() == idx {
                        profile_state.select(None);
                    }
                }
                delete_confirm = false;
                continue 'main_loop;
            }
        }
        if let Event::Key(KeyEvent { code, .. }) = crossterm::event::read().unwrap() {
            match code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c') if category_state.selected() == Some(0) => {
                    return Ok(NavChoice::NewProfileView);
                }
                KeyCode::Down if focus_left => {
                    category_state.select(category_state.selected().map(|i| (i + 1) % 2));
                }
                KeyCode::Up if focus_left => {
                    category_state.select(category_state.selected().map(|i| {
                        if i == 0 {
                            1
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Right | KeyCode::Enter if focus_left => {
                    focus_left = false;
                }
                KeyCode::Left => {
                    focus_left = true;
                }
                KeyCode::Enter if category_state.selected() == Some(0) => {
                    if let Some(idx) = profile_state.selected() {
                        return Ok(NavChoice::ProfileView(profiles[idx].id));
                    }
                }
                KeyCode::Down if !focus_left && category_state.selected() == Some(0) => {
                    profile_state
                        .select(profile_state.selected().map(|i| (i + 1) % profiles.len()));
                }
                KeyCode::Up if !focus_left && category_state.selected() == Some(0) => {
                    profile_state.select(profile_state.selected().map(|i| {
                        if i == 0 {
                            profiles.len() - 1
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Char('d') if !focus_left && category_state.selected() == Some(0) => {
                    if profile_state.selected().is_some() {
                        delete_confirm = true;
                    }
                }
                KeyCode::F(2) if !focus_left && category_state.selected() == Some(0) => {
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
                _ => {}
            }
        };
    }
    Ok(NavChoice::Back)
}

fn run_new_profile_view(ctx: &mut AppContext) -> Result<NavChoice> {
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
                    template_state.select(template_state.selected().map(|i| (i + 1) % 3));
                }
                KeyCode::Up => {
                    template_state.select(template_state.selected().map(|i| {
                        if i == 0 {
                            3
                        } else {
                            i - 1
                        }
                    }));
                }
                KeyCode::Enter => {
                    let profile_id =
                        gen::create_profile(&ctx.conn).context("Could not create profile")?;
                    let selected = template_state.selected().unwrap_or_default();
                    match selected {
                        0 => {
                            let plugins = gen::generate_shadowsocks_plugins();
                            gen::save_plugins(plugins, profile_id, &ctx.conn)
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

fn run_profile_view(ctx: &mut AppContext, id: ProfileId) -> Result<NavChoice> {
    let profile = Profile::query_by_id(id.0 as _, &ctx.conn)
        .context("Could not query all profiles")?
        .ok_or_else(|| anyhow!("Profile not found"))?;
    let mut plugins = Plugin::query_all_by_profile(profile.id, &ctx.conn)
        .context("Failed to query all profiles")?;
    let mut entry_plugins = Plugin::query_entry_by_profile(profile.id, &ctx.conn)
        .context("Failed to query entry profiles")?;
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
                            plugin_state.select(None);
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
                    use cbor4ii::core::Value as CborValue;
                    // Note: some editors will change line endings
                    const CANCEL_SAFEWORD: &[u8] =
                        b"//  === Remove this line to cancel editing ===\n";
                    const BAD_JSON_MSG: & [u8] = b"//  === Remove this line and everything below after correcting the errors ===\n";
                    let plugin = plugins[idx].clone();
                    let mut json_val: CborValue = cbor4ii::serde::from_slice(&plugin.param)
                        .context("Failed to deserialize Plugin param from CBOR")?;

                    /// Map CBOR bytes to string or base64 encoded string for
                    /// later converting back.
                    fn escape_cbor_buf(val: &mut CborValue) {
                        match val {
                            CborValue::Bytes(bytes) => {
                                let bytes = std::mem::take(bytes);
                                *val = match std::str::from_utf8(&bytes) {
                                    Ok(str) => CborValue::Map(vec![
                                        (
                                            CborValue::Text("__byte_repr".into()),
                                            CborValue::Text("utf8".into()),
                                        ),
                                        (
                                            CborValue::Text("data".into()),
                                            CborValue::Text(str.into()),
                                        ),
                                    ]),
                                    Err(_) => CborValue::Map(vec![
                                        (
                                            CborValue::Text("__byte_repr".into()),
                                            CborValue::Text("base64".into()),
                                        ),
                                        (
                                            CborValue::Text("data".into()),
                                            CborValue::Text(BASE64_STANDARD.encode(&bytes)),
                                        ),
                                    ]),
                                };
                            }
                            CborValue::Array(v) => v.iter_mut().for_each(escape_cbor_buf),
                            CborValue::Map(kvs) => kvs
                                .iter_mut()
                                .for_each(|(k, v)| (escape_cbor_buf(k), escape_cbor_buf(v), ()).2),
                            _ => {}
                        }
                    }

                    escape_cbor_buf(&mut json_val);
                    let json_buf = serde_json::to_vec_pretty(&json_val)
                        .context("Failed to convert Plugin param into JSON")?;
                    let mut edit_buf = CANCEL_SAFEWORD.to_vec();
                    edit_buf.extend_from_slice(&json_buf);
                    json_val = loop {
                        let input_buf = edit::edit_bytes_with_builder(
                            &edit_buf,
                            edit::Builder::new()
                                .prefix("ytflow-editor-param-")
                                .suffix(".json"),
                        )
                        .context("Failed to edit Plugin param")?;
                        // Editor process output will mess up the terminal
                        // Force a redraw
                        ctx.term.clear().unwrap();

                        if !input_buf.starts_with(CANCEL_SAFEWORD)
                            || (input_buf.len() == edit_buf.len()
                                && input_buf.as_slice() == edit_buf.as_slice())
                        {
                            continue 'main_loop;
                        }

                        fn unescape_cbor_buf(
                            val: &mut CborValue,
                        ) -> std::result::Result<(), String> {
                            match val {
                                CborValue::Array(v) => {
                                    for i in v {
                                        unescape_cbor_buf(i)?;
                                    }
                                }
                                CborValue::Map(kvs) => {
                                    let mut byte_repr = None;
                                    let mut data = None;
                                    let mut unexpected_sibling = None;
                                    for kv in &mut *kvs {
                                        match kv {
                                            (CborValue::Text(k), CborValue::Text(v)) => {
                                                if k == "__byte_repr" {
                                                    byte_repr = Some(v);
                                                    continue;
                                                }
                                                if k == "data" {
                                                    data = Some(v);
                                                    continue;
                                                }
                                                unexpected_sibling = Some(&**k)
                                            }
                                            (CborValue::Text(k), _) => {
                                                unexpected_sibling = Some(&**k)
                                            }
                                            _ => unexpected_sibling = Some(""),
                                        }
                                    }
                                    if let (Some(_), Some(sibling)) =
                                        (&byte_repr, unexpected_sibling)
                                    {
                                        return Err(format!(
                                            "Unexpected sibling {} of __byte_repr",
                                            sibling
                                        ));
                                    }
                                    let data = match (byte_repr, data) {
                                        (Some(repr), Some(buf)) if repr == "utf8" => {
                                            std::mem::take(buf).into_bytes()
                                        }
                                        (Some(repr), Some(buf)) if repr == "base64" => {
                                            BASE64_STANDARD
                                                .decode(std::mem::take(buf).into_bytes())
                                                .map_err(|_| "Invalid base64 data")?
                                        }
                                        (Some(_), None) => return Err("Missing data field".into()),
                                        (Some(repr), _) => {
                                            return Err(format!("Unknown representation {}", repr))
                                        }
                                        (None, _) => {
                                            for (k, v) in kvs {
                                                unescape_cbor_buf(k)?;
                                                unescape_cbor_buf(v)?;
                                            }
                                            return Ok(());
                                        }
                                    };

                                    *val = CborValue::Bytes(data);
                                }
                                _ => {}
                            }
                            Ok(())
                        }

                        // Leave a newline in the buffer for correct error messages
                        match serde_json::from_slice(&input_buf[(CANCEL_SAFEWORD.len() - 1)..])
                            .map_err(|e| e.to_string().replace(&['\r', '\n'][..], ""))
                            .and_then(|mut v| unescape_cbor_buf(&mut v).map(|()| v))
                        {
                            Ok(v) => break v,
                            Err(err_str) => {
                                edit_buf.clear();
                                edit_buf
                                    .reserve(input_buf.len() + BAD_JSON_MSG.len() + err_str.len());
                                edit_buf.extend_from_slice(&input_buf);
                                edit_buf.extend_from_slice(BAD_JSON_MSG);
                                edit_buf.extend_from_slice(err_str.as_bytes());
                                continue;
                            }
                        };
                    };

                    let new_param = cbor4ii::serde::to_vec(vec![], &json_val)
                        .context("Failed to serialize Plugin param from JSON")?;

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

fn run_input_view(ctx: &mut AppContext, req: &mut InputRequest) -> Result<NavChoice> {
    use tui_input::backend::crossterm as input_backend;
    use tui_input::StateChanged;

    let mut input = tui_input::Input::default().with_value(req.initial_value.clone());
    let desc = req.desc.clone() + "\r\n\r\nPress Enter to submit, Esc to go back.";
    let mut has_error = false;
    loop {
        let size = ctx.term.size()?;
        let vchunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(2),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(size);
        let desc_chunk = vchunks[2];
        let edit_chunk = vchunks[0];
        let width = edit_chunk.width.max(3) - 3; // keep 2 for borders and 1 for cursor
        let scroll = (input.cursor() as u16).max(width) - width;

        ctx.term.draw(|f| {
            let input_widget = Paragraph::new(input.value())
                .scroll((0, scroll))
                .style(Style::default().fg(if has_error { Color::Red } else { FG }))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("Input {}", &req.item)),
                )
                .scroll((0, scroll));
            f.render_widget(input_widget, edit_chunk);
            f.set_cursor(
                // Put cursor past the end of the input text
                edit_chunk.x + (input.cursor() as u16).min(width) + 1,
                // Move one line down, from the border to the input line
                edit_chunk.y + 1,
            );
            let desc = Paragraph::new(&*desc);
            f.render_widget(desc, desc_chunk);
        })?;

        let ev = crossterm::event::read().unwrap();
        match &ev {
            Event::Key(KeyEvent {
                code: KeyCode::Esc, ..
            }) => return Ok(NavChoice::Back),
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            }) if !has_error => break,
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            }) => {}
            _ => {
                if let Some(StateChanged { value: true, .. }) =
                    input_backend::to_input_request(&ev).and_then(|req| input.handle(req))
                {
                    let len = input.value().len();
                    has_error = !(1..req.max_len).contains(&len);
                }
            }
        }
    }

    (req.action)(ctx, input.value().to_string())?;
    Ok(NavChoice::Back)
}

fn run_plugin_type_view(
    ctx: &mut AppContext,
    profile_id: ProfileId,
    plugin: &mut Option<Plugin>,
) -> Result<NavChoice> {
    use strum::{EnumMessage, IntoEnumIterator};

    let title_text = match plugin {
        Some(p) => format!("Choose a new type for Plugin {}", &p.name),
        None => "Choose a type for the new plugin".into(),
    };
    let type_names: Vec<_> = gen::defaults::PluginType::iter()
        .map(|t| ListItem::new(t.to_string()))
        .collect();
    let type_descs: Vec<_> = gen::defaults::PluginType::iter()
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
                let new_plugin = gen::defaults::PluginType::iter()
                    .nth(type_state.selected().unwrap())
                    .unwrap()
                    .gen_default();
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
                        new_plugin.desc,
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
