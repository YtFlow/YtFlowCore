use std::io;

use anyhow::{Context, Result};
use clap::{app_from_crate, arg, ArgMatches};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};

use ytflow::data::{Connection, Database, Profile, ProfileId};

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

fn main() {
    let args = get_args();
    let conn = match get_db_conn(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    run_tui(conn);
}

fn get_args() -> ArgMatches {
    app_from_crate!()
        .arg(arg!(<PATH> "Path to the database file").allow_invalid_utf8(true))
        .get_matches()
}

fn get_db_conn(args: &ArgMatches) -> Result<Connection> {
    let db_path = args.value_of_os("PATH").expect("Cannot get database path");
    let db = Database::open(db_path).context("Could not prepare database")?;
    let conn = db.connect().context("Could not connect to database")?;
    Ok(conn)
}

fn run_tui(conn: Connection) {
    enable_raw_mode().unwrap();
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).expect("Cannot create terminal");
    terminal.clear().unwrap();
    terminal.hide_cursor().unwrap();
    let mut ctx = AppContext {
        term: terminal,
        conn,
    };
    let res = run_main_loop(&mut ctx);
    let mut terminal = ctx.term;
    disable_raw_mode().unwrap();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .unwrap();
    terminal.show_cursor().unwrap();
    if let Err(e) = res {
        eprintln!("{}", e);
    }
}

struct AppContext {
    term: Terminal<CrosstermBackend<io::Stdout>>,
    conn: Connection,
}

enum NavChoice {
    MainView,
    ProfileView(ProfileId),
    Back,
}

fn run_main_loop(ctx: &mut AppContext) -> Result<()> {
    let mut nav_choices = vec![NavChoice::MainView];
    loop {
        let next_nav_choice = match nav_choices.last() {
            Some(NavChoice::MainView) => run_main_view(ctx)?,
            Some(NavChoice::ProfileView(_)) => todo!(),
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
    let profiles = Profile::query_all(&ctx.conn).context("Could not query all profiles")?;
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
    let mut focus_left = true;
    let mut category_state = ListState::default();
    category_state.select(Some(0));
    loop {
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
                    .block(Block::default().title("Profiles").borders(Borders::ALL));
                    f.render_widget(items, right_chunk);
                    f.render_widget(
                        Paragraph::new("c: Create Profile; q: Quit"),
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
        match crossterm::event::read().unwrap() {
            Event::Key(KeyEvent { code, .. }) => match code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c') if category_state.selected() == Some(0) => {
                    return Ok(NavChoice::ProfileView(0.into()));
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
                KeyCode::Right => {
                    focus_left = false;
                }
                KeyCode::Left => {
                    focus_left = true;
                }
                _ => {}
            },
            _ => {}
        };
    }
    Ok(NavChoice::Back)
}
