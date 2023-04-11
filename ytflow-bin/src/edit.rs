#![feature(let_chains)]

use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{arg, value_parser, ArgMatches};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{backend::CrosstermBackend, Terminal};

mod gen;
mod views;
use ytflow::data::{Connection, Database};

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

pub struct AppContext {
    term: Terminal<CrosstermBackend<io::Stdout>>,
    conn: Connection,
}

fn run_main_loop(ctx: &mut AppContext) -> Result<()> {
    use views::NavChoice;

    let mut nav_choices = vec![NavChoice::MainView];
    loop {
        let next_nav_choice = match nav_choices.last_mut() {
            Some(NavChoice::MainView) => views::run_main_view(ctx)?,
            Some(NavChoice::NewProfileView) => views::run_new_profile_view(ctx)?,
            Some(NavChoice::ProfileView(id)) => views::run_profile_view(ctx, *id)?,
            Some(NavChoice::PluginTypeView(profile_id, plugin)) => {
                views::run_plugin_type_view(ctx, *profile_id, plugin)?
            }
            Some(NavChoice::NewProxyGroupView) => views::run_new_proxy_group_view(ctx)?,
            Some(NavChoice::ProxyGroupView(id)) => views::run_proxy_group_view(ctx, *id)?,
            Some(NavChoice::ProxyTypeView(group_id)) => views::run_proxy_type_view(ctx, *group_id)?,
            Some(NavChoice::InputView(req)) => views::run_input_view(ctx, req)?,
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
