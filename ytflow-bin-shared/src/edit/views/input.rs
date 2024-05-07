use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use tui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph},
};

use super::{InputRequest, NavChoice, FG};
use crate::edit;

pub fn run_input_view(ctx: &mut edit::AppContext, req: &mut InputRequest) -> Result<NavChoice> {
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
                code: KeyCode::Esc,
                kind: KeyEventKind::Press,
                ..
            }) => return Ok(NavChoice::Back),
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                kind: KeyEventKind::Press,
                ..
            }) if !has_error => break,
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                kind: KeyEventKind::Press,
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
