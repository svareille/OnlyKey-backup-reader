use tui::{text::{Span, Spans}, style::{Style, Modifier}};

use crate::ui::key_style;

pub(crate) fn help_text() -> Vec<Spans<'static>> {
    vec![
        Spans::from(vec![
            Span::raw("Press "), key_style("h"), Span::raw(" anywhere to get this help."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("q"),Span::raw(" anywhere to exit."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("Tab"),Span::raw(" anywhere to navigate between panel."),
            ]
        ),
        Spans::from(Span::raw("")),
        Spans::from(vec![
            Span::raw("Press "), key_style("s"), Span::raw(" to show or hide secrets."),
            ]
        ),
        Spans::from(Span::raw("")),
        Spans::from(Span::styled("When a profile panel is on screen:", Style::default().add_modifier(Modifier::ITALIC))),
        Spans::from(vec![
            Span::raw("Press "), key_style("l"), Span::raw(" to copy the label into the clipboard."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("U"), Span::raw(" to copy the URL into the clipboard."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("u"), Span::raw(" to copy the username into the clipboard."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("p"), Span::raw(" to copy the password into the clipboard."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("o"), Span::raw(" to copy the OTP into the clipboard."),
            ]
        ),
        Spans::from(vec![
            Span::raw("Press "), key_style("O"), Span::raw(" to copy the OTP seed into the clipboard."),
            ]
        ),
        Spans::from(Span::raw("")),
        Spans::from(Span::styled("When a key in the general panel is selected:", Style::default().add_modifier(Modifier::ITALIC))),
        Spans::from(vec![
            Span::raw("Press "), key_style("k"), Span::raw(" to copy the private key into the clipboard."),
            ]
        ),
        Spans::from(Span::raw("")),
        Spans::from(vec![
            Span::styled("Note: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("The clipboard is cleared after a few seconds."),
        ]),
        Spans::from(Span::raw("")),
        Spans::from(Span::raw("")),
        Spans::from(vec![
            Span::raw("Press "), key_style("Esc"), Span::raw(" to escape from this popup."),
        ]),
    ]
}