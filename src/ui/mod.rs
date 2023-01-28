use std::time::Duration;

use log::{error};
use tui::{backend::Backend, Frame, layout::{Layout, Direction, Constraint, Alignment, Rect}, widgets::{Block, Borders, BorderType, Paragraph, canvas::{Line, Shape}, Clear, List, ListItem, Tabs, Wrap, Widget, Gauge}, style::{Style, Color, Modifier}, text::{Spans, Span}};

use crate::{App, Panel};

mod onlykey;
use crate::res;

use onlykey::{OnlyKeyWidget, AccountDataWidget};

use self::onlykey::{GeneralSelectionWidget, EccDataWidget, split_string_in_chunks, RsaDataWidget, HmacDataWidget, DerivationKeyDataWidget};
use crate::SelectedGeneral;

pub fn key_style(text: &str) -> Span {
    Span::styled(text, Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
}

pub(crate) fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let size = f.size();

    // Vertical main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
            ].as_ref())
        .split(size);

    let block = Block::default().style(Style::default().bg(Color::Black).fg(Color::White));
    f.render_widget(block, size);

    // Title
    let title = make_title();
    f.render_widget(title, chunks[0]);

    let upper_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(11),
            ].as_ref())
        .split(chunks[1]);

    // Profile tab
    let titles = ["Profile 1", "Profile 2", "General"].iter().cloned().map(Spans::from).collect();
    let tabs = Tabs::new(titles)
        .block(Block::default()
                .borders(Borders::ALL)
                .title("Profile")
                .border_type(if matches!(app.current_panel, Panel::ProfileTab) {BorderType::Double} else {BorderType::Plain})
                .border_style(Style::default().fg(if matches!(app.current_panel, Panel::ProfileTab) {Color::Cyan} else {Color::White}))
            )
        .select(app.current_profile)
        .style(Style::default().fg(Color::Cyan))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
        );
    f.render_widget(tabs, upper_chunks[0]);

    let help = Paragraph::new(Spans::from(vec![
        Span::raw("Press "),
        Span::styled("h", Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED))
        ]))
        .block(Block::default()
            .title("Help")
            .borders(Borders::ALL)
            .border_type(if matches!(app.current_panel, Panel::HelpButton) {BorderType::Double} else {BorderType::Plain})
            .border_style(Style::default().fg(if matches!(app.current_panel, Panel::HelpButton) {Color::Cyan} else {Color::White}))
        )
        .style(Style::default())
        .alignment(Alignment::Center);
    
    f.render_widget(help, upper_chunks[1]);

    match app.current_profile {
        0 | 1 => {
            make_onlykey_profile_view(app, chunks[2], f);
        }
        2 => {
            make_onlykey_general_view(app, chunks[2], f);
        }
        _ => {

        }

    }

    let status_bar = StatusBar::new(&app.clipboard_status_text, app.clipboard_remaining.unwrap_or(Duration::ZERO), app.clipboard_total)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .border_type(if matches!(app.current_panel, Panel::StatusBar) {BorderType::Double} else {BorderType::Plain})
                .border_style(Style::default().fg(if matches!(app.current_panel, Panel::StatusBar) {Color::Cyan} else {Color::White}))
    );
    f.render_widget(status_bar, chunks[3]);
    
    if matches!(app.current_panel, Panel::SelectDecrKeyType) {
        make_select_key_type_popup(app, size, f);
    }
    else if matches!(app.current_panel, Panel::EnterDecrPass) {
        make_enter_passphrase_popup(app, size, f);
    }
    else if matches!(app.current_panel, Panel::EnterECCKey(_)) {
        make_enter_ecc_popup(app, size, f);
    }
    else if matches!(app.current_panel, Panel::EnterRsaKey) {
        make_enter_rsa_popup(app, size, f);
    }
    else if matches!(app.current_panel, Panel::SelectDecrEccKeyType) {
        make_select_ecc_key_type_popup(app, size, f);
    }
    else if matches!(app.current_panel, Panel::HelpPopup) {
        make_help_popup(size, f);
    }

    if let Some(text) = app.get_error() {
        make_error_dialog(text, size, f);
    }
}

fn make_title<'a>() -> Paragraph<'a> {
    Paragraph::new("OnlyKey backup reader TUI")
        .style(Style::default().fg(Color::LightCyan))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .border_type(BorderType::Plain),
        )
}

fn make_onlykey_profile_view<B: Backend>(app: &App, chunk: Rect, f: &mut Frame<B>) {
    // Horizontal key data layout
    let key_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([
            Constraint::Length(67),
            Constraint::Min(40),
            ].as_ref())
        .split(chunk);
    // OnlyKey
    let profile = match & app.onlykey {
        Some(ok) => match app.current_profile {
            0 => Some(& ok.profile1),
            1 => Some(& ok.profile2),
            _ => {
                error!("Nonexistent profile! This shouldn't have happened!");
                return;
            },
        }
        None => None,
    };

    let mut labels: [(String, String); 6] = [(String::new(), String::new()), (String::new(), String::new()), (String::new(), String::new()), (String::new(), String::new()), (String::new(), String::new()), (String::new(), String::new())];

    if let Some(profile) = profile {
        for (i, label) in labels.iter_mut().enumerate() {
            *label = {
                let label_a = if let Ok(account) = profile.get_account_by_name(&format!("{}a", i+1)) {
                    account.label.clone()
                }
                else {
                    String::new()
                };
                let label_b = if let Ok(account) = profile.get_account_by_name(&format!("{}b", i+1)) {
                    account.label.clone()
                }
                else {
                    String::new()
                };
                (label_a, label_b)
            }
        }
    }

    let ok_widget = OnlyKeyWidget::new(labels)
        .block(
            Block::default()
                .title("OnlyKey")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .border_type(if matches!(app.current_panel, Panel::Onlykey) {BorderType::Double} else {BorderType::Plain})
                .border_style(Style::default().fg(if matches!(app.current_panel, Panel::Onlykey) {Color::Cyan} else {Color::White}))
        )
        .select(app.current_account);
    f.render_widget(ok_widget, key_chunks[0]);

    let account = match profile {
        Some(profile) => {
            let account_name = app.get_current_account_name();
            match profile.get_account_by_name(&account_name) {
                Ok(account) => Some(account),
                Err(e) => {
                    error!("Error while getting account {} on profile {}: {}", account_name, app.current_profile, e);
                    return;
                },
            }
        },
        None => None,
    };
    let data_widget = AccountDataWidget::new(account, app.show_secrets)
        .block(
            Block::default()
                .title(format!("Account {}", app.get_current_account_name()))
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .border_type(if matches!(app.current_panel, Panel::DataDisplay) {BorderType::Double} else {BorderType::Plain})
                .border_style(Style::default().fg(if matches!(app.current_panel, Panel::DataDisplay) {Color::Cyan} else {Color::White}))
        );
    f.render_widget(data_widget, key_chunks[1]);
}

fn make_onlykey_general_view<B: Backend>(app: &App, chunk: Rect, f: &mut Frame<B>) {
    // Horizontal layout
    let hchunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(0)
        .constraints([
            Constraint::Length(66),
            Constraint::Min(40),
            ].as_ref())
        .split(chunk);
    
    let mut ecc_labels: [Option<String>; 16] = Default::default();

    let mut rsa_labels: [Option<String>; 4] = Default::default();

    let mut hmac_present= [false; 2];

    if let Some(ok) = &app.onlykey {
        for i in 1..=4 {
            rsa_labels[i-1] = match ok.get_rsa_key(i) {
                Ok(key) => key.map(|key| key.label.to_string()),
                Err(e) => {
                    error!("Error while getting RSA key {}: {}", i, e);
                    return;
                }
            };
        }
        for i in 1..=16 {
            ecc_labels[i-1] = match ok.get_ecc_key(i) {
                Ok(key) => key.map(|key| key.label.to_string()),
                Err(e) => {
                    error!("Error while getting ECC key {}: {}", i, e);
                    return;
                }
            }
        }
        hmac_present = ok.hmac_keys.iter().map(|h| h.is_some()).collect::<Vec<bool>>().try_into().unwrap();
    }

    let general_widget = GeneralSelectionWidget::new(rsa_labels, ecc_labels, hmac_present)
        .block(
            Block::default()
                .title("General")
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .border_type(if matches!(app.current_panel, Panel::General) {BorderType::Double} else {BorderType::Plain})
                .border_style(Style::default().fg(if matches!(app.current_panel, Panel::General) {Color::Cyan} else {Color::White}))
        )
        .select(app.current_general);
    f.render_widget(general_widget, hchunks[0]);

    match app.current_general {
        SelectedGeneral::None => {},
        SelectedGeneral::Ecc(i) => {
            if let Some(ok) = &app.onlykey {
                match ok.get_ecc_key(i.into()) {
                    Ok(key) => {
                        let data_widget = EccDataWidget::new(key.cloned(), app.show_secrets)
                            .block(
                                Block::default()
                                    .title(format!("ECC key {}", i))
                                    .borders(Borders::ALL)
                                    .style(Style::default().fg(Color::White))
                                    .border_type(if matches!(app.current_panel, Panel::DataDisplay) {BorderType::Double} else {BorderType::Plain})
                                    .border_style(Style::default().fg(if matches!(app.current_panel, Panel::DataDisplay) {Color::Cyan} else {Color::White}))
                            );
                        f.render_widget(data_widget, hchunks[1]);
                    }
                    Err(e) => {
                        error!("Error while getting ECC key {}: {}", 1, e);
                    }
                }
            };
        },
        SelectedGeneral::Rsa(i) => {
            if let Some(ok) = &app.onlykey {
                match ok.get_rsa_key(i.into()) {
                    Ok(key) => {
                        let data_widget = RsaDataWidget::new(key.cloned(), app.show_secrets)
                            .block(
                                Block::default()
                                    .title(format!("RSA key {}", i))
                                    .borders(Borders::ALL)
                                    .style(Style::default().fg(Color::White))
                                    .border_type(if matches!(app.current_panel, Panel::DataDisplay) {BorderType::Double} else {BorderType::Plain})
                                    .border_style(Style::default().fg(if matches!(app.current_panel, Panel::DataDisplay) {Color::Cyan} else {Color::White}))
                            );
                        f.render_widget(data_widget, hchunks[1]);
                    }
                    Err(e) => {
                        error!("Error while getting RSA key {}: {}", 1, e);
                    }
                }
            };
        }
        SelectedGeneral::Hmac(i) => {
            if let Some(ok) = &app.onlykey {
                let data_widget = HmacDataWidget::new(ok.hmac_keys[(i-1) as usize].clone(), app.show_secrets)
                    .block(
                        Block::default()
                            .title(format!("Hmac key {}", i))
                            .borders(Borders::ALL)
                            .style(Style::default().fg(Color::White))
                            .border_type(if matches!(app.current_panel, Panel::DataDisplay) {BorderType::Double} else {BorderType::Plain})
                            .border_style(Style::default().fg(if matches!(app.current_panel, Panel::DataDisplay) {Color::Cyan} else {Color::White}))
                    );
                f.render_widget(data_widget, hchunks[1]);
            };
        }
        SelectedGeneral::DerivationKey => {
            if let Some(ok) = &app.onlykey {
                let data_widget = DerivationKeyDataWidget::new(ok.derivation_key.clone(), app.show_secrets)
                    .block(
                        Block::default()
                            .title("Derivation key")
                            .borders(Borders::ALL)
                            .style(Style::default().fg(Color::White))
                            .border_type(if matches!(app.current_panel, Panel::DataDisplay) {BorderType::Double} else {BorderType::Plain})
                            .border_style(Style::default().fg(if matches!(app.current_panel, Panel::DataDisplay) {Color::Cyan} else {Color::White}))
                    );
                f.render_widget(data_widget, hchunks[1]);
            };
        }
    }

}

fn make_select_key_type_popup<B: Backend>(app: &mut App, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);

    let items: Vec<ListItem> = app
        .decr_key_items
        .items
        .iter()
        .map(|s| {
            let lines = vec![Spans::from(*s)];
            ListItem::new(lines).style(Style::default())
        })
        .collect();
    
    let area = centered_rect(20, 2+items.len() as u16, size);
    f.render_widget(Clear, area); //this clears out the background

    
    let list = List::new(items)
        .block(Block::default().title("Select key type").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
        .highlight_symbol(">>");
    f.render_stateful_widget(list, area, &mut app.decr_key_items.state);
}

fn make_enter_passphrase_popup<B: Backend>(app: &App, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);
    let area = centered_rect(app.input.max_len as u16 + 2, 3, size);
    f.render_widget(Clear, area); //this clears out the background

    let input = Paragraph::new(app.input.value.as_ref())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Enter Passphrase"));
    f.render_widget(input, area);
    f.set_cursor(
        // Put cursor past the end of the input text
        area.x + app.input.cursor as u16 + 1,
        // Move one line down, from the border to the input line
        area.y + 1,
    );
}

fn make_enter_ecc_popup<B: Backend>(app: &App, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);
    let area = centered_rect(app.input.max_len as u16 + 2, 3, size);
    f.render_widget(Clear, area); //this clears out the background

    let input = Paragraph::new(app.input.value.as_ref())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Enter ECC hex key"));
    f.render_widget(input, area);
    f.set_cursor(
        // Put cursor past the end of the input text
        area.x + app.input.cursor as u16 + 1,
        // Move one line down, from the border to the input line
        area.y + 1,
    );
}

fn make_enter_rsa_popup<B: Backend>(app: &App, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);
    let width = size.width.min(app.input.max_len as u16 + 2);
    let height = (app.input.max_len as f32 / (width-2) as f32).ceil() as u16 + 2;
    let area = centered_rect(width, height, size);
    f.render_widget(Clear, area); //this clears out the background

    let (cursor_x, cursor_y) = {
        let x = area.x + 1 + (app.input.cursor as u16 % (width-2));
        let y = area.y + 1 + (app.input.cursor as u16 / (width-2));
        (x,y)
    };

     let (text, _) = split_string_in_chunks(&app.input.value, (width-2).into());

    let input = Paragraph::new(text)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Enter RSA hex key, as the p and q parameters concatenated"));
    f.render_widget(input, area);
    f.set_cursor(
        // Put cursor past the end of the input text
        cursor_x,
        // Move one line down, from the border to the input line
        cursor_y,
    );
}

fn make_select_ecc_key_type_popup<B: Backend>(app: &mut App, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);

    let items: Vec<ListItem> = app
        .decr_ecc_key_items
        .items
        .iter()
        .map(|s| {
            let lines = vec![Spans::from(*s)];
            ListItem::new(lines).style(Style::default())
        })
        .collect();

    let area = centered_rect(25, 2+items.len() as u16, size);
    f.render_widget(Clear, area); //this clears out the background
    
    let list = List::new(items)
        .block(Block::default().title("Select ECC key type").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED))
        .highlight_symbol(">>");
    f.render_stateful_widget(list, area, &mut app.decr_ecc_key_items.state);
}

fn make_help_popup<B: Backend>(size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);
    let area = centered_rect_percent(50, 75, size);
    f.render_widget(Clear, area); //this clears out the backgrounds


    let help = Paragraph::new(res::text::help_text())
        .block(Block::default()
            .title("Help")
            .borders(Borders::ALL)
        )
        .style(Style::default())
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: false });
    
    f.render_widget(help, area);
}

fn make_error_dialog<B: Backend>(text: &str, size: Rect, f: &mut Frame<B>) {
    let block = Block::default().style(Style::default().add_modifier(Modifier::DIM));
    f.render_widget(block, size);
    let area = centered_rect_percent(50, 75, size);
    f.render_widget(Clear, area); //this clears out the backgrounds

    let vchunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(3),
            ].as_ref())
        .split(area);

    let border = Block::default()
        .title("Error:")
        .borders(Borders::ALL);
    f.render_widget(border, area);

    let dialog = Paragraph::new(text)
        .style(Style::default())
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });
    
    f.render_widget(dialog, vchunks[0]);

    let button = Paragraph::new("Ok")
        .block(Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White))
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Cyan))
        )
        .style(Style::default())
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });
    
        let mut button_area = vchunks[1];
        button_area.x += (button_area.width - 6)/2;
        button_area.width = 6;
    f.render_widget(button, button_area);
}

struct PolyLine {
    pub points: Vec<(f64, f64)>,
    pub color: Color,
}

impl Shape for PolyLine {
    fn draw(&self, painter: &mut tui::widgets::canvas::Painter) {
        let (mut prev_x, mut prev_y) = self.points[0];
        for &(x, y) in &self.points {
            //println!("{} {} {} {}", prev_x, prev_y, x, y);
            Line { x1: prev_x, y1: prev_y, x2: x, y2: y, color: self.color }.draw(painter);
            prev_x = x;
            prev_y = y;
        }
    }
}

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length((r.height-height)/2),
                Constraint::Length(height),
                Constraint::Min((r.height-height)/2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length((r.width-width)/2),
                Constraint::Length(width),
                Constraint::Min((r.width-width)/2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

fn centered_rect_percent(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

pub struct StatusBar<'a> {
    /// A block to wrap the widget in
    block: Option<Block<'a>>,
    clipboard_text: String,
    clipboard_remaining: Duration,
    clipboard_total: Duration,
}

impl<'a> StatusBar<'a> {
    pub fn new(clipboard_text: &str, clipboard_remaining: Duration, clipboard_total: Duration) -> StatusBar<'a>
    {
        StatusBar {
            block: None,
            clipboard_text: clipboard_text.to_owned(),
            clipboard_remaining,
            clipboard_total,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> StatusBar<'a> {
        self.block = Some(block);
        self
    }
}

impl<'a> Widget for StatusBar<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.height < 1 {
            //buf.set_string(text_area.left(), text_area.top(), "Not enough space. Please widen the terminal.", Style::default());
            return;
        }
        
        if !self.clipboard_text.is_empty() {
            let text_len = self.clipboard_text.len();
            buf.set_string(text_area.left(), text_area.top(), self.clipboard_text, Style::default());

            let gauge_area = Rect{ x: text_area.x + text_len as u16 + 1, y: text_area.y, width: (text_area.width - 1 - text_len as u16).min(self.clipboard_total.as_secs() as u16), height: 1 };

            let clipboard_gauge = Gauge::default()
                .gauge_style(Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD))
                .label(format!("{} sec", self.clipboard_remaining.as_secs()))
                .ratio(self.clipboard_remaining.as_secs_f64() / self.clipboard_total.as_secs_f64());
            clipboard_gauge.render(gauge_area, buf);
        }
        else {
            let key_style = Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
            let text = vec![
                Spans::from(vec![
                    Span::raw("Press "),Span::styled("q", key_style),Span::raw(" anywhere to exit. Press "),Span::styled("Tab", key_style),Span::raw(" anywhere to navigate between panels.")
                ]),
                Spans::from(Span::styled("Second line", Style::default().fg(Color::Red))),
            ];
            Paragraph::new(text)
                .style(Style::default())
                .alignment(Alignment::Left)
                .render(text_area, buf);
        }
    }
}