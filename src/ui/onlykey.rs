use chrono::{DateTime, Utc, Timelike};
use data_encoding::HEXUPPER;
use ok_backup::{AccountSlot, OTP, ECCKeySlot, KeyFeature};
use tui::{widgets::{Block, Widget, Table, Cell, Row, Gauge, Paragraph, Borders}, style::{Style, Color, Modifier}, layout::{Rect, Constraint, Alignment}};

use crate::SelectedGeneral;


pub(crate) struct OnlyKeyWidgetBase<'a> {
    /// A block to wrap the widget in
    pub block: Option<Block<'a>>,
}

impl<'a> OnlyKeyWidgetBase<'a> {
    pub fn new() -> OnlyKeyWidgetBase<'a>
    {
        OnlyKeyWidgetBase {
            block: None
        }
            
    }

    pub fn _block(mut self, block: Block<'a>) -> OnlyKeyWidgetBase<'a> {
        self.block = Some(block);
        self
    }
}

// ┌ ┐ └ ┘ ─ │ ├ ┤ ┬ ┴ ┼
// ╔ ╗ ╚ ╝ ═ ║ ╠ ╣ ╦ ╩ ╬
// ╭ ╮ ╯ ╰ ╱ ╲ ╳
// ⓵ ⓶ ⓷ ⓸ ⓹ ⓺
// █ ▌▐ ▄
// ◯ ◎ ◉

/*
    ┌─────────┐
    │ █▌▄ ▄▐█ │ 
    │ █▌█ █▐█ │
    │ █▌█ █▐█ │
┌───┘         └───┐
│ ╭───╮     ╔═══╗ │
│ │ 1 │     ║ 2 ║ │
│ ╰───╯     ╚═══╝ │
│     ONLYKEY     │
│ ╭───╮     ╔═══╗ │
│ │ 3 │     ║ 4 ║ │
│ ╰───╯     ╚═══╝ │
│      crp.to     │
│ ╭───╮     ╔═══╗ │
│ │ 5 │     ║ 6 ║ │
│ ╰───╯     ╚═══╝ │
└──────╮ O ╭──────┘
       ╰───╯
*/

impl<'a> Widget for OnlyKeyWidgetBase<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.height < 18 || text_area.width < 17 {
            return
        }

        let border_style = Style::default().fg(Color::White);
        let pin_style = Style::default().fg(Color::Yellow);

        // Borders
        buf.set_string(text_area.left()+3, text_area.top(),      "┌─────────┐", border_style);
        buf.set_string(text_area.left()+3, text_area.top()+1,    "│         │", border_style);
        buf.set_string(text_area.left()+3, text_area.top()+2,    "│         │", border_style);
        buf.set_string(text_area.left()+3, text_area.top()+3,    "│         │", border_style);
        buf.set_string(text_area.left(), text_area.top()+4,   "┌──┘         └──┐", border_style);
        buf.set_string(text_area.left(), text_area.top()+5,   "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+6,   "│   1       2   │", border_style);
        buf.set_string(text_area.left(), text_area.top()+7,   "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+8,   "│    ONLYKEY    │", border_style);
        buf.set_string(text_area.left(), text_area.top()+9,   "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+10,  "│   3       4   │", border_style);
        buf.set_string(text_area.left(), text_area.top()+11,  "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+12,  "│    crp.to     │", border_style);
        buf.set_string(text_area.left(), text_area.top()+13,  "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+14,  "│   5       6   │", border_style);
        buf.set_string(text_area.left(), text_area.top()+15,  "│               │", border_style);
        buf.set_string(text_area.left(), text_area.top()+16,  "└─────╮ O ╭─────┘", border_style);
        buf.set_string(text_area.left(), text_area.top()+17,  "      ╰───╯", border_style);

        // USB pins
        buf.set_string(text_area.left()+4, text_area.top()+1,  " █▌▄ ▄▐█ ", pin_style);
        buf.set_string(text_area.left()+4, text_area.top()+2,  " █▌█ █▐█ ", pin_style);
        buf.set_string(text_area.left()+4, text_area.top()+3,  " █▌█ █▐█ ", pin_style);

        // Buttons borders
        for i in [5, 9, 13] {
            buf.set_string(text_area.left()+2, text_area.top()+i,    "╭───╮   ╭───╮", pin_style);
            buf.set_string(text_area.left()+2, text_area.top()+i+1,  "│   │   │   │", pin_style);
            buf.set_string(text_area.left()+2, text_area.top()+i+2,  "╰───╯   ╰───╯", pin_style);
        }

        // Buttons numbers
        buf.set_string(text_area.left()+4, text_area.top()+6,   "1", border_style);
        buf.set_string(text_area.left()+12, text_area.top()+6,   "2", border_style);
        buf.set_string(text_area.left()+4, text_area.top()+10,   "3", border_style);
        buf.set_string(text_area.left()+12, text_area.top()+10,   "4", border_style);
        buf.set_string(text_area.left()+4, text_area.top()+14,   "5", border_style);
        buf.set_string(text_area.left()+12, text_area.top()+14,   "6", border_style);
        
    }
}

pub(crate) struct OnlyKeyWidget<'a> {
    /// A block to wrap the widget in
    block: Option<Block<'a>>,
    ok_base: OnlyKeyWidgetBase<'a>,

    /// Labels of the accounts, as (label slot a, label slot b)
    labels: [(String, String); 6],
    /// Account selected
    selected: usize,
}

impl<'a> OnlyKeyWidget<'a> {
    pub fn new(labels: [(String, String); 6]) -> OnlyKeyWidget<'a>
    {
        OnlyKeyWidget {
            block: None,
            ok_base: OnlyKeyWidgetBase::new(),
            labels,
            selected: 0,
        }
            
    }

    pub fn block(mut self, block: Block<'a>) -> OnlyKeyWidget<'a> {
        self.block = Some(block);
        self
    }

    pub fn select(mut self, selected: usize) -> OnlyKeyWidget<'a> {
        self.selected = selected;
        self
    }
}

impl<'a> Widget for OnlyKeyWidget<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.height < 18 || text_area.width < 65 {
            buf.set_string(text_area.left(), text_area.top(), "Not enough space. Please widen the terminal.", Style::default());
            return
        }

        let label_width = 16+1+4+3;

        let ok_area = Rect { x: text_area.x+label_width, y: text_area.y, width: text_area.width-label_width, height: text_area.height };

        self.ok_base.render(ok_area, buf);

        //let border_style = Style::default();
        //let pin_style = Style::default().fg(Color::Yellow);
        let button_style = Style::default().fg(Color::Blue);
        let label_style = Style::default().add_modifier(Modifier::UNDERLINED);
        let selected_style = button_style.add_modifier(Modifier::REVERSED);

        // Buttons
        for (i, j, (a, b)) in [(3, 1, (0, 2)), (8, 3, (4, 6)), (13, 5, (8, 10))] {
            
            buf.set_string(text_area.left()+17, text_area.top()+i,      "┌──┐", button_style);
            buf.set_string(text_area.left()+17, text_area.top()+i+1,    "│  │", button_style);
            buf.set_string(text_area.left()+17, text_area.top()+i+2,    "╞══╡", button_style);
            buf.set_string(text_area.left()+17, text_area.top()+i+3,    "│  │", button_style);
            buf.set_string(text_area.left()+17, text_area.top()+i+4,    "└──┘", button_style);

            buf.set_string(text_area.left()+18, text_area.top()+i+1,    format!("{}a", j), if self.selected == a {selected_style} else {button_style});
            buf.set_string(text_area.left()+18, text_area.top()+i+3,    format!("{}b", j), if self.selected == b {selected_style} else {button_style});
        }
        for (i, j, (a, b)) in [(3, 2, (1, 3)), (8, 4, (5, 7)), (13, 6, (9, 11))] {
            buf.set_string(text_area.left()+44, text_area.top()+i,      "┌──┐", button_style);
            buf.set_string(text_area.left()+44, text_area.top()+i+1,    "│  │", button_style);
            buf.set_string(text_area.left()+44, text_area.top()+i+2,    "╞══╡", button_style);
            buf.set_string(text_area.left()+44, text_area.top()+i+3,    "│  │", button_style);
            buf.set_string(text_area.left()+44, text_area.top()+i+4,    "└──┘", button_style);

            buf.set_string(text_area.left()+45, text_area.top()+i+1,    format!("{}a", j), if self.selected == a {selected_style} else {button_style});
            buf.set_string(text_area.left()+45, text_area.top()+i+3,    format!("{}b", j), if self.selected == b {selected_style} else {button_style});
        }

        // Labels
        for (i,pos) in [(0, 4), (2, 9), (4, 14)] {
            let label_a = self.labels[i].0.clone();
            buf.set_string(text_area.left() + 16 - label_a.len() as u16, text_area.top()+pos, label_a, label_style);
            let label_b = self.labels[i].1.clone();
            buf.set_string(text_area.left() + 16 - label_b.len() as u16, text_area.top()+pos+2, label_b, label_style);
        }
        for (i,pos) in [(1, 4), (3, 9), (5, 14)] {
            let label_a = self.labels[i].0.clone();
            buf.set_string(text_area.left() + 49, text_area.top()+pos, label_a, label_style);
            let label_b = self.labels[i].1.clone();
            buf.set_string(text_area.left() + 49, text_area.top()+pos+2, label_b, label_style);
        }

    }
}

pub struct AccountDataWidget<'a> {
    /// A block to wrap the widget in
    block: Option<Block<'a>>,
    account: Option<AccountSlot>,
    show_secrets: bool,
}

impl<'a> AccountDataWidget<'a> {
    pub fn new(account: Option<AccountSlot>, show_secrets: bool) -> AccountDataWidget<'a>
    {
        AccountDataWidget {
            block: None,
            account,
            show_secrets,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> AccountDataWidget<'a> {
        self.block = Some(block);
        self
    }
}

impl<'a> Widget for AccountDataWidget<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.width < 26 {
            buf.set_string(text_area.left(), text_area.top(), "Not enough space. Please widen the terminal.", Style::default());
            return
        }

        let field_name_style = Style::default().fg(Color::Yellow);

        let max_value_width = text_area.width-10;
        let constraints = [Constraint::Length(9), Constraint::Length(max_value_width)];
        let mut to_otp_height = 0;

        let url_row = {
            let mut height: u16 = 1;
            let row = Row::new(vec![
                Cell::from("URL:").style(field_name_style),
                Cell::from(match &self.account {
                    Some(account) => {
                        let res = split_string_in_chunks(&account.url, max_value_width.into());
                        height = res.1 as u16;
                        res.0
                    },
                    None => String::new(),
                })
                ]
            );
            to_otp_height += height;
            row.height(height)
        };

        let username_row = {
            let mut height: u16 = 1;
            let row = Row::new(vec![
                Cell::from("Username:").style(field_name_style),
                Cell::from(match &self.account {
                    Some(account) => {
                        let res = split_string_in_chunks(&account.username, max_value_width.into());
                        height = res.1 as u16;
                        res.0
                    },
                    None => String::new(),
                })
                ]
            );
            to_otp_height += height;
            row.height(height)
        };

        let password_row = {
            let mut height: u16 = 1;
            let row = Row::new(vec![
                Cell::from("Password:").style(field_name_style),
                Cell::from(match &self.account {
                    Some(account) => {
                        if self.show_secrets {
                            let res = split_string_in_chunks(&account.password, max_value_width.into());
                            height = res.1 as u16;
                            res.0
                        } else if account.password.is_empty(){
                            String::new()
                        } else {
                            "****".to_owned()
                        }
                    },
                    None => String::new(),
                })
                ]
            );
            to_otp_height += height;
            row.height(height)
        };

        let otp_seed_row = {
            let mut height: u16 = 1;
            let row = Row::new(vec![
                Cell::from("OTP seed:").style(field_name_style),
                Cell::from(match &self.account {
                    Some(account) => match &account.otp {
                        OTP::None => String::new(),
                        OTP::TOTP(seed)=> {
                            if self.show_secrets {
                                let res = split_string_in_chunks(seed, max_value_width.into());
                                height = res.1 as u16;
                                res.0
                            } else {
                                "****".to_owned()
                            }
                        }
                    },
                    None => String::new(),
                })
                ]
            );
            to_otp_height += height;
            row.height(height)
        };



        let table = Table::new(vec![
            Row::new(vec![Cell::from("Label:").style(field_name_style), Cell::from(match &self.account {
                Some(account) => &account.label,
                None => "",
            })]),
            url_row,
            username_row,
            password_row,
            otp_seed_row,
            Row::new(vec![Cell::from("OTP:").style(field_name_style), Cell::from(match &self.account {
                Some(account) => if self.show_secrets { account.otp.compute() } else { "****".to_owned()},
                None => String::new(),
            })]).height(2),
            ])
            .style(Style::default())
            .header(
                Row::new(vec!["Field", "Value"])
                    .style(Style::default().fg(Color::Blue).add_modifier(Modifier::ITALIC))
            )
            .widths(&constraints)
            //.block(Block::default().borders(Borders::ALL))
            .column_spacing(1);
        table.render(text_area, buf);

        to_otp_height += 3;

        let gauge_area = Rect{ x: text_area.x, y: text_area.y + to_otp_height, width: text_area.width, height: 1 };

        let mut rem_secs = 0;
        let total_secs = 30.0;

        if let Some(account) =  self.account {
            match account.otp {
                OTP::None => {},
                OTP::TOTP(_) => {
                    let now: DateTime<Utc> = Utc::now();
                    rem_secs = 29 - (now.second() % 30) as u16;
                },
            }
        }

        let otp_gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD))
            .label(format!("{} sec", rem_secs))
            .ratio(rem_secs as f64/ total_secs);
        otp_gauge.render(gauge_area, buf);
    }
}

fn split_string_in_chunks(instr: &str, chunk_size: usize) -> (String, usize) {
    let mut height = 1;
    if instr.len() > chunk_size {
        height = instr.len() / chunk_size as usize + 1;
        (instr.chars()
            .collect::<Vec<char>>()
            .chunks(chunk_size)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n"), height)
    } else {
        (instr.to_string(), height)
    }
}

pub(crate) struct GeneralSelectionWidget<'a> {
    /// A block to wrap the widget in
    block: Option<Block<'a>>,

    /// Labels of the ECC slots
    ecc_labels: [String; 16],
    /// Item selected
    selected: SelectedGeneral,
}

impl<'a> GeneralSelectionWidget<'a> {
    pub fn new(ecc_labels: [String; 16]) -> GeneralSelectionWidget<'a>
    {
        GeneralSelectionWidget {
            block: None,
            ecc_labels,
            selected: SelectedGeneral::None,
        }
            
    }

    pub fn block(mut self, block: Block<'a>) -> GeneralSelectionWidget<'a> {
        self.block = Some(block);
        self
    }

    pub fn select(mut self, selected: SelectedGeneral) -> GeneralSelectionWidget<'a> {
        self.selected = selected;
        self
    }
}

impl<'a> Widget for GeneralSelectionWidget<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.height < 18 || text_area.width < 50 {
            buf.set_string(text_area.left(), text_area.top(), "Not enough space. Please widen the terminal.", Style::default());
            return;
        }

        let ecc_label_width = text_area.width/4;

        /*let mut y = 0;
        let mut x = 0;

        for slot_nb in 1..=16 {
            if !self.ecc_labels[slot_nb as usize - 1].is_empty() {
                let ecc_label = Paragraph::new(self.ecc_labels[slot_nb as usize - 1].clone())
                    .block(Block::default()
                        .title(format!("ECC {}", slot_nb))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if self.selected == SelectedGeneral::Ecc(slot_nb){Color::LightRed} else {Color::White}))
                    )
                    .style(Style::default())
                    .alignment(Alignment::Left);
                ecc_label.render(Rect { x: text_area.x+x*ecc_label_width, y: text_area.y+y*3, width: ecc_label_width, height: 3 }, buf);
                x += 1;
                if x == 4 {
                    x = 0;
                    y += 1;
                }
            }
        }*/

        for y in 0..4 {
            for x in 0..4 {
                let slot_nb = x + y*4 + 1;
                let ecc_label = Paragraph::new(self.ecc_labels[slot_nb as usize - 1].clone())
                    .block(Block::default()
                        .title(format!("ECC {}", slot_nb))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if self.selected == SelectedGeneral::Ecc(slot_nb){Color::LightRed} else {Color::White}))
                    )
                    .style(Style::default())
                    .alignment(Alignment::Left);
                ecc_label.render(Rect { x: text_area.x+x*ecc_label_width, y: text_area.y+y*3, width: ecc_label_width, height: 3 }, buf);
            }
        }
    }
}

pub struct EccDataWidget<'a> {
    /// A block to wrap the widget in
    block: Option<Block<'a>>,
    key: Option<ECCKeySlot>,
    show_secrets: bool,
}

impl<'a> EccDataWidget<'a> {
    pub fn new(key: Option<ECCKeySlot>, show_secrets: bool) -> EccDataWidget<'a>
    {
        EccDataWidget {
            block: None,
            key,
            show_secrets,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> EccDataWidget<'a> {
        self.block = Some(block);
        self
    }
}

impl<'a> Widget for EccDataWidget<'a> {
    fn render(mut self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let text_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        if text_area.width < 26 {
            buf.set_string(text_area.left(), text_area.top(), "Not enough space. Please widen the terminal.", Style::default());
            return
        }

        let field_name_style = Style::default().fg(Color::Yellow);
        let max_value_width = text_area.width-13;
        let constraints = [Constraint::Length(12), Constraint::Length(max_value_width)];

        let private_key_row = {
            let mut height: u16 = 1;
            let row = Row::new(vec![
                Cell::from("Private Key:").style(field_name_style),
                Cell::from(match &self.key {
                    Some(key) => {
                        if self.show_secrets {
                            let res = split_string_in_chunks(&HEXUPPER.encode(&key.private_key.to_bytes()), max_value_width.into());
                            height = res.1 as u16;
                            res.0
                        } else {"****".to_owned()}
                    },
                    None => String::new(),
                })
                ]
            );
            row.height(height)
        };

        let mut key_label = String::new();
        let mut key_type = "";
        let mut key_usage = String::new();

        match self.key {
            Some(key) => {
                key_label = key.label;
                key_type = match key.r#type {
                    ok_backup::ECCKeyType::X25519 => "X25519",
                    ok_backup::ECCKeyType::NIST256P1 => "NIST256P1",
                    ok_backup::ECCKeyType::SECP256K1 => "SECP256K1",
                };
                key_usage = {
                    let mut usage = vec![];
                    if key.feature.contains(KeyFeature::DECRYPTION) {usage.push("Decryption");}
                    if key.feature.contains(KeyFeature::SIGNATURE) {usage.push("Signature");}
                    if key.feature.contains(KeyFeature::BACKUP) {usage.push("Backup");}
                    usage.join(" & ")
                };
            }
            None => {},
        }

        let table = Table::new(vec![
            Row::new(vec![Cell::from("Label:").style(field_name_style), Cell::from(key_label)]),
            private_key_row,
            Row::new(vec![Cell::from("Types:").style(field_name_style), Cell::from(key_type)]),
            Row::new(vec![Cell::from("Usage:").style(field_name_style), Cell::from(key_usage)]),
            ])
            .style(Style::default())
            .header(
                Row::new(vec!["Field", "Value"])
                    .style(Style::default().fg(Color::Blue).add_modifier(Modifier::ITALIC))
            )
            .widths(&constraints)
            //.block(Block::default().borders(Borders::ALL))
            .column_spacing(1);
        table.render(text_area, buf);
    }
}