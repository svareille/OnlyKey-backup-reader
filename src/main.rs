use std::{
    io::{self}, path::PathBuf, fs, time::{Duration, Instant}, error::Error,
};
use anyhow::{Result, bail, ensure};
use clipboard::{ClipboardProvider, ClipboardContext};
use data_encoding::{HEXLOWER, HEXUPPER};
use log::{warn, error, info, debug};
use rsa::pkcs8::ToPrivateKey;
use tui::{
    backend::{CrosstermBackend, Backend},
    Terminal, widgets::ListState,
};
use crossterm::{
    event::{self, EnableMouseCapture, DisableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use clap::{Parser};

mod ui;

mod res {
    pub mod text;
}

use okbr::{OnlyKey, OTP, BackupError, ECCKeyType};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(value_parser)]
    /// Path to the OnlyKey backup to load
    backup: PathBuf,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[clap(short, long, value_parser, value_name = "FILE")]
    /// If present, store the decrypted raw backup in the specified file
    raw_output: Option<PathBuf>,

    /*#[clap(short, long, arg_enum, value_parser)]
    /// Set the decryption key type to decrypt the loaded backup
    decryption_key_type: Option<DecrKeyType>,*/
}

/*#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DecrKeyType {
    Ecc,
    Rsa,
    Pass,
}*/

#[derive(Clone)]
enum Panel {
    #[allow(dead_code)]
    DataDisplay,
    EnterDecrPass,
    HelpButton,
    HelpPopup,
    Onlykey,
    ProfileTab,
    SelectDecrKeyType,
    EnterECCKey(ECCKeyType),
    EnterRsaKey,
    SelectDecrEccKeyType,
    General,
    #[allow(dead_code)]
    StatusBar,
}

enum InputMode {
    Normal,
    Editing,
}

struct Input {
    value: String,
    cursor: usize,
    max_len: usize,
}

impl Input {
    fn drain(&mut self) -> String {
        self.cursor = 0;
        self.value.drain(..).collect()
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
pub enum SelectedGeneral {
    None,
    Ecc(u16),
    Rsa(u16),
    Hmac(u16),
    DerivationKey,
}

struct App<'a> {
    /// Path of the backup
    pub backup_path: PathBuf,
    /// Path of the destination file where to store the raw output
    pub raw_path: Option<PathBuf>,
    /// Onlykey object representing the backup
    pub onlykey: Option<OnlyKey>,
    /// Decryption key types
    decr_key_items: StatefulList<&'a str>,
    /// Decryption ECC key types
    decr_ecc_key_items: StatefulList<&'a str>,

    /// Current profile to work on
    pub current_profile: usize,
    /// Current account to work on
    pub current_account: usize,
    /// Current general item to work on
    pub current_general: SelectedGeneral,

    /// Display secrets on screen
    pub show_secrets: bool,

    /// Current selected panel
    pub current_panel: Panel,
    /// History of panels for popup navigation
    pub panel_history: Vec<Panel>,

    /// Text to display on the Status Bar for the clipboard
    pub clipboard_status_text: String,
    /// Remaining time before erasing the clipboard
    pub clipboard_remaining: Option<Duration>,
    /// Tme to wait before erasing the clipboard
    pub clipboard_total: Duration,

    /// Current input mode
    input_mode: InputMode,
    /// Value of the input box
    input: Input,

    /// Text of the error. None for no error.
    error: Option<String>,
}

impl<'a> App<'a> {
    fn new() -> App<'a> {
        App {
            backup_path: PathBuf::default(),
            raw_path: None,
            onlykey: None,
            decr_key_items: StatefulList::with_items(vec![
                "RSA",
                "ECC",
                "Passphrase",
            ], Some(0)),
            decr_ecc_key_items: StatefulList::with_items(vec![
                "X25519",
                "NIST256P1",
                "SECP256K1",
            ], Some(0)),

            current_profile: 0,
            current_account: 0,
            current_general: SelectedGeneral::Rsa(1),

            show_secrets: false,

            current_panel: Panel::ProfileTab,
            panel_history: vec![],

            clipboard_status_text: String::new(),
            clipboard_remaining: None,
            clipboard_total: Duration::from_secs(15),

            input_mode: InputMode::Normal,
            input: Input { value: String::new(), cursor: 0, max_len: 16},

            error: None,
        }
    }

    pub fn next_profile(&mut self) {
        self.current_profile = (self.current_profile + 1) % 3;
    }

    pub fn previous_profile(&mut self) {
        if self.current_profile > 0 {
            self.current_profile -= 1;
        } else {
            self.current_profile = 2;
        }
    }

    pub fn next_panel(&mut self) {
        self.current_panel = match &self.current_panel {
            Panel::ProfileTab => Panel::HelpButton,
            Panel::HelpButton => match self.current_profile {0 | 1 => Panel::Onlykey, 2 => Panel::General, _ => Panel::ProfileTab},
            Panel::Onlykey => Panel::ProfileTab,
            Panel::General => Panel::ProfileTab,
            other => other.clone(),
        };
    }

    pub fn previous_panel(&mut self) {
        self.current_panel = match &self.current_panel {
            Panel::ProfileTab => match self.current_profile {0 | 1 => Panel::Onlykey, 2 => Panel::General, _ => Panel::ProfileTab},
            Panel::Onlykey => Panel::HelpButton,
            Panel::General => Panel::HelpButton,
            Panel::HelpButton => Panel::ProfileTab,
            other => other.clone(),
        };
    }

    pub fn get_current_account_name(&self) -> String {
        ["1a", "2a", "1b", "2b", "3a", "4a", "3b", "4b", "5a", "6a", "5b", "6b"][self.current_account].to_owned()
    }

    fn on_tick(&mut self, elapsed: Duration) {
        if let Some(remaining) = &mut self.clipboard_remaining {
            *remaining = remaining.checked_sub(elapsed).unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                if let Err(e) = self.clear_clipboard() {
                    warn!("Couldn't clear clipboard: {}", e);
                    self.clipboard_status_text = "⚠️ Couldn't clear clipboard".to_owned();
                }
                
            }
        }
    }

    fn clear_clipboard(&mut self) -> Result<(), Box<dyn Error>> {
        let mut ctx =  ClipboardContext::new()?;
        ctx.set_contents(String::new())?;
        self.clipboard_remaining = None;
        self.clipboard_status_text = String::new();
        Ok(())
    }

    fn set_clipboard(&mut self, text: String) -> Result<(), Box<dyn Error>> {
        let mut ctx =  ClipboardContext::new()?;
        ctx.set_contents(text)?;
        self.clipboard_remaining = Some(self.clipboard_total);
        Ok(())
    }

    pub fn set_error(&mut self, error_text: &str) {
        self.error = Some(error_text.to_owned());
    }

    pub fn clear_error(&mut self) {
        self.error = None;
    }

    pub fn get_error(&self) -> Option<&String> {self.error.as_ref()}
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    setup_logger(cli.verbose.log_level_filter())?;

    ensure!(okbr::verify_backup(&fs::read_to_string(&cli.backup).expect("Problem reading backup"))?,
            "Backup seems corrupted. Aborting.");
    

    let mut app = App::new();
    app.backup_path = cli.backup;
    app.current_panel = Panel::SelectDecrKeyType;
    app.raw_path = cli.raw_output;

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    info!("Terminal properly configured.");

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal().unwrap();
        default_hook(info);
    }));

    // run app
    let tick_rate = Duration::from_secs(1);
    let res = run_app(&mut terminal, app, tick_rate);

    restore_terminal()?;

    info!("Terminal properly restored.");

    if let Err(err) = res {
        error!("Error occurred: {:?}", err);
        println!("Error occurred: {:?}", err);
    }

    Ok(())
}

fn restore_terminal() -> Result<()>{
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

fn setup_logger(level: log::LevelFilter) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}]{} [{}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.target(),
                record.level(),
                record.file().unwrap_or("?"),
                record.line().map(|l| l.to_string()).unwrap_or_default(),
                message
            ))
        })
        .level(level)
        .chain(fern::log_file("output.log")?)
        .apply()?;
    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App, tick_rate: Duration,) -> Result<()> {
    let mut last_tick = Instant::now();
    loop {
        // Compute the OTP
        let account_name = app.get_current_account_name();

        if let Some(ok) = &mut app.onlykey {
            let profile = match app.current_profile {
                0 => Some(&mut ok.profile1),
                1 => Some(&mut ok.profile2),
                n => {
                    warn!("Nonexistent profile {}! This shouldn't have happened!", n);
                    None
                }
            };
            if let Some(profile) = profile {
                let account = profile.get_account_by_name_mut(&account_name).unwrap();
                match account.otp {
                    OTP::None | OTP::TOTP(_) => account.generate_new_otp(),
                    OTP::YubicoOTP(_) => {
                        if account.get_computed_otp().is_empty() {
                            account.generate_new_otp();
                        }
                    },
                }
            }
        }

        terminal.draw(|f| ui::ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if app.get_error().is_some() {
                    match key.code {
                        KeyCode::Enter | KeyCode::Esc => {
                            app.clear_error();
                        },
                        _ => {},
                    }
                    continue;
                }
                match app.input_mode {
                    InputMode::Normal => {
                        match app.current_panel {
                            Panel::SelectDecrKeyType => match key.code {
                                KeyCode::Down => {
                                    app.decr_key_items.next();
                                },
                                KeyCode::Up => {
                                    app.decr_key_items.previous();
                                },
                                KeyCode::Enter => {
                                    match app.decr_key_items.state.selected() {
                                        Some(0) => { // RSA
                                            info!("RSA key selected");
                                            app.current_panel = Panel::EnterRsaKey;
                                            app.input_mode = InputMode::Editing;
                                            app.input.max_len = 1024;
                                            app.panel_history.push(Panel::SelectDecrKeyType);
                                        }, 
                                        Some(1) => { // ECC
                                            info!("ECC key type selected");
                                            app.current_panel = Panel::SelectDecrEccKeyType;
                                        }, 
                                        Some(2) => { // Passphrase
                                            info!("Passphrase key type selected");
                                            app.current_panel = Panel::EnterDecrPass;
                                            app.input_mode = InputMode::Editing;
                                            app.input.max_len = 64;
                                        }, 
                                        None => {},
                                        Some(n) => {
                                            error!("Problem with decryption key selection: unexpected selection {}", n);
                                            bail!("Problem with decryption key selection: unexpected selection {}", n);
                                        },
                                    }
                                    app.panel_history.push(Panel::SelectDecrKeyType);
                                },
                                _ => {}
                            }
                            Panel::SelectDecrEccKeyType => match key.code {
                                KeyCode::Down => {
                                    app.decr_ecc_key_items.next();
                                },
                                KeyCode::Up => {
                                    app.decr_ecc_key_items.previous();
                                },
                                KeyCode::Enter => {
                                    match app.decr_ecc_key_items.state.selected() {
                                        Some(0) => { // X25519
                                            info!("X25519 ECC key type selected");
                                            app.current_panel = Panel::EnterECCKey(ECCKeyType::X25519);
                                            app.input_mode = InputMode::Editing;
                                            app.input.max_len = 64;
                                        }, 
                                        Some(1) => { // NIST256P1
                                            info!("NIST256P1 ECC key type selected");
                                            app.current_panel = Panel::EnterECCKey(ECCKeyType::NIST256P1);
                                            app.input_mode = InputMode::Editing;
                                            app.input.max_len = 64;
                                        }, 
                                        Some(2) => { // SECP256K1
                                            info!("SECP256K1 ECC key type selected");
                                            app.current_panel = Panel::EnterECCKey(ECCKeyType::SECP256K1);
                                            app.input_mode = InputMode::Editing;
                                            app.input.max_len = 64;
                                        }, 
                                        None => {},
                                        Some(n) => {
                                            error!("Problem with decryption ecc key selection: unexpected selection {}", n);
                                            bail!("Problem with decryption ecc key selection: unexpected selection {}", n);
                                        },
                                    }
                                    app.panel_history.push(Panel::SelectDecrEccKeyType);
                                },
                                KeyCode::Esc => {
                                    if let Some(panel) = app.panel_history.pop() {
                                        app.current_panel = panel;
                                    }
                                },
                                _ => {}
                            }
                            Panel::ProfileTab => match key.code {
                                KeyCode::Right => {
                                    app.next_profile();
                                }
                                KeyCode::Left => {
                                    app.previous_profile();
                                }
                                _ => {}
                            }
                            Panel::Onlykey => match key.code {
                                KeyCode::Right => {
                                    //app.current_account = (app.current_account + 1)%12;
                                    // Move in one row : 0 <-> 1 ; 2 <-> 3 ; 4 <-> 5...
                                    let base = (app.current_account / 2)*2;
                                    app.current_account = base + (app.current_account - base + 1)%2;
                                }
                                KeyCode::Left => {
                                    /*if app.current_account > 0 {
                                        app.current_account -= 1;
                                    } else {
                                        app.current_account = 11;
                                    }*/
                                    let base = (app.current_account / 2)*2;
                                    if app.current_account == base {
                                        app.current_account += 1;
                                    } else {
                                        app.current_account -= 1;
                                    }
                                }
                                KeyCode::Down => {
                                    app.current_account = (app.current_account + 2)%12;
                                }
                                KeyCode::Up => {
                                    if app.current_account > 1 {
                                        app.current_account -= 2;
                                    } else if app.current_account == 1 {
                                        app.current_account = 11;
                                    } else if app.current_account == 0 {
                                        app.current_account = 10;
                                    }
                                }
                                _ => {}
                            }
                            Panel::General => {
                                /*let mut keys: Vec<usize> = vec![];
                                if let Some(ok) = &app.onlykey {
                                    for i in 1..=16 {
                                        if ok.get_ecc_key(i).unwrap().is_some() {
                                            keys.push(i);
                                        }
                                    }
                                }*/
                                match key.code {
                                    KeyCode::Right => {
                                        app.current_general = match app.current_general {
                                            SelectedGeneral::None => SelectedGeneral::None,
                                            SelectedGeneral::Ecc(i) => {
                                                // Move in one row : 1 -> 2 -> 3 -> 4 -> 1
                                                let base = ((i-1) / 4)*4 + 1;
                                                
                                                SelectedGeneral::Ecc(if i == base+3 {base} else {i+1})
                                            },
                                            SelectedGeneral::Rsa(i) => 
                                                SelectedGeneral::Rsa(i%4+1),
                                            SelectedGeneral::Hmac(i) =>
                                                if i == 1 {
                                                    SelectedGeneral::Hmac(2)
                                                } else {
                                                    SelectedGeneral::DerivationKey
                                                },
                                            SelectedGeneral::DerivationKey => SelectedGeneral::Hmac(1),
                                        };
                                    }
                                    KeyCode::Left => {
                                        app.current_general = match app.current_general {
                                            SelectedGeneral::None => SelectedGeneral::None,
                                            SelectedGeneral::Ecc(i) => {
                                                // Move in one row : 1 <-> 2 <-> 3 <-> 4 <-> 1
                                                let base = ((i-1) / 4)*4 + 1;
                                                SelectedGeneral::Ecc(if i == base {i+3} else {i-1})
                                            },
                                            SelectedGeneral::Rsa(i) =>
                                                SelectedGeneral::Rsa(if i == 1 {4} else {i-1}),
                                            SelectedGeneral::Hmac(i) => 
                                                if i == 1 {
                                                    SelectedGeneral::DerivationKey
                                                } else {
                                                    SelectedGeneral::Hmac(1)
                                                },
                                            SelectedGeneral::DerivationKey => SelectedGeneral::Hmac(2),
                                        };
                                    }
                                    KeyCode::Down => {
                                        app.current_general = match app.current_general {
                                            SelectedGeneral::None => SelectedGeneral::None,
                                            SelectedGeneral::Rsa(i) =>
                                                SelectedGeneral::Ecc(i),
                                            SelectedGeneral::Ecc(i) => {
                                                // Move in one row : 1 <-> 2 <-> 3 <-> 4 <-> 1
                                                let base = ((i-1) / 4)*4 + 1;
                                                if base == 13 {
                                                    let index = (i-1)%4+1;
                                                    if index <= 2 {
                                                        SelectedGeneral::Hmac(index)
                                                    } else if index == 3 {
                                                        SelectedGeneral::DerivationKey
                                                    } else {
                                                        SelectedGeneral::Rsa(index)
                                                    }
                                                } else {
                                                    SelectedGeneral::Ecc(base + 4 + (i-1)%4)
                                                }
                                            },
                                            SelectedGeneral::Hmac(i) => SelectedGeneral::Rsa(i),
                                            SelectedGeneral::DerivationKey => SelectedGeneral::Rsa(3),
                                        };
                                    }
                                    KeyCode::Up => {
                                        app.current_general = match app.current_general {
                                            SelectedGeneral::None => SelectedGeneral::None,
                                            SelectedGeneral::Rsa(i) => if i <= 2 {
                                                    SelectedGeneral::Hmac(i)
                                                } else if i == 3 {
                                                    SelectedGeneral::DerivationKey
                                                } else {
                                                    SelectedGeneral::Ecc(13 + i-1)
                                                },
                                            SelectedGeneral::Ecc(i) => {
                                                // Move in one row : 1 <-> 2 <-> 3 <-> 4 <-> 1
                                                let base = ((i-1) / 4)*4 + 1;
                                                if base == 1 {
                                                    SelectedGeneral::Rsa(i)
                                                } else {
                                                    SelectedGeneral::Ecc(base - 4 + (i-1)%4)
                                                }
                                            },
                                            SelectedGeneral::Hmac(i) => {
                                                SelectedGeneral::Ecc(13 + i-1)
                                            },
                                            SelectedGeneral::DerivationKey => 
                                                SelectedGeneral::Ecc(13 + 2),
                                        };
                                    }
                                    _ => {}
                                }
                            }
                            Panel::HelpButton => if key.code == KeyCode::Enter {
                                debug!("Displaying help popup");
                                app.panel_history.push(Panel::HelpButton);
                                app.current_panel = Panel::HelpPopup
                            }
                            Panel::HelpPopup => if key.code == KeyCode::Esc {
                                if let Some(panel) = app.panel_history.pop() {
                                    app.current_panel = panel;
                                }
                            }
                            _ => {}
                        }
                        if let Some(ok) = &app.onlykey {
                            match app.current_profile {
                                profile@0 | profile@1 => {
                                    debug!("Working on profile {}", profile);
                                    let profile = match app.current_profile {
                                        0 => &ok.profile1,
                                        1 => &ok.profile2,
                                        n => {
                                            error!("Nonexistent profile {}! This shouldn't have happened!", n);
                                            bail!("Nonexistent profile {}", n);
                                        },
                                    };
                                    let account_name = app.get_current_account_name();
                                    debug!("Working on account {}", account_name);
                                    match profile.get_account_by_name(&account_name) {
                                        Ok(account) => {
                                            match key.code {
                                                KeyCode::Char('l') => {
                                                    debug!("Copying label to clipboard");
                                                    match app.set_clipboard(account.label.clone()) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "Label copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy label to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy label to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('U') => {
                                                    debug!("Copying URL to clipboard");
                                                    match app.set_clipboard(account.url.clone()) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "URL copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy URL to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy URL to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('u') => {
                                                    debug!("Copying username to clipboard");
                                                    match app.set_clipboard(account.username.clone()) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "Username copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy username to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy username to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('p') => {
                                                    debug!("Copying password to clipboard");
                                                    match app.set_clipboard(account.password.clone()) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "Password copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy password to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy password to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('O') => {
                                                    debug!("Copying OTP seed to clipboard");
                                                    match app.set_clipboard(match &account.otp {
                                                        OTP::None => String::new(),
                                                        OTP::TOTP(seed)=> {
                                                            seed.clone()
                                                        }
                                                        OTP::YubicoOTP(yubico) => {
                                                            let pub_id = yubico_otp_gen::MODHEX.encode(&yubico.public_id);
                                                            let priv_id = yubico_otp_gen::MODHEX.encode(&yubico.private_id);
                                                            let key = yubico_otp_gen::MODHEX.encode(&yubico.key);
                                                            
                                                            format!("{}\n{}\n{}", pub_id, priv_id, key)
                                                        }
                                                    }) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "OTP seed copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy OTP seed to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy OTP seed to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('o') => {
                                                    debug!("Copying OTP to clipboard");
                                                    let otp = account.get_computed_otp();
                                                    match app.set_clipboard(otp) {
                                                        Ok(_) => {
                                                            app.clipboard_status_text = "OTP copied to clipboard".to_owned();
                                                        },
                                                        Err(e) => {
                                                            error!("Failed to copy OTP to clipboard: {}", e);
                                                            app.set_error(&format!("Could not copy OTP to clipboard: {}", e));
                                                        }
                                                    }
                                                },
                                                KeyCode::Char('r') => {
                                                    debug!("Reload OTP");
                                                    if let Some(ok) = &mut app.onlykey {
                                                        let profile = match app.current_profile {
                                                            0 => Some(&mut ok.profile1),
                                                            1 => Some(&mut ok.profile2),
                                                            n => {
                                                                warn!("Nonexistent profile {}! This shouldn't have happened!", n);
                                                                None
                                                            }
                                                        };
                                                        if let Some(profile) = profile {
                                                            let account = profile.get_account_by_name_mut(&account_name).unwrap();
                                                            account.generate_new_otp();
                                                        }
                                                    }
                                                }
                                                KeyCode::Char('+') => {
                                                    debug!("Increment OTP counter");
                                                    if let Some(ok) = &mut app.onlykey {
                                                        let profile = match app.current_profile {
                                                            0 => Some(&mut ok.profile1),
                                                            1 => Some(&mut ok.profile2),
                                                            n => {
                                                                warn!("Nonexistent profile {}! This shouldn't have happened!", n);
                                                                None
                                                            }
                                                        };
                                                        if let Some(profile) = profile {
                                                            let account = profile.get_account_by_name_mut(&account_name).unwrap();
                                                            if let OTP::YubicoOTP(yubico) = &mut account.otp {
                                                                debug!("Increment Yubico OTP counter");
                                                                yubico.counter += 1;
                                                                account.generate_new_otp();
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        },
                                        Err(e) => {
                                            error!("Error while getting account {} on profile {}: {}", account_name, app.current_profile, e);
                                            return Err(e);
                                        },
                                    }
                                }
                                2 => {
                                    debug!("Working on general data");
                                    match app.current_general {
                                        SelectedGeneral::None => {},
                                        SelectedGeneral::Ecc(index) => {
                                            if let KeyCode::Char('k') =  key.code {
                                                if let Some(ok) = &app.onlykey {
                                                    match ok.get_ecc_key(index.into()) {
                                                        Ok(key) => {
                                                            debug!("Copying private key to clipboard");
                                                            if let Some(key) = key {
                                                                let key = key.clone();
                                                                match app.set_clipboard(HEXUPPER.encode(key.private_key.as_bytes())) {
                                                                    Ok(_) => {
                                                                        app.clipboard_status_text = "Private key copied to clipboard".to_owned();
                                                                    },
                                                                    Err(e) => {
                                                                        error!("Failed to copy private key to clipboard: {}", e);
                                                                        app.set_error(&format!("Could not copy private key to clipboard: {}", e));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            error!("Error while getting ECC key {}: {}", 1, e);
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        SelectedGeneral::Rsa(index) => {
                                            match key.code {
                                                KeyCode::Char('k') => {
                                                    if let Some(ok) = &app.onlykey {
                                                        match ok.get_rsa_key(index.into()) {
                                                            Ok(key) => {
                                                                debug!("Copying private key to clipboard");
                                                                if let Some(key) = key {
                                                                    let key = key.clone();
                                                                    let private_key = match &key.private_key {
                                                                        Some(key) => {
                                                                            let p = &key.primes()[0];
                                                                            let q = &key.primes()[1];
                                                                            let mut raw = p.to_bytes_be();
                                                                            raw.extend(q.to_bytes_be());
                                                                            HEXUPPER.encode(&raw)
                                                                        }
                                                                        None => {"".to_owned()}
                                                                    };
                                                                    match app.set_clipboard(private_key) {
                                                                        Ok(_) => {
                                                                            app.clipboard_status_text = "Private key copied to clipboard".to_owned();
                                                                        },
                                                                        Err(e) => {
                                                                            error!("Failed to copy private key to clipboard: {}", e);
                                                                            app.set_error(&format!("Could not copy private key to clipboard: {}", e));
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Error while getting ECC key {}: {}", 1, e);
                                                            }
                                                        }
                                                    }
                                                }
                                                KeyCode::Char('K') => {
                                                    if let Some(ok) = &app.onlykey {
                                                        match ok.get_rsa_key(index.into()) {
                                                            Ok(key) => {
                                                                debug!("Copying private key to clipboard");
                                                                if let Some(key) = key {
                                                                    let key = key.clone();
                                                                    let private_key: String = match &key.private_key {
                                                                        Some(key) => {
                                                                            match key.to_pkcs8_pem() {
                                                                                Ok(pem) => {
                                                                                    pem.to_string()
                                                                                },
                                                                                Err(e) => {
                                                                                    error!("Could not create PKCS#8 string: {}", e);
                                                                                    "Could not create PKCS#8 PEM string".to_string()
                                                                                },
                                                                            }
                                                                        }
                                                                        None => {"".to_owned()}
                                                                    };
                                                                    match app.set_clipboard(private_key) {
                                                                        Ok(_) => {
                                                                            app.clipboard_status_text = "Private key copied to clipboard".to_owned();
                                                                        },
                                                                        Err(e) => {
                                                                            error!("Failed to copy private key to clipboard: {}", e);
                                                                            app.set_error(&format!("Could not copy private key to clipboard: {}", e));
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                error!("Error while getting ECC key {}: {}", 1, e);
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        },
                                        SelectedGeneral::Hmac(_) => {},
                                        SelectedGeneral::DerivationKey => {},
                                    }
                                }
                                _ => {}
                            }
                        }
                        match key.code {
                            KeyCode::Char('q') => return Ok(()),
                            KeyCode::Char('h') => {
                                app.panel_history.push(app.current_panel);
                                app.current_panel = Panel::HelpPopup;
                            }
                            KeyCode::Char('s') => {
                                app.show_secrets = !app.show_secrets;
                            }
                            KeyCode::Tab => {
                                app.next_panel();
                            }
                            KeyCode::BackTab => {
                                app.previous_panel();
                            }
                            _ => {}
                        }
                    },
                    InputMode::Editing => match key.code {
                        KeyCode::Enter => {
                            match &app.current_panel {
                                Panel::EnterDecrPass => {
                                    debug!("Decryption passphrase entered");
                                    let mut ok = OnlyKey::new();
                                    let passphrase: String = app.input.drain();
                                    
                                    ok.set_backup_passphrase(&passphrase);
                                    info!("Passphrase set");
                                    match fs::read_to_string(&app.backup_path) {
                                        Ok(backup) => {
                                            debug!("Backup has been read");
                                            match &app.raw_path {
                                                Some(path) => {                                                    
                                                    match ok.decode_backup(&backup) {
                                                        Ok(decoded) => {
                                                            let backup_key = ok.backup_key().unwrap();
                                                            match backup_key.decrypt_backup(decoded) {
                                                                Ok(raw) => {
                                                                    fs::write(path, raw)?;
                                                                    return Ok(());
                                                                },
                                                                Err(_) => app.set_error("Failed to decrypt backup. Retry with another passphrase. If the decryption keep failing, the backup may be unusable."),
                                                            }
                                                        },
                                                        Err(e) => bail!("Could not decode backup: {}", e),
                                                    }
                                                }
                                                None => {
                                                    match ok.load_backup(&backup) {
                                                        Ok(()) => {
                                                            info!("Backup decoded");
                                                            app.onlykey = Some(ok);
                                                            app.panel_history.pop();
                                                            app.current_panel = Panel::ProfileTab;
                                                            app.input_mode = InputMode::Normal;
                                                        }
                                                        Err(error) => {
                                                            error!("Failed to load backup: {}", error);
                                                            match error.downcast_ref::<BackupError>() {
                                                                Some(BackupError::KeyTypeNoMatch) | Some(BackupError::UnexpectedByte(_))  | Some(BackupError::UnexpectedSlotNumber(_))=> {
                                                                    app.set_error("Failed to load backup. Retry with another passphrase. If the loading keep failing, the backup may be unusable.");
                                                                },
                                                                Some(_) | None => {
                                                                    bail!("Could not load backup: {}", error);
                                                                },
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            error!("Could not read provided file: {}", e);
                                            bail!(e);
                                        }
                                    }
                                }
                                Panel::EnterECCKey(key_type) => {
                                    debug!("Decryption ECC key has been entered");
                                    let mut ok = OnlyKey::new();
                                    let hex_key: String = app.input.drain();
                                    let hex_key = hex_key.to_ascii_lowercase();
                                    match HEXLOWER.decode(hex_key.as_bytes()) {
                                        Ok(key) => {
                                            if key.len() != 32 {
                                                error!("Key must be 32 bytes, got {}", key.len());
                                                app.set_error(&format!("Key must be 32 bytes (64 hex characters), got {}.", key.len()))
                                            } else {
                                                if let Err(e) =  ok.set_backup_ecc_key(key, key_type.clone()) {
                                                    error!("Problem setting ECC key: {}", e);
                                                    return Err(e);
                                                }
                                                info!("ECC key parsed");
                                                match fs::read_to_string(&app.backup_path) {
                                                    Ok(backup) => {
                                                        match &app.raw_path {
                                                            Some(path) => {                                                    
                                                                match ok.decode_backup(&backup) {
                                                                    Ok(decoded) => {
                                                                        let backup_key = ok.backup_key().unwrap();
                                                                        match backup_key.decrypt_backup(decoded) {
                                                                            Ok(raw) => {
                                                                                fs::write(path, raw)?;
                                                                                return Ok(());
                                                                            },
                                                                            Err(_) => app.set_error("Failed to decrypt backup. Retry with another ECC key. If the decryption keep failing, the backup may be unusable."),
                                                                        }
                                                                    },
                                                                    Err(e) => bail!("Could not decode backup: {}", e),
                                                                }
                                                            }
                                                            None => {
                                                                match ok.load_backup(&backup) {
                                                                    Ok(()) => {
                                                                        info!("Backup decoded");
                                                                        app.onlykey = Some(ok);
                                                                        app.panel_history.pop();
                                                                        app.current_panel = Panel::ProfileTab;
                                                                        app.input_mode = InputMode::Normal;
                                                                    }
                                                                    Err(e) => {
                                                                        error!("Failed to load backup: {}", e);
                                                                        match e.downcast_ref::<BackupError>() {
                                                                            Some(BackupError::KeyTypeNoMatch) => {
                                                                                app.set_error("Failed to load backup: The ECC key type provided does not match the one used for encryption.");
                                                                            }
                                                                            Some(BackupError::UnexpectedByte(_))  | Some(BackupError::UnexpectedSlotNumber(_))=> {
                                                                                app.set_error("Failed to load backup. Retry with another ECC key. If the loading keep failing, the backup may be unusable.");
                                                                            },
                                                                            Some(_) | None => {
                                                                                bail!("Could not load backup: {}", e);
                                                                            },
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    Err(e) => {
                                                        error!("Could not read provided file: {}", e);
                                                        bail!(e);
                                                    }
                                                }
                                            }
                                            
                                        },
                                        Err(e) => {
                                            error!("Wrong key format: {}", e);
                                            app.set_error(&format!("Wrong key format: {}.\nProvided key must be a 64 character hexadecimal string.", e));
                                        },
                                    }
                                },
                                Panel::EnterRsaKey => {
                                    debug!("Decryption RSA key has been entered");
                                    let mut ok = OnlyKey::new();
                                    let hex_key: String = app.input.drain();
                                    let hex_key = hex_key.to_ascii_lowercase();
                                    match HEXLOWER.decode(hex_key.as_bytes()) {
                                        Ok(key) => {
                                            if let Err(e) =  ok.set_backup_rsa_key(key) {
                                                error!("Problem setting RSA key: {}", e);
                                                return Err(e);
                                            }
                                            info!("RSA key parsed");
                                            match fs::read_to_string(&app.backup_path) {
                                                Ok(backup) => {
                                                    match &app.raw_path {
                                                        Some(path) => {                                                    
                                                            match ok.decode_backup(&backup) {
                                                                Ok(decoded) => {
                                                                    let backup_key = ok.backup_key().unwrap();
                                                                    match backup_key.decrypt_backup(decoded) {
                                                                        Ok(raw) => {
                                                                            fs::write(path, raw)?;
                                                                            return Ok(());
                                                                        },
                                                                        Err(_) => app.set_error("Failed to decrypt backup. Retry with another ECC key. If the decryption keep failing, the backup may be unusable."),
                                                                    }
                                                                },
                                                                Err(e) => bail!("Could not decode backup: {}", e),
                                                            }
                                                        }
                                                        None => {
                                                            match ok.load_backup(&backup) {
                                                                Ok(()) => {
                                                                    info!("Backup decoded");
                                                                    app.onlykey = Some(ok);
                                                                    app.panel_history.pop();
                                                                    app.current_panel = Panel::ProfileTab;
                                                                    app.input_mode = InputMode::Normal;
                                                                }
                                                                Err(e) => {
                                                                    error!("Failed to load backup: {}", e);
                                                                    match e.downcast_ref::<BackupError>() {
                                                                        Some(BackupError::KeyTypeNoMatch) => {
                                                                            app.set_error("Failed to load backup: The RSA key type provided does not match the one used for encryption.");
                                                                        }
                                                                        Some(BackupError::UnexpectedByte(_))  | Some(BackupError::UnexpectedSlotNumber(_))=> {
                                                                            app.set_error("Failed to load backup. Retry with another RSA key. If the loading keep failing, the backup may be unusable.");
                                                                        },
                                                                        Some(_) | None => {
                                                                            bail!("Could not load backup: {}", e);
                                                                        },
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                Err(e) => {
                                                    error!("Could not read provided file: {}", e);
                                                    bail!(e);
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            error!("Wrong key format: {}", e);
                                            app.set_error(&format!("Wrong key format: {}.\nProvided key must be a 256, 512, 768 or 1024 characters hexadecimal string.", e));
                                        },
                                    }
                                }
                                _ => {}
                            }
                            //app.messages.push(app.input.drain(..).collect());
                        }
                        KeyCode::Char(c) => {
                            if app.input.value.len() < app.input.max_len {
                                app.input.value.insert(app.input.cursor, c);
                                app.input.cursor += 1;
                            }
                        }
                        KeyCode::Backspace => {
                            if app.input.cursor > 0 {
                                app.input.cursor -= 1;
                                app.input.value.remove(app.input.cursor);
                            }
                        }
                        KeyCode::Delete => {
                            if app.input.cursor < app.input.value.len() {
                                app.input.value.remove(app.input.cursor);
                            }
                        }
                        KeyCode::Esc => {
                            if let Some(panel) = app.panel_history.pop() {
                                app.current_panel = panel;
                            }
                            app.input_mode = InputMode::Normal;
                        }
                        KeyCode::Left => {
                            if app.input.cursor > 0 {
                                app.input.cursor -= 1;
                            }
                        }
                        KeyCode::Right => {
                            if app.input.cursor < app.input.value.len() {
                                app.input.cursor += 1;
                            }
                        }
                        KeyCode::Home => {
                            app.input.cursor = 0;
                        }
                        KeyCode::End => {
                            app.input.cursor = app.input.value.len();
                        }
                        _ => {}
                    },
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            app.on_tick(last_tick.elapsed());
            last_tick = Instant::now();
        }
    }
}

struct StatefulList<T> {
    state: ListState,
    items: Vec<T>,
}

impl<T> StatefulList<T> {
    fn with_items(items: Vec<T>, selected: Option<usize>) -> StatefulList<T> {
        let mut state = ListState::default();
        state.select(selected);
        StatefulList {
            state,
            items,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn _unselect(&mut self) {
        self.state.select(None);
    }
}