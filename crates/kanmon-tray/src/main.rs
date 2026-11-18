//! kanmon-tray — Windows の通知領域（タスクトレイ）のアイコン。
//!
//! kanmond はサービス（セッション 0）で動くので、利用者の画面に出せない。トレイはログオン時に
//! 利用者の権限で起動し（kanmon-setup.ps1 が HKLM の Run に登録）、kanmond の状態パイプ
//! `\\.\pipe\kanmon` に 3 秒ごとに `{"cmd":"status"}` を送って、次を行う。
//! - アイコンの色：平常（緑）・注意（黄、warn）・警告（赤、critical）・停止（灰、kanmond に届かない）
//! - メニュー：状態、直近の警告 10 件（選ぶと詳細）、すべて確認済みにする、通知を 1 時間止める、終了
//! - トースト通知：warn 以上の新しい警告
//!
//! パイプは読むだけ（設定を変える口は無い）。表示する文字列は model.rs で制御文字を除いて切る。
#![cfg_attr(windows, windows_subsystem = "windows")]

// 判断の部分は Windows 以外ではテストでだけ使う
#[cfg_attr(not(windows), allow(dead_code))]
mod model;

#[cfg(not(windows))]
fn main() {
    eprintln!("kanmon-tray は Windows 専用です（macOS は Kanmon.app を使います）");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    if let Err(e) = win::run() {
        win::log(&format!("終了：{e}"));
    }
}

#[cfg(windows)]
mod win {
    use crate::model::{self, IconState, Model, Status};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::time::{Duration, Instant};
    use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MessageBoxW, PeekMessageW, TranslateMessage, MB_ICONINFORMATION, MB_OK, MSG, PM_REMOVE,
    };

    const PIPE: &str = r"\\.\pipe\kanmon";
    /// トーストの送り主（AppUserModelID）。HKCU に表示名を登録して使う【要検証：パッケージ化しないアプリのトースト】
    const AUMID: &str = "Kanmon.Tray";
    const POLL: Duration = Duration::from_secs(3);
    const MAX_ITEMS: usize = 10;

    pub fn log(msg: &str) {
        let Some(dir) = std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("kanmon")) else {
            return;
        };
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("tray.log");
        // 大きくなりすぎたら作り直す
        if std::fs::metadata(&p).is_ok_and(|m| m.len() > 1_000_000) {
            let _ = std::fs::remove_file(&p);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            let _ = writeln!(f, "{:?} {msg}", std::time::SystemTime::now());
        }
    }

    /// 状態パイプに 1 行送り、1 行（最大 2MB）受け取る
    fn query() -> Option<Status> {
        let mut f = std::fs::OpenOptions::new().read(true).write(true).open(PIPE).ok()?;
        f.write_all(b"{\"cmd\":\"status\"}\n").ok()?;
        let mut line = String::new();
        let n = BufReader::new(f.take(2 * 1024 * 1024)).read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        Status::parse(&line)
    }

    /// 丸いアイコン（32×32、色だけを変える）
    fn icon(state: IconState) -> Icon {
        let (r, g, b) = match state {
            IconState::Normal => (0x2e, 0x7d, 0x32),
            IconState::Warn => (0xf9, 0xa8, 0x25),
            IconState::Critical => (0xc6, 0x28, 0x28),
            IconState::Down => (0x75, 0x75, 0x75),
        };
        let n = 32i32;
        let mut px = Vec::with_capacity((n * n * 4) as usize);
        for y in 0..n {
            for x in 0..n {
                let dx = x as f32 - 15.5;
                let dy = y as f32 - 15.5;
                let d = (dx * dx + dy * dy).sqrt();
                // 外側 1px は暗い縁、内側は塗る、外は透明
                let (cr, cg, cb, a) = if d <= 13.5 {
                    (r, g, b, 255)
                } else if d <= 15.0 {
                    (r / 2, g / 2, b / 2, 255)
                } else {
                    (0, 0, 0, 0)
                };
                px.extend_from_slice(&[cr, cg, cb, a]);
            }
        }
        Icon::from_rgba(px, n as u32, n as u32).expect("icon")
    }

    /// トーストの送り主を HKCU に登録する（利用者の権限で書ける場所）
    fn register_aumid() {
        let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
        if let Ok((k, _)) = hkcu.create_subkey(format!(r"Software\Classes\AppUserModelId\{AUMID}")) {
            let _ = k.set_value("DisplayName", &"kanmon");
        }
    }

    fn toast(title: &str, body: &str) {
        use windows::Data::Xml::Dom::XmlDocument;
        use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
        let r = (|| -> windows::core::Result<()> {
            let doc = XmlDocument::new()?;
            doc.LoadXml(&HSTRING::from(model::toast_xml(title, body)))?;
            let t = ToastNotification::CreateToastNotification(&doc)?;
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?.Show(&t)?;
            Ok(())
        })();
        if let Err(e) = r {
            log(&format!("トーストを出せません：{e}"));
        }
    }

    /// 詳細を別スレッドの MessageBox で出す（ループを止めない）
    fn show_detail(title: String, body: String) {
        std::thread::spawn(move || {
            let t = HSTRING::from(model::clean(&title, 200));
            let b = HSTRING::from(model::clean_body(&body, 30, 300));
            unsafe {
                MessageBoxW(None, PCWSTR(b.as_ptr()), PCWSTR(t.as_ptr()), MB_OK | MB_ICONINFORMATION);
            }
        });
    }

    fn tooltip(st: Option<&Status>, m: &Model, paused: bool) -> String {
        let mut s = match st {
            None => "kanmon：kanmond に接続できません".to_string(),
            Some(s) => {
                let n = m.unacked(s);
                let mode = if s.learning { "学習中" } else { s.mode.as_str() };
                if n > 0 {
                    format!("kanmon（{mode}）：未確認の警告 {n} 件")
                } else {
                    format!("kanmon（{mode}）：問題なし")
                }
            }
        };
        if paused {
            s.push_str("・通知停止中");
        }
        // トレイの吹き出しは 127 文字まで
        model::clean(&s, 120)
    }

    pub fn run() -> anyhow_lite::Result<()> {
        // 二重起動を防ぐ（ログオンごと・セッションごとに 1 つ）
        let name = HSTRING::from("Local\\kanmon-tray");
        let _mutex = unsafe { CreateMutexW(None, true, PCWSTR(name.as_ptr())) };
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            return Ok(());
        }
        // トースト（WinRT）を呼ぶ前に、このスレッドを初期化する
        unsafe {
            let _ = windows::Win32::System::WinRT::RoInitialize(windows::Win32::System::WinRT::RO_INIT_SINGLETHREADED);
        }
        register_aumid();

        let header = MenuItem::new("kanmon", false, None);
        let recent = Submenu::new("直近の警告", true);
        let ack = MenuItem::new("すべて確認済みにする", true, None);
        let pause = CheckMenuItem::new("通知を 1 時間止める", true, false, None);
        let quit = MenuItem::new("終了", true, None);
        let menu = Menu::new();
        menu.append_items(&[
            &header,
            &PredefinedMenuItem::separator(),
            &recent,
            &ack,
            &pause,
            &PredefinedMenuItem::separator(),
            &quit,
        ])
        .map_err(|e| e.to_string())?;

        let tray: TrayIcon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("kanmon")
            .with_icon(icon(IconState::Down))
            .build()
            .map_err(|e| e.to_string())?;

        let mut model = Model::default();
        let mut status: Option<Status> = None;
        let mut items: Vec<(MenuItem, crate::model::Alert)> = vec![];
        // 警告が無いときの「（なし）」
        let none_item = MenuItem::new("（なし）", false, None);
        let _ = recent.append(&none_item);
        let mut none_shown = true;
        let mut last_state = IconState::Down;
        let mut last_poll = Instant::now() - POLL;
        let mut paused_until: Option<Instant> = None;
        let mut down_logged = false;

        loop {
            // Windows のメッセージを回す（トレイとメニューはこのスレッドのメッセージで動く）
            unsafe {
                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }

            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                if ev.id == *quit.id() {
                    return Ok(());
                } else if ev.id == *ack.id() {
                    if let Some(s) = &status {
                        model.ack_all(s);
                    }
                    last_poll = Instant::now() - POLL;
                } else if ev.id == *pause.id() {
                    paused_until = pause.is_checked().then(|| Instant::now() + Duration::from_secs(3600));
                } else if let Some((_, a)) = items.iter().find(|(i, _)| *i.id() == ev.id) {
                    show_detail(
                        a.title.clone(),
                        format!("{}\n\nレベル：{}（{} 点）\n{}", a.body, a.level, a.score, a.ts),
                    );
                }
            }

            if paused_until.is_some_and(|t| Instant::now() >= t) {
                paused_until = None;
                pause.set_checked(false);
            }

            if last_poll.elapsed() >= POLL {
                last_poll = Instant::now();
                status = query();
                let paused = paused_until.is_some();
                match &status {
                    Some(s) => {
                        down_logged = false;
                        for a in model.update(s, paused) {
                            toast(&a.title, &a.body);
                        }
                        header.set_text(model::clean(&format!("kanmon {}（{}）", s.version, s.host), 60));
                        // 直近の警告を作り直す（変わったときだけ）
                        let ids: Vec<&str> = s.alerts.iter().take(MAX_ITEMS).map(|a| a.id.as_str()).collect();
                        let cur: Vec<&str> = items.iter().map(|(_, a)| a.id.as_str()).collect();
                        if ids != cur {
                            for (i, _) in items.drain(..) {
                                let _ = recent.remove(&i);
                            }
                            for a in s.alerts.iter().take(MAX_ITEMS) {
                                let i = MenuItem::new(model::menu_label(a), true, None);
                                let _ = recent.append(&i);
                                items.push((i, a.clone()));
                            }
                            if items.is_empty() && !none_shown {
                                let _ = recent.append(&none_item);
                                none_shown = true;
                            } else if !items.is_empty() && none_shown {
                                let _ = recent.remove(&none_item);
                                none_shown = false;
                            }
                        }
                    }
                    None => {
                        if !down_logged {
                            log("kanmond に接続できません（サービスが止まっているか、権限が無い）");
                            down_logged = true;
                        }
                        header.set_text("kanmon（kanmond に接続できません）");
                    }
                }
                let st = model.icon(status.as_ref());
                if st != last_state {
                    let _ = tray.set_icon(Some(icon(st)));
                    last_state = st;
                }
                let _ = tray.set_tooltip(Some(tooltip(status.as_ref(), &model, paused)));
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 依存を増やさないための小さな Result
    pub mod anyhow_lite {
        pub type Result<T> = std::result::Result<T, String>;
    }
}
