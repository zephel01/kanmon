//! Windows：サービスとして動かす（`kanmond --service --config <設定>`。kanmon-setup.ps1 が登録する）。
//!
//! サービス コントロール マネージャー（SCM）から起動され、停止・シャットダウンの要求で終わる。
//! 監視そのものは別スレッドで `Monitor::run` を回す（コンソールで動かすときと同じ）。

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::OnceLock;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "kanmond";

static CONFIG: OnceLock<Option<PathBuf>> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// SCM に制御を渡す（サービスが止まるまで戻らない）
pub fn run(config: Option<PathBuf>) -> anyhow::Result<()> {
    let _ = CONFIG.set(config);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| {
        anyhow::anyhow!("サービスとして起動できません（コンソールから実行するときは --service を付けない）: {e}")
    })
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        crate::logln!("サービスの実行に失敗: {e:#}");
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty(), 0))?;

    let cfg_path = CONFIG.get().cloned().flatten();
    let (fail_tx, fail_rx) = mpsc::channel::<String>();
    std::thread::Builder::new().name("kanmon-monitor".into()).spawn(move || {
        let r = (|| -> anyhow::Result<()> {
            let mut m = crate::start_monitor(cfg_path.as_deref())?;
            m.run()
        })();
        if let Err(e) = r {
            let _ = fail_tx.send(format!("{e:#}"));
        }
    })?;

    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
    ))?;
    crate::logln!("サービスとして開始");

    // 停止の要求か、監視の失敗を待つ
    let code = loop {
        if stop_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            crate::logln!("サービスの停止の要求");
            break 0;
        }
        if let Ok(e) = fail_rx.try_recv() {
            crate::logln!("監視が止まりました: {e}");
            break 1;
        }
    };
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), code))?;
    // 監視のスレッドは止める手段が無いので、プロセスごと終える
    std::process::exit(code as i32);
}
