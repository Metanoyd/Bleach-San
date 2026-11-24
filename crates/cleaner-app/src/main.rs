#![windows_subsystem = "windows"]

mod cli;
mod logging;

use clap::Parser;
use cli::{run_cli_scan, run_cli_scheduled_clean, run_cli_storage_analyze};
use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

#[derive(Parser, Debug)]
#[command(
    name = "bleachsan",
    version,
    about = "Windows storage cleaner and analyzer"
)]
struct CliArgs {
    /// Show reviewed cleanup categories without deleting anything
    #[arg(long, conflicts_with_all = ["scheduled", "clean_safe", "analyze"])]
    scan: bool,

    /// Include read-only guesses in the scan
    #[arg(long, requires = "scan")]
    discover: bool,

    /// Select a local volume for --scan or --analyze, such as C:
    #[arg(long, value_parser = drive_letter)]
    drive: Option<String>,

    /// Run scheduled headless cleanup
    #[arg(long)]
    scheduled: bool,

    /// Clean only positively identified safe categories
    #[arg(long)]
    clean_safe: bool,

    /// Analyze the selected volume without deleting anything
    #[arg(long, conflicts_with_all = ["scheduled", "clean_safe"])]
    analyze: bool,
}

fn drive_letter(value: &str) -> Result<String, String> {
    let drive = value.trim_end_matches('\\');
    if matches!(drive.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic()) {
        Ok(format!("{}\\", drive.to_ascii_uppercase()))
    } else {
        Err("Use a drive letter such as C:".into())
    }
}

fn main() -> anyhow::Result<()> {
    if std::env::args_os().len() > 1 {
        // Preserve Explorer's console-free launch. CLI arguments need terminal output.
        let _ = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
    }
    let args = CliArgs::parse();
    let headless = args.scan || args.scheduled || args.clean_safe || args.analyze;
    let _log_guard = logging::init_logging(headless);
    if args.scan {
        run_cli_scan(args.drive.as_deref(), args.discover);
    } else if args.scheduled || args.clean_safe {
        run_cli_scheduled_clean(args.drive.as_deref());
    } else if args.analyze {
        run_cli_storage_analyze(args.drive.as_deref().unwrap_or("C:\\"));
    } else if let Err(error) = cleaner_ui::run_ui() {
        tracing::error!("UI launch failed: {error}");
        let message: Vec<u16> = format!("BleachSan could not open.\n\n{error}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            MessageBoxW(
                None,
                windows::core::PCWSTR(message.as_ptr()),
                windows::core::w!("BleachSan"),
                MB_OK | MB_ICONERROR,
            );
        }
        return Err(anyhow::anyhow!(error.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_modes_conflict_with_cleanup() {
        for read_only in ["--scan", "--analyze"] {
            for cleanup in ["--scheduled", "--clean-safe"] {
                assert!(CliArgs::try_parse_from(["bleachsan", read_only, cleanup]).is_err());
            }
        }
        assert!(CliArgs::try_parse_from(["bleachsan", "--scheduled", "--clean-safe"]).is_ok());
    }
}
