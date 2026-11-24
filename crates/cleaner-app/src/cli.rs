use cleaner_core::format_bytes;
use cleaner_core::models::SafetyLevel;
use cleaner_core::rules::get_embedded_rules;
use cleaner_core::scanner::{scan_all_rules, scan_with_discovery};
use cleaner_core::storage::StorageAnalyzer;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub fn run_cli_scan(drive: Option<&str>, discover: bool) {
    let rules = get_embedded_rules();
    let cancel = Arc::new(AtomicBool::new(false));

    println!("Scanning {} cleaner rules...", rules.len());
    let plans = if discover {
        scan_with_discovery(&rules, drive, cancel)
    } else {
        scan_all_rules(&rules, drive, None, cancel)
    };

    println!(
        "\n{:<32} {:<14} {:<8} {:<12} {:<24}",
        "RULE", "CATEGORY", "SAFETY", "FILE BYTES", "STATUS"
    );
    println!("{:-<92}", "");

    let mut grand_total = 0;
    for plan in &plans {
        if plan.total_bytes > 0 || !plan.warnings.is_empty() {
            grand_total += plan.total_bytes;
            for warning in &plan.warnings {
                println!("  Note: {warning}");
            }
            let status = if plan.is_blocked_by_process {
                format!(
                    "BLOCKED ({})",
                    plan.blocked_process_name.as_deref().unwrap_or("Active")
                )
            } else if plan.is_selected {
                "SELECTED".to_string()
            } else {
                "UNSELECTED".to_string()
            };
            println!(
                "{:<32} {:<14} {:<8} {:<12} {:<24}",
                plan.rule_name,
                plan.category,
                plan.safety.to_string(),
                format_bytes(plan.total_bytes),
                status
            );
        }
    }

    println!("{:-<92}", "");
    println!(
        "Total inspected logical bytes: {}",
        format_bytes(grand_total)
    );
}

pub fn run_cli_scheduled_clean(drive: Option<&str>) {
    tracing::info!("Starting scheduled headless cleanup");
    let rules = get_embedded_rules();
    let cancel = Arc::new(AtomicBool::new(false));

    // Only scan and select SAFE rules
    let safe_rules: Vec<_> = rules
        .into_iter()
        .filter(|r| r.safety == SafetyLevel::Safe)
        .collect();
    let plans = scan_all_rules(&safe_rules, drive, None, cancel);

    let results = cleaner_core::execute_all_selected(&plans);
    let total_reclaimed: u64 = results.iter().map(|r| r.reclaimed_bytes).sum();
    let total_files: usize = results.iter().map(|r| r.files_deleted).sum();

    tracing::info!(
        "Scheduled cleanup finished: reclaimed {}, {} files deleted",
        format_bytes(total_reclaimed),
        total_files
    );
    println!(
        "Scheduled cleanup complete: reclaimed {}",
        format_bytes(total_reclaimed)
    );
}

pub fn run_cli_storage_analyze(drive: &str) {
    let cancel = Arc::new(AtomicBool::new(false));
    let root = PathBuf::from(drive);

    println!("Analyzing storage in {:?}...", root);
    let items = StorageAnalyzer::analyze_directory(&root, &cancel, 30);

    println!("\n{:<35} {:<15} {:<12}", "ITEM", "CATEGORY", "SIZE");
    println!("{:-<65}", "");

    for item in items {
        println!(
            "{:<35} {:<15} {:<12}",
            item.name,
            item.category,
            format_bytes(item.size_bytes)
        );
    }
}
