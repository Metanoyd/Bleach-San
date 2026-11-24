pub mod heuristic;
pub mod stream;
pub mod worker;

pub use heuristic::{DiscoveredCache, HeuristicDiscoveryEngine};
pub use stream::{matches_simple_pattern, scan_directory_bounded, ScanStats};
pub use worker::{apply_drive_to_path, get_system_drives, ScanWorker};

use crate::models::{CleanupPlan, ScanProgress};
use crate::rules::schema::CleanerRule;
use crossbeam_channel::Sender;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::{atomic::AtomicBool, Arc, OnceLock};

pub fn scan_all_rules(
    rules: &[CleanerRule],
    target_drive: Option<&str>,
    progress_tx: Option<Sender<ScanProgress>>,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<CleanupPlan> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    let scan = |rule| ScanWorker::scan_rule(rule, target_drive, progress_tx.as_ref(), &cancel_flag);
    match POOL.get_or_init(|| rayon::ThreadPoolBuilder::new().num_threads(2).build().ok()) {
        Some(pool) => pool.install(|| rules.par_iter().map(scan).collect()),
        None => rules.iter().map(scan).collect(),
    }
}

pub fn scan_with_discovery(
    rules: &[CleanerRule],
    target_drive: Option<&str>,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<CleanupPlan> {
    let mut plans = scan_all_rules(rules, target_drive, None, Arc::clone(&cancel_flag));
    let mut seen: HashSet<_> = plans
        .iter()
        .flat_map(|p| &p.candidates)
        .map(|c| c.path.to_string_lossy().to_lowercase())
        .collect();
    for mut plan in HeuristicDiscoveryEngine::discover_drive_caches(
        target_drive.unwrap_or("All Drives"),
        &cancel_flag,
    ) {
        plan.candidates
            .retain(|c| seen.insert(c.path.to_string_lossy().to_lowercase()));
        if plan.candidates.is_empty() {
            continue;
        }
        plan.total_bytes = plan.candidates.iter().map(|c| c.size_bytes).sum();
        plan.total_files = plan.candidates.iter().map(|c| c.file_count).sum();
        plan.description = format!("Inspect in Explorer. {}", plan.description);

        plans.push(plan);
    }
    plans
}
