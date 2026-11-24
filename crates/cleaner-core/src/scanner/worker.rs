use crate::models::{CleanupPlan, SafetyLevel, ScanProgress, TargetCandidate};
use crate::processes::ProcessGuard;
use crate::rules::env_resolver::resolve_env_vars;
use crate::rules::schema::{CleanerRule, RuleAction};
use crate::safety::validator::{classify_path_safety, validate_target_path};
use crate::scanner::stream::scan_with_age;
use cleaner_platform_windows::recycle_bin::get_recycle_bin_info;
use crossbeam_channel::Sender;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn minimum_age(rule_id: &str) -> Option<Duration> {
    (rule_id == "user_temp").then_some(Duration::from_secs(7 * 24 * 60 * 60))
}

pub fn get_system_drives() -> Vec<String> {
    (b'C'..=b'Z')
        .map(|letter| format!("{}:\\", letter as char))
        .filter(|drive| Path::new(drive).exists())
        .collect()
}

/// Legacy discovery helper for custom rules. Built-in cleanup only filters actual paths by drive.
pub fn apply_drive_to_path(path: &Path, target_drive: &str) -> PathBuf {
    let target = target_drive.as_bytes();
    let current = path.to_string_lossy();
    if matches!(target, [letter, b':'] | [letter, b':', b'\\'] if letter.is_ascii_alphabetic())
        && current.as_bytes().get(1..3) == Some(b":\\")
    {
        PathBuf::from(format!("{}{}", &target_drive[..2], &current[2..]))
    } else {
        path.to_owned()
    }
}

pub struct ScanWorker;

impl ScanWorker {
    pub fn scan_rule(
        rule: &CleanerRule,
        target_drive: Option<&str>,
        progress_tx: Option<&Sender<ScanProgress>>,
        cancel_flag: &Arc<AtomicBool>,
    ) -> CleanupPlan {
        let drive = target_drive.filter(|d| !d.eq_ignore_ascii_case("All Drives"));
        let requirements = rule.requirements.as_ref();
        let requires_admin = requirements.and_then(|r| r.requires_admin).unwrap_or(false);
        let blocked_process_name = ProcessGuard::check_blocking_process(
            requirements.and_then(|r| r.process_closed.as_deref()),
        );
        let mut plan = CleanupPlan {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            category: rule.category.clone(),
            description: rule.description.clone(),
            candidates: Vec::new(),
            total_bytes: 0,
            total_files: 0,
            safety: rule.safety,
            is_selected: false,
            is_blocked_by_process: blocked_process_name.is_some(),
            blocked_process_name,
            requires_admin,
            warnings: Vec::new(),
        };
        let enabled = !plan.is_blocked_by_process
            && (!requires_admin || cleaner_platform_windows::elevation::is_elevated());
        let mut seen = HashSet::new();

        for target in &rule.targets {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }
            if target.action == RuleAction::EmptyRecycleBin {
                if let Ok((bytes, count)) = get_recycle_bin_info(drive) {
                    if count > 0 {
                        plan.total_bytes += bytes;
                        plan.total_files += count as usize;
                        plan.candidates.push(TargetCandidate {
                            path: PathBuf::from(format!(
                                "SPECIAL:RECYCLE_BIN:{}",
                                drive.unwrap_or("ALL")
                            )),
                            display_path: "Windows Recycle Bin".into(),
                            size_bytes: bytes,
                            file_count: count as usize,
                            is_dir: true,
                            safety: rule.safety,
                            is_locked: false,
                            is_selected: false,
                            action: target.action,
                            pattern: None,
                            exclude: Vec::new(),
                        });
                    }
                }
                continue;
            }

            let Some(root) = target
                .allowed_root
                .as_ref()
                .and_then(|root| resolve_env_vars(root).ok())
            else {
                plan.warnings
                    .push("Cleanup rule has no resolvable allowed folder.".into());
                continue;
            };
            for path in crate::rules::discovery_resolver::resolve_target_paths(target, None) {
                let Ok(path) = resolve_env_vars(&path) else {
                    continue;
                };
                if drive.is_some_and(|d| {
                    !path
                        .to_string_lossy()
                        .get(..2)
                        .is_some_and(|p| p.eq_ignore_ascii_case(d.trim_end_matches('\\')))
                }) {
                    continue;
                }
                let path = match validate_target_path(&path, Some(&root)) {
                    Ok(path) => path,
                    Err(error) => {
                        plan.warnings.push(error.to_string());
                        continue;
                    }
                };
                if !seen.insert(path.to_string_lossy().to_lowercase()) {
                    continue;
                }
                let safety = classify_path_safety(&path, rule.safety);
                let exclude = target.exclude.as_deref().unwrap_or_default();
                let pattern = if target.action == RuleAction::DeleteFilesMatching {
                    target.pattern.as_deref()
                } else {
                    None
                };
                let stats = scan_with_age(
                    &path,
                    pattern,
                    exclude,
                    cancel_flag,
                    0,
                    minimum_age(&rule.id),
                    true,
                );
                if stats.skipped_entries > 0 {
                    plan.warnings.push(format!(
                        "{} unreadable or linked entries skipped in {}",
                        stats.skipped_entries,
                        path.display()
                    ));
                }
                plan.warnings.extend(stats.errors);
                if stats.file_count == 0 {
                    continue;
                }
                if let Some(tx) = progress_tx {
                    let _ = tx.send(ScanProgress {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        current_target: path.display().to_string(),
                        scanned_bytes: stats.total_bytes,
                        scanned_files: stats.file_count,
                        is_complete: false,
                    });
                }
                plan.total_bytes += stats.total_bytes;
                plan.total_files += stats.file_count;
                plan.candidates.push(TargetCandidate {
                    display_path: path.display().to_string(),
                    size_bytes: stats.total_bytes,
                    file_count: stats.file_count,
                    is_dir: path.is_dir(),
                    path,
                    safety,
                    is_locked: false,
                    is_selected: enabled && safety == SafetyLevel::Safe,
                    action: target.action,
                    pattern: target.pattern.clone(),
                    exclude: exclude.to_vec(),
                });
            }
        }
        plan.is_selected = plan
            .candidates
            .iter()
            .any(|candidate| candidate.is_selected);
        plan
    }
}
