use crate::models::{CleanupPlan, CleanupResult};
use crate::processes::ProcessGuard;
use crate::rules::{get_embedded_rules, schema::RuleAction};
use crate::safety::{
    levels::is_forbidden_from_cleanup,
    validator::{classify_path_safety, validate_target_path},
};
use crate::scanner::{
    matches_simple_pattern,
    stream::{older_than, walk_regular_files},
    worker::minimum_age,
};
use cleaner_platform_windows::filesystem::delete_file_checked;
use cleaner_platform_windows::recycle_bin::empty_recycle_bin;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Instant, SystemTime};

pub struct CleanupExecutor;

impl CleanupExecutor {
    pub fn execute_plan(plan: &CleanupPlan) -> CleanupResult {
        let start = Instant::now();
        let mut result = CleanupResult {
            rule_id: plan.rule_id.clone(),
            rule_name: plan.rule_name.clone(),
            ..CleanupResult::default()
        };
        if is_forbidden_from_cleanup(plan.safety) {
            result
                .errors
                .push("This category is for inspection only.".into());
            return result;
        }
        let rule = get_embedded_rules()
            .into_iter()
            .find(|r| r.id == plan.rule_id);
        let required_closed = rule
            .as_ref()
            .and_then(|r| r.requirements.as_ref())
            .and_then(|r| r.process_closed.as_deref());
        let blocking = plan
            .blocked_process_name
            .clone()
            .or_else(|| ProcessGuard::check_blocking_process(required_closed));
        if plan.is_blocked_by_process || blocking.is_some() {
            result.errors.push(format!(
                "Execution skipped: Required application must be closed ({})",
                blocking.as_deref().unwrap_or("process state unavailable")
            ));
            return result;
        }

        let age = minimum_age(&plan.rule_id);
        let now = SystemTime::now();
        let cancel = AtomicBool::new(false);
        for candidate in plan.candidates.iter().filter(|c| c.is_selected) {
            if is_forbidden_from_cleanup(candidate.safety) {
                result.files_skipped += 1;
                continue;
            }
            if candidate.action == RuleAction::EmptyRecycleBin {
                let path = candidate.path.to_string_lossy();
                if plan.rule_id != "recycle_bin" {
                    result.errors.push("Invalid Recycle Bin action.".into());
                    continue;
                }
                let drive = path
                    .strip_prefix("SPECIAL:RECYCLE_BIN:")
                    .filter(|d| *d != "ALL" && !d.is_empty());
                match empty_recycle_bin(drive) {
                    Ok(_) => {
                        result.files_deleted += candidate.file_count;
                        result.reclaimed_bytes += candidate.size_bytes;
                    }
                    Err(error) => result.errors.push(error.to_string()),
                }
                continue;
            }
            let root = match validate_target_path(&candidate.path, None) {
                Ok(path) => path,
                Err(error) => {
                    result.files_skipped += 1;
                    result
                        .errors
                        .push(format!("Critical Safety Violation: {error}"));
                    continue;
                }
            };
            if plan.requires_admin && !cleaner_platform_windows::elevation::is_elevated() {
                result.files_skipped += 1;
                result
                    .errors
                    .push("This operation requires elevation.".into());
                continue;
            }
            if is_forbidden_from_cleanup(classify_path_safety(&root, candidate.safety)) {
                result.files_skipped += 1;
                continue;
            }

            let mut exclude = candidate.exclude.clone();
            exclude.extend(
                [
                    "AutomaticDestinations",
                    "CustomDestinations",
                    ".git",
                    ".ssh",
                ]
                .map(str::to_owned),
            );
            let pattern = if candidate.action == RuleAction::DeleteFilesMatching {
                candidate.pattern.as_deref()
            } else {
                None
            };
            let issues = walk_regular_files(&root, &exclude, &cancel, |path, preview| {
                if is_active_session_artifact(path)
                    || age.is_some_and(|age| !older_than(preview, age, now))
                    || pattern.is_some_and(|p| {
                        (candidate.is_dir && path.parent() != Some(root.as_path()))
                            || !matches_simple_pattern(
                                &path.file_name().unwrap_or_default().to_string_lossy(),
                                p,
                            )
                    })
                {
                    return;
                }
                let modified = preview.modified().ok();
                let verified = delete_file_checked(path, |live| {
                    live.len() == preview.len()
                        && modified.is_some()
                        && live.modified().ok() == modified
                        && age.is_none_or(|age| older_than(live, age, now))
                });
                match verified {
                    Ok(bytes) => {
                        result.files_deleted += 1;
                        result.reclaimed_bytes += bytes;
                    }
                    Err(error) => {
                        result.files_skipped += 1;
                        if result.errors.len() < 20 {
                            result.errors.push(format!("{}: {}", path.display(), error));
                        }
                    }
                }
            });
            result.files_skipped += issues.skipped;
            result.errors.extend(issues.errors);
        }
        result.duration_ms = start.elapsed().as_millis() as u64;
        result
    }
}

pub fn is_active_session_artifact(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        name.starts_with("scoped_dir")
            || name.starts_with("crashpad")
            || name.starts_with("etilqs_")
            || name.starts_with("singleton")
            || name.starts_with("manifest-")
            || matches!(
                name.as_str(),
                "lock"
                    | "current"
                    | "index"
                    | "data_0"
                    | "data_1"
                    | "data_2"
                    | "data_3"
                    | "gpu_metrics.bin"
                    | "blob_storage"
                    | "automaticdestinations"
                    | "customdestinations"
                    | ".git"
                    | ".ssh"
            )
            || name.ends_with(".sock")
            || name.ends_with(".pipe")
            || name.ends_with(".lock")
    })
}
