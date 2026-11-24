use cleaner_platform_windows::filesystem::{has_reparse_attribute, verify_plain_path};
use glob::{MatchOptions, Pattern};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

#[derive(Default)]
pub struct ScanStats {
    pub total_bytes: u64,
    pub file_count: usize,
    pub items: Vec<PathBuf>,
    pub skipped_entries: usize,
    pub errors: Vec<String>,
}

#[derive(Default)]
pub(crate) struct WalkIssues {
    pub skipped: usize,
    pub errors: Vec<String>,
}

impl WalkIssues {
    fn error(&mut self, path: &Path, error: std::io::Error) {
        self.skipped += 1;
        if self.errors.len() < 3 {
            self.errors.push(format!("{}: {}", path.display(), error));
        }
    }
}

pub(crate) fn matches_exclusion(name: &str, exclude: &[String]) -> bool {
    exclude.iter().any(|pat| matches_simple_pattern(name, pat))
}

pub(crate) fn older_than(meta: &Metadata, age: Duration, now: SystemTime) -> bool {
    meta.modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|elapsed| elapsed >= age)
}

/// Walks each real directory once, reusing Windows directory-entry metadata.
pub(crate) fn walk_regular_files(
    root: &Path,
    exclude: &[String],
    cancel: &AtomicBool,
    mut visit: impl FnMut(&Path, &Metadata),
) -> WalkIssues {
    let mut issues = WalkIssues::default();
    if cancel.load(Ordering::Relaxed) {
        return issues;
    }
    match verify_plain_path(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return issues,
        Err(error) => {
            issues.error(root, error);
            return issues;
        }
    }
    let root_meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) => {
            issues.error(root, error);
            return issues;
        }
    };
    if has_reparse_attribute(&root_meta) {
        issues.skipped += 1;
        return issues;
    }
    if root_meta.is_file() {
        visit(root, &root_meta);
        return issues;
    }

    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                issues.error(&dir, error);
                continue;
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                return issues;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    issues.error(&dir, error);
                    continue;
                }
            };
            let name = entry.file_name();
            if matches_exclusion(&name.to_string_lossy(), exclude) {
                continue;
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    issues.error(&entry.path(), error);
                    continue;
                }
            };
            if has_reparse_attribute(&metadata) {
                issues.skipped += 1;
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                visit(&entry.path(), &metadata);
            }
        }
    }
    issues
}

pub fn scan_directory_bounded(
    dir: &Path,
    pattern: Option<&str>,
    exclude: &[String],
    cancel_flag: &AtomicBool,
    max_items_to_record: usize,
) -> ScanStats {
    scan_with_age(
        dir,
        pattern,
        exclude,
        cancel_flag,
        max_items_to_record,
        None,
        false,
    )
}

pub(crate) fn scan_with_age(
    dir: &Path,
    pattern: Option<&str>,
    exclude: &[String],
    cancel_flag: &AtomicBool,
    max_items_to_record: usize,
    age: Option<Duration>,
    cleaning: bool,
) -> ScanStats {
    let now = SystemTime::now();
    let compiled = pattern.and_then(|pat| Pattern::new(pat).ok());
    let mut stats = ScanStats::default();
    let issues = walk_regular_files(dir, exclude, cancel_flag, |path, meta| {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if matches_exclusion(&name, exclude)
            || pattern.is_some_and(|_| !compiled.as_ref().is_some_and(|p| matches(p, &name)))
            || age.is_some_and(|age| !older_than(meta, age, now))
            || (cleaning && crate::cleaner::is_active_session_artifact(path))
        {
            return;
        }
        stats.total_bytes = stats.total_bytes.saturating_add(meta.len());
        stats.file_count += 1;
        if stats.items.len() < max_items_to_record {
            stats.items.push(path.to_owned());
        }
    });
    stats.skipped_entries = issues.skipped;
    stats.errors = issues.errors;
    stats
}

fn matches(pattern: &Pattern, name: &str) -> bool {
    pattern.matches_with(
        name,
        MatchOptions {
            case_sensitive: false,
            ..MatchOptions::new()
        },
    )
}

pub fn matches_simple_pattern(name: &str, pattern: &str) -> bool {
    Pattern::new(if pattern.is_empty() { "*" } else { pattern })
        .is_ok_and(|pattern| matches(&pattern, name))
}
