use crate::{
    models::StorageItem,
    scanner::{get_system_drives, scan_directory_bounded, stream::walk_regular_files},
};
use cleaner_platform_windows::filesystem::{has_reparse_attribute, verify_plain_path};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub struct StorageAnalyzer;

impl StorageAnalyzer {
    /// Estimates logical file lengths for immediate volume entries.
    pub fn analyze_directory(
        root: &Path,
        cancel: &Arc<AtomicBool>,
        limit: usize,
    ) -> Vec<StorageItem> {
        if verify_plain_path(root).is_err() {
            return Vec::new();
        }
        let Ok(entries) = fs::read_dir(root) else {
            return Vec::new();
        };
        let entries: Vec<_> = entries.flatten().collect();
        let visit = |entry: fs::DirEntry| {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            let meta = entry.metadata().ok()?;
            if has_reparse_attribute(&meta) {
                return None;
            }
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let (size_bytes, child_count, category) = if meta.is_dir() {
                let stats = scan_directory_bounded(&path, None, &[], cancel, 0);
                let category = if stats.skipped_entries > 0 {
                    format!("Partial · {} skipped", stats.skipped_entries)
                } else {
                    "Folder".into()
                };
                (stats.total_bytes, stats.file_count, category)
            } else {
                (meta.len(), 0, file_category(&path))
            };
            Some(StorageItem {
                path,
                name,
                size_bytes,
                is_dir: meta.is_dir(),
                child_count,
                category,
                is_selected: false,
            })
        };
        let mut items: Vec<_> =
            if let Ok(pool) = rayon::ThreadPoolBuilder::new().num_threads(2).build() {
                pool.install(|| entries.into_par_iter().filter_map(visit).collect())
            } else {
                entries.into_iter().filter_map(visit).collect()
            };
        items.sort_by_key(|item| Reverse(item.size_bytes));
        items.truncate(limit);
        items
    }

    /// Keeps the largest 100 readable files without retaining the full volume inventory.
    pub fn analyze_large_junk_files(cancel: &Arc<AtomicBool>, drive: &str) -> Vec<StorageItem> {
        let drives = if drive.eq_ignore_ascii_case("All Drives") {
            get_system_drives()
        } else {
            vec![drive.to_owned()]
        };
        let mut largest = BinaryHeap::<Reverse<(u64, PathBuf)>>::new();
        for drive in drives {
            walk_regular_files(Path::new(&drive), &[], cancel, |path, meta| {
                let size = meta.len();
                if size < 50 * 1024 * 1024 {
                    return;
                }
                if largest.len() == 100 {
                    if largest.peek().is_some_and(|min| size <= min.0 .0) {
                        return;
                    }
                    largest.pop();
                }
                largest.push(Reverse((size, path.to_owned())));
            });
        }
        largest
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((size_bytes, path))| {
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let category = file_category(&path);
                StorageItem {
                    path,
                    name,
                    size_bytes,
                    category,
                    is_dir: false,
                    child_count: 0,
                    is_selected: false,
                }
            })
            .collect()
    }
}

fn file_category(path: &Path) -> String {
    let extension = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    match extension.as_str() {
        "exe" | "msi" | "dll" => "Binary",
        "zip" | "tar" | "7z" | "rar" => "Archive",
        "mp4" | "mkv" | "png" | "wav" => "Media",
        "vhd" | "vhdx" | "vdi" => "Virtual disk",
        _ => "File",
    }
    .into()
}
