#[test]
fn release_rules_exclude_system_servicing_and_drive_root_guesses() {
    let rules = cleaner_core::rules::get_embedded_rules();
    for id in [
        "windows_update",
        "windows_old",
        "drive_junk",
        "device_drivers",
    ] {
        assert!(
            !rules.iter().any(|rule| rule.id == id),
            "{id} must stay out of cleanup"
        );
    }
    assert!(rules.iter().any(|rule| rule.id == "user_temp"));
}

#[test]
fn standalone_file_scan_counts_the_selected_file() {
    use std::sync::{atomic::AtomicBool, Arc};
    let file = std::env::temp_dir().join(format!("bleachsan-test-file-{}", std::process::id()));
    std::fs::write(&file, b"test data").unwrap();
    let stats = cleaner_core::scanner::scan_directory_bounded(
        &file,
        None,
        &[],
        &Arc::new(AtomicBool::new(false)),
        10,
    );
    std::fs::remove_file(file).unwrap();
    assert_eq!(stats.total_bytes, 9);
    assert_eq!(stats.file_count, 1);
}

#[test]
fn open_file_is_skipped_and_can_be_cleaned_after_it_closes() {
    use cleaner_platform_windows::filesystem::delete_file_checked;
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    let path = std::env::temp_dir().join(format!("bleachsan-lock-fixture-{}", std::process::id()));
    std::fs::write(&path, b"preserve me").unwrap();
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    assert!(delete_file_checked(&path, |_| true).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve me");
    drop(handle);
    assert_eq!(delete_file_checked(&path, |_| true).unwrap(), 11);
    assert!(!path.exists());
}
#[test]
fn discovery_shows_project_outputs_without_enabling_cleanup() {
    use cleaner_core::{scanner::scan_with_discovery, SafetyLevel};
    use std::sync::{atomic::AtomicBool, Arc};
    let root = std::env::temp_dir().join(format!(
        "bleachsan-discovery-fixture-{}",
        std::process::id()
    ));
    let output = root.join("project").join(".next").join("server");
    std::fs::create_dir_all(&output).unwrap();
    std::fs::write(output.join("deploy.js"), b"project output").unwrap();
    let plans = scan_with_discovery(&[], root.to_str(), Arc::new(AtomicBool::new(false)));
    std::fs::remove_dir_all(&root).unwrap();
    assert!(!plans.is_empty());
    assert!(plans.iter().all(|p| p.safety == SafetyLevel::Protected
        && !p.is_selected
        && p.candidates.iter().all(|c| !c.is_selected)));
}

#[test]
fn stale_temp_scan_keeps_fresh_files() {
    use cleaner_core::{
        rules::{get_embedded_rules, schema::CleanerRule},
        scanner::ScanWorker,
    };
    use std::{
        fs::{File, FileTimes},
        sync::{atomic::AtomicBool, Arc},
        time::{Duration, SystemTime},
    };
    let root = std::env::temp_dir().join(format!("bleachsan-age-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let old = root.join("old.tmp");
    let fresh = root.join("fresh.tmp");
    std::fs::write(&old, b"old file").unwrap();
    std::fs::write(&fresh, b"fresh file").unwrap();
    let past = SystemTime::now() - Duration::from_secs(8 * 86400);
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_times(FileTimes::new().set_modified(past))
        .unwrap();
    let mut rule: CleanerRule = get_embedded_rules()
        .into_iter()
        .find(|r| r.id == "user_temp")
        .unwrap();
    rule.targets[0].path = root.to_str().map(str::to_owned);
    rule.targets[0].allowed_root = rule.targets[0].path.clone();
    let plan = ScanWorker::scan_rule(&rule, None, None, &Arc::new(AtomicBool::new(false)));
    let result = cleaner_core::cleaner::CleanupExecutor::execute_plan(&plan);
    let old_exists = old.exists();
    let fresh_exists = fresh.exists();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(plan.total_files, 1);
    assert_eq!(result.files_deleted, 1);
    assert!(!old_exists && fresh_exists);
}
