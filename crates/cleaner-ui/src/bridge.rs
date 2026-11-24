use crate::view_models::{large_junk_to_ui_item, plan_to_ui_item, storage_to_ui_item, AppWindow};
use cleaner_core::cleaner::calculate_total_selected_bytes;
use cleaner_core::format_bytes;
use cleaner_core::models::CleanupPlan;
use cleaner_core::rules::get_embedded_rules;
use cleaner_core::scanner::{scan_all_rules, scan_with_discovery};
use cleaner_core::storage::StorageAnalyzer;
use cleaner_platform_windows::task_scheduler::{
    is_task_registered, register_daily_task, unregister_task,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::env;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct UIState {
    pub plans: Vec<CleanupPlan>,
    pub large_files: Vec<cleaner_core::models::StorageItem>,
    pub cancel_flag: Arc<AtomicBool>,
}

fn get_available_drives() -> Vec<SharedString> {
    let mut drives = Vec::new();
    let sys_drives = cleaner_core::get_system_drives();
    for drive in &sys_drives {
        drives.push(SharedString::from(drive.as_str()));
    }
    if sys_drives.len() > 1 {
        drives.push(SharedString::from("All Drives"));
    }
    drives
}

pub fn setup_ui_bridge(window: &AppWindow) {
    let state = Arc::new(Mutex::new(UIState {
        plans: Vec::new(),
        large_files: Vec::new(),
        cancel_flag: Arc::new(AtomicBool::new(false)),
    }));

    // Initial check for Task Scheduler and Elevation
    let is_scheduled = is_task_registered(None);
    window.set_task_scheduler_enabled(is_scheduled);

    let is_admin = cleaner_platform_windows::elevation::is_elevated();
    window.set_is_admin(is_admin);
    window.set_app_version(env!("CARGO_PKG_VERSION").into());

    window.on_request_elevation(move || {
        let _ = cleaner_platform_windows::elevation::relaunch_as_admin();
    });

    // Disaster Recovery: System Restore Point Creation
    let handle_restore = window.as_weak();
    window.on_request_create_restore_point(move || {
        if let Some(h) = handle_restore.upgrade() {
            h.set_is_creating_restore_point(true);
            h.set_status_message("Creating Windows System Restore Point...".into());
        }

        let handle_worker = handle_restore.clone();
        thread::spawn(move || {
            let result =
                cleaner_platform_windows::create_restore_point("BleachSan Pre-Clean Checkpoint");

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(h) = handle_worker.upgrade() {
                    h.set_is_creating_restore_point(false);
                    match result {
                        Ok(msg) => {
                            h.set_status_message(format!("✅ {}", msg).into());
                        }
                        Err(err) => {
                            h.set_status_message(format!("⚠️ {}", err).into());
                        }
                    }
                }
            });
        });
    });

    // Initial load of rules as empty placeholders
    let rules = get_embedded_rules();
    let initial_plans: Vec<CleanupPlan> = rules
        .iter()
        .map(|r| CleanupPlan {
            rule_id: r.id.clone(),
            rule_name: r.name.clone(),
            category: r.category.clone(),
            description: r.description.clone(),
            candidates: Vec::new(),
            total_bytes: 0,
            total_files: 0,
            safety: r.safety,
            is_selected: false,
            is_blocked_by_process: false,
            blocked_process_name: None,
            requires_admin: r
                .requirements
                .as_ref()
                .and_then(|x| x.requires_admin)
                .unwrap_or(false),
            warnings: Vec::new(),
        })
        .collect();

    let ui_items: Vec<_> = initial_plans.iter().map(plan_to_ui_item).collect();
    window.set_cleaner_items(ModelRc::new(VecModel::from(ui_items)));
    state.lock().unwrap().plans = initial_plans;

    // Set available drives
    let drives = get_available_drives();
    window.set_available_drives(ModelRc::new(VecModel::from(drives)));

    // --- 1. On Request Scan ---
    let state_scan = Arc::clone(&state);
    let handle_scan = window.as_weak();
    window.on_request_scan(move || {
        let (drive_str, discovery) = if let Some(h) = handle_scan.upgrade() {
            if h.get_is_scanning() || h.get_is_cleaning() {
                return;
            }
            h.set_is_scanning(true);
            h.set_status_message("Scanning system & application targets...".into());
            (h.get_selected_drive().to_string(), h.get_discover_extra())
        } else {
            ("C:\\".into(), false)
        };

        let state_worker = Arc::clone(&state_scan);
        let handle_worker = handle_scan.clone();

        thread::spawn(move || {
            let rules = get_embedded_rules();
            let cancel = Arc::new(AtomicBool::new(false));
            state_worker.lock().unwrap().cancel_flag = Arc::clone(&cancel);

            let plans = if discovery {
                scan_with_discovery(&rules, Some(&drive_str), cancel)
            } else {
                scan_all_rules(&rules, Some(&drive_str), None, cancel)
            };
            let total_bytes = calculate_total_selected_bytes(&plans);
            let total_candidates: usize = plans.iter().map(|p| p.candidates.len()).sum();
            let selected_count = plans.iter().filter(|p| p.is_selected).count();

            state_worker.lock().unwrap().plans = plans.clone();

            let mut display_plans: Vec<_> = plans.iter().filter(|p| p.total_files > 0 || !p.warnings.is_empty()).collect();
            display_plans.sort_by_key(|p| std::cmp::Reverse(p.total_bytes));
            let notices: usize = plans.iter().map(|p| p.warnings.len()).sum();
            let ui_items: Vec<_> = display_plans.into_iter().map(plan_to_ui_item).collect();

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(h) = handle_worker.upgrade() {
                    h.set_scanned_drive(drive_str.into());
                    h.set_is_scanning(false);
                    h.set_status_message(format!("Scanned {}. {total_candidates} locations, {notices} notices. Sizes are logical file bytes.", h.get_scanned_drive()).into());
                    h.set_cleaner_items(ModelRc::new(VecModel::from(ui_items)));
                    h.set_reclaimable_space(format_bytes(total_bytes).into());
                    h.set_total_selected_size(format_bytes(total_bytes).into());
                    h.set_total_selected_count(selected_count as i32);
                    h.set_total_candidates_count(total_candidates.to_string().into());
                }
            });
        });
    });

    // --- 2. On Request Clean ---
    let state_clean = Arc::clone(&state);
    let handle_clean = window.as_weak();
    window.on_request_clean(move || {
        let Some(h) = handle_clean.upgrade() else { return };
        let drive_str = h.get_scanned_drive().to_string();
        if drive_str.is_empty() || h.get_selected_drive().as_str() != drive_str || h.get_is_scanning() || h.get_is_cleaning() {
            return;
        }
        h.set_is_cleaning(true);
        h.set_status_message("Cleaning selected locations...".into());

        let state_worker = Arc::clone(&state_clean);
        let handle_worker = handle_clean.clone();

        thread::spawn(move || {
            let plans = {
                let s = state_worker.lock().unwrap();
                s.plans.clone()
            };

            let results = cleaner_core::execute_all_selected(&plans);
            let total_reclaimed: u64 = results.iter().map(|r| r.reclaimed_bytes).sum();

            let skipped: usize = results.iter().map(|r| r.files_skipped).sum();
            let notices: usize = results.iter().map(|r| r.errors.len()).sum();
            let first_error = results.iter().find_map(|r| r.errors.first()).cloned();
            for report in &results {
                for error in &report.errors { tracing::warn!("{error}"); }
            }
            let rules = get_embedded_rules();
            let cancel = Arc::new(AtomicBool::new(false));
            let refreshed_plans = scan_all_rules(&rules, Some(&drive_str), None, cancel);
            let refreshed_total = calculate_total_selected_bytes(&refreshed_plans);
            let refreshed_candidates: usize = refreshed_plans.iter().map(|p| p.candidates.len()).sum();
            let selected_count = refreshed_plans.iter().filter(|p| p.is_selected).count();

            let mut display_plans: Vec<_> = refreshed_plans.clone();
            if !drive_str.starts_with("C:") && !drive_str.eq_ignore_ascii_case("All Drives") {
                let active: Vec<_> = refreshed_plans.iter().filter(|p| p.total_bytes > 0 || p.total_files > 0).cloned().collect();
                if !active.is_empty() {
                    display_plans = active;
                }
            } else {
                display_plans.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
            }

            state_worker.lock().unwrap().plans = refreshed_plans.clone();
            let ui_items: Vec<_> = display_plans.iter().map(plan_to_ui_item).collect();

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(h) = handle_worker.upgrade() {
                    h.set_is_cleaning(false);
                    let detail = first_error.as_deref().unwrap_or("");
                    h.set_status_message(format!("Removed {} of logical file data. {skipped} skipped, {notices} notices. {detail}", format_bytes(total_reclaimed)).into());
                    h.set_cleaner_items(ModelRc::new(VecModel::from(ui_items)));
                    h.set_reclaimable_space(format_bytes(refreshed_total).into());
                    h.set_total_selected_size(format_bytes(refreshed_total).into());
                    h.set_total_selected_count(selected_count as i32);
                    h.set_total_candidates_count(refreshed_candidates.to_string().into());
                    h.set_last_cleaned_time("Just now".into());
                }
            });
        });
    });

    // --- 3. On Toggle Item ---
    let state_toggle = Arc::clone(&state);
    let handle_toggle = window.as_weak();
    window.on_request_toggle_item(move |rule_id, is_checked| {
        let mut s = state_toggle.lock().unwrap();
        if let Some(plan) = s.plans.iter_mut().find(|p| p.rule_id == rule_id.as_str()) {
            if !plan.is_blocked_by_process
                && !cleaner_core::safety::levels::is_forbidden_from_cleanup(plan.safety)
            {
                plan.is_selected = is_checked;
                for c in &mut plan.candidates {
                    c.is_selected = is_checked
                        && !cleaner_core::safety::levels::is_forbidden_from_cleanup(c.safety);
                }
            }
        }

        let total_bytes = calculate_total_selected_bytes(&s.plans);
        let selected_count = s.plans.iter().filter(|p| p.is_selected).count();
        let ui_items: Vec<_> = s.plans.iter().map(plan_to_ui_item).collect();

        if let Some(h) = handle_toggle.upgrade() {
            h.set_cleaner_items(ModelRc::new(VecModel::from(ui_items)));
            h.set_total_selected_size(format_bytes(total_bytes).into());
            h.set_total_selected_count(selected_count as i32);
            h.set_reclaimable_space(format_bytes(total_bytes).into());
        }
    });

    // --- 4. On Request Select All ---
    let state_sel_all = Arc::clone(&state);
    let handle_sel_all = window.as_weak();
    window.on_request_select_all(move |is_checked| {
        let mut s = state_sel_all.lock().unwrap();
        for plan in &mut s.plans {
            if !plan.is_blocked_by_process
                && plan.safety == cleaner_core::SafetyLevel::Safe
                && plan.total_bytes > 0
            {
                plan.is_selected = is_checked;
                for c in &mut plan.candidates {
                    c.is_selected = is_checked
                        && !cleaner_core::safety::levels::is_forbidden_from_cleanup(c.safety);
                }
            }
        }

        let total_bytes = calculate_total_selected_bytes(&s.plans);
        let selected_count = s.plans.iter().filter(|p| p.is_selected).count();
        let ui_items: Vec<_> = s.plans.iter().map(plan_to_ui_item).collect();

        if let Some(h) = handle_sel_all.upgrade() {
            h.set_cleaner_items(ModelRc::new(VecModel::from(ui_items)));
            h.set_total_selected_size(format_bytes(total_bytes).into());
            h.set_total_selected_count(selected_count as i32);
            h.set_reclaimable_space(format_bytes(total_bytes).into());
        }
    });

    // --- 5. On Storage Analysis ---
    let handle_storage = window.as_weak();
    window.on_request_storage_analysis(move || {
        let drive_str = if let Some(h) = handle_storage.upgrade() {
            h.set_is_analyzing(true);
            h.get_selected_drive().to_string()
        } else {
            "C:\\".to_string()
        };

        let handle_worker = handle_storage.clone();
        thread::spawn(move || {
            let cancel = Arc::new(AtomicBool::new(false));
            let roots = if drive_str.eq_ignore_ascii_case("All Drives") {
                cleaner_core::get_system_drives()
            } else {
                vec![drive_str]
            };
            let mut results: Vec<_> = roots
                .iter()
                .flat_map(|root| {
                    StorageAnalyzer::analyze_directory(std::path::Path::new(root), &cancel, 50)
                })
                .collect();
            results.sort_by_key(|item| std::cmp::Reverse(item.size_bytes));
            let ui_items: Vec<_> = results.iter().map(storage_to_ui_item).collect();

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(h) = handle_worker.upgrade() {
                    h.set_is_analyzing(false);
                    h.set_storage_items(ModelRc::new(VecModel::from(ui_items)));
                }
            });
        });
    });

    // --- 6. On Toggle Task Scheduler ---
    let handle_sched = window.as_weak();
    window.on_request_toggle_scheduler(move |enable| {
        let current_exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("bleachsan.exe"));

        if enable {
            let _ = register_daily_task(None, &current_exe, "--scheduled --clean-safe");
        } else {
            let _ = unregister_task(None);
        }

        let status = is_task_registered(None);
        if let Some(h) = handle_sched.upgrade() {
            h.set_task_scheduler_enabled(status);
        }
    });

    // --- 7. On Request Large Scan ---
    let state_large_scan = Arc::clone(&state);
    let handle_large_scan = window.as_weak();
    window.on_request_large_scan(move || {
        let drive_str = if let Some(h) = handle_large_scan.upgrade() {
            h.set_is_large_scanning(true);
            h.set_large_status_message("Scanning for large junk files...".into());
            h.get_selected_drive().to_string()
        } else {
            "C:\\".to_string()
        };

        let state_worker = Arc::clone(&state_large_scan);
        let handle_worker = handle_large_scan.clone();

        thread::spawn(move || {
            let cancel = Arc::new(AtomicBool::new(false));
            state_worker.lock().unwrap().cancel_flag = Arc::clone(&cancel);

            let results = StorageAnalyzer::analyze_large_junk_files(&cancel, &drive_str);
            state_worker.lock().unwrap().large_files = results.clone();

            let ui_items: Vec<_> = results.iter().map(large_junk_to_ui_item).collect();

            let _ = slint::invoke_from_event_loop(move || {
                if let Some(h) = handle_worker.upgrade() {
                    h.set_is_large_scanning(false);
                    h.set_large_status_message("Scan complete.".into());
                    h.set_large_file_items(ModelRc::new(VecModel::from(ui_items)));
                }
            });
        });
    });

    let state_open = Arc::clone(&state);
    window.on_request_open_location(move |id| {
        let path = state_open
            .lock()
            .unwrap()
            .large_files
            .iter()
            .find(|item| item.path.to_string_lossy() == id.as_str())
            .map(|item| item.path.clone());
        if let Some(path) = path.filter(|p| p.exists()) {
            let _ = std::process::Command::new("explorer.exe")
                .arg(format!("/select,{}", path.display()))
                .spawn();
        }
    });
}
