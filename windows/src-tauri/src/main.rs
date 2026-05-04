#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use log::info;
use tauri::Manager;

fn main() {
    env_logger::init();
    info!("PQ Vault starting...");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::unlock_vault,
            commands::lock_vault,
            commands::create_vault,
            commands::add_entry,
            commands::get_entries,
            commands::generate_password,
            commands::start_sync,
            commands::get_peers,
        ])
        .setup(|app| {
            info!("PQ Vault initialized");

            #[cfg(desktop)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.set_title("PQ Vault - Post-Quantum Password Manager").ok();
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}