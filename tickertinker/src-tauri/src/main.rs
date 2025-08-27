// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tickertinker_lib::network_monitor;

fn main() {
    tauri::Builder::default()
        .manage(network_monitor::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![
            network_monitor::start_capture,
            network_monitor::stop_capture,
            network_monitor::get_traffic_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
