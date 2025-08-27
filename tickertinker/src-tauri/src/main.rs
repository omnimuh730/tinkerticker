// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tickertinker_lib::networking;

fn main() {
    tauri::Builder::default()
        .manage(networking::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![
            networking::start_capture,
            networking::stop_capture,
            networking::get_traffic_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
