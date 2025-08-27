pub mod networking;
pub mod mmdb;
pub mod countries;
pub mod report;
pub mod translations;
pub mod utils;

use tauri::State;
use crate::network_monitor::NetworkMonitorState;
// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String { 
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]

#[tauri::command]
async fn start_capture(
    app_handle: tauri::AppHandle,
    interface_name: String,
    state: State<'_, NetworkMonitorState>,
) -> Result<(), String> {
    crate::network_monitor::start_capture(interface_name, state, app_handle)
}

#[tauri::command]

#[tauri::command]
fn stop_capture(
    state: State<NetworkMonitorState>,
) -> Result<(), String> {
    crate::network_monitor::stop_capture(state)
}

#[tauri::command]

#[tauri::command]
fn get_traffic_data(
    state: State<NetworkMonitorState>,
) -> Result<crate::network_monitor::traffic_data::TrafficData, String> {
    crate::network_monitor::get_traffic_data(state)
}

#[tauri::command]
fn list_interfaces(
    state: State<NetworkMonitorState>,
) -> Result<Vec<String>, String> {
    crate::network_monitor::list_interfaces(state).map(|devices| devices.into_iter().map(|d| d.name).collect())
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
    .manage(crate::network_monitor::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![greet, start_capture, stop_capture, get_traffic_data])
        .run(tauri::generate_context!())
 .expect("error while running tauri application");
}
