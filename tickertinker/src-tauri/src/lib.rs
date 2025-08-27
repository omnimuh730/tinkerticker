mod networking;

use tauri::State;
use networking::NetworkMonitorState;
// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String { 
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn start_capture(
    app_handle: tauri::AppHandle,
    interface_name: String,
 state: State<'_, NetworkMonitorState>,
) -> Result<(), String> {
 networking::start_capture(interface_name, state, app_handle)
}

#[tauri::command]
fn stop_capture(
    state: State<NetworkMonitorState>,
) -> Result<(), String> {
 networking::stop_capture(state)
}

#[tauri::command]
fn get_traffic_data(
    state: State<NetworkMonitorState>,
) -> Result<networking::TrafficData, String> {
 networking::get_traffic_data(state)
}

#[tauri::command]
fn list_interfaces(
    state: State<NetworkMonitorState>,
) -> Result<Vec<String>, String> { networking::list_interfaces(state).map(|devices| devices.into_iter().map(|d| d.name).collect()) }
#[cfg_attr(mobile, tauri::mobile_entry_point)]

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(networking::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![greet, start_capture, stop_capture, get_traffic_data])
        .run(tauri::generate_context!())
 .expect("error while running tauri application");
}
