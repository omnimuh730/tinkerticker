mod network_monitor;

use tauri::State;
// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn start_capture(
    app_handle: tauri::AppHandle,
    interface_name: String,
) -> Result<(), String> {
 network_monitor::start_capture(interface_name)
}

#[tauri::command]
fn stop_capture() {
 network_monitor::stop_capture()
}

#[tauri::command]
fn get_traffic_data() -> network_monitor::TrafficData {
 network_monitor::get_traffic_data()
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<String>, String> { network_monitor::list_interfaces() }
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(network_monitor::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![greet, start_capture, stop_capture, get_traffic_data])
        .run(tauri::generate_context!())
 .expect("error while running tauri application");
}
