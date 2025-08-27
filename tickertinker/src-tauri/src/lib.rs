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
    state: State<network_monitor::NetworkMonitorState>,
) -> Result<(), String> {
    network_monitor::start_capture(app_handle, state).await
}

#[tauri::command]
async fn stop_capture(state: State<network_monitor::NetworkMonitorState>) -> Result<(), String> {
    network_monitor::stop_capture(state).await
}

#[tauri::command]
async fn get_traffic_data(state: State<network_monitor::NetworkMonitorState>) -> Result<network_monitor::types::info_traffic::InfoTraffic, String> {
    network_monitor::get_traffic_data(state).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(network_monitor::NetworkMonitorState::default())
        .invoke_handler(tauri::generate_handler![greet, start_capture, stop_capture, get_traffic_data])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
