#![allow(dead_code, clippy::enum_variant_names, clippy::module_inception)]

use std::{collections::BTreeMap, sync::{Arc, Mutex}};

use pcap::{Device, Packet};
use tauri::{AppHandle, Manager, State};
use std::time::Instant;

mod capture;
mod traffic_analyzer;
mod traffic_data;

use traffic_analyzer::TrafficAnalyzer;
use traffic_data::{TrafficChartData, TrafficData};

#[derive(Default)]
pub struct NetworkMonitorState {
    capture_thread: Arc<Mutex<Option<capture::CaptureThread>>>,
    traffic_analyzer: Arc<Mutex<TrafficAnalyzer>>,
}

impl NetworkMonitorState {
    pub fn start_capture(&self, device_name: &str, app_handle: AppHandle) -> Result<(), String> {
        let mut capture_thread = self.capture_thread.lock().unwrap();
        if capture_thread.is_some() {
            return Err("Capture already in progress".into());
        }

        let device = Device::list().unwrap().into_iter()
            .find(|d| d.name == device_name)
            .ok_or_else(|| format!("Device not found: {}", device_name))?;

        let (sender, receiver) = std::sync::mpsc::channel::<Packet>();

        let analyzer = self.traffic_analyzer.clone();
        let app_handle_clone = app_handle.clone();

        let thread = capture::CaptureThread::new(
            device,
            sender,
            analyzer,
            app_handle_clone,
        );

        *capture_thread = Some(thread);
        Ok(())
    }

    pub fn stop_capture(&self) -> Result<(), String> {
        let mut capture_thread = self.capture_thread.lock().unwrap();
        if let Some(thread) = capture_thread.take() {
            thread.stop();
            Ok(())
        } else {
            Err("No capture in progress".into())
        }
    }

    pub fn get_traffic_data(&self) -> Result<TrafficData, String> {
        let analyzer = self.traffic_analyzer.lock().unwrap();
        Ok(analyzer.get_traffic_data())
    }

    pub fn list_interfaces(&self) -> Result<Vec<Device>, String> {
        Device::list().map_err(|e| e.to_string())
    }
}

// Tauri commands

#[tauri::command]
fn list_interfaces(state: State<NetworkMonitorState>) -> Result<Vec<Device>, String> {
    state.list_interfaces()
}

#[tauri::command]
fn start_capture(device_name: String, state: State<NetworkMonitorState>, app_handle: AppHandle) -> Result<(), String> {
    state.start_capture(&device_name, app_handle)
}

#[tauri::command]
fn stop_capture(state: State<NetworkMonitorState>) -> Result<(), String> {
    state.stop_capture()
}

#[tauri::command]
fn get_traffic_data(state: State<NetworkMonitorState>) -> Result<TrafficData, String> {
    state.get_traffic_data()
}
