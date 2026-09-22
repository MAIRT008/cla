#![windows_subsystem = "windows"]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("nsis warmup app failed to start");
}
