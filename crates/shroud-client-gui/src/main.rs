mod app;
mod config_store;
mod import;
mod logs;
mod process;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();

    eframe::run_native(
        "Shroud Client",
        options,
        Box::new(|cc| Ok(Box::new(app::ShroudGuiApp::new(cc)))),
    )
}
