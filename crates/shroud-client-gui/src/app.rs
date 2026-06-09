use crate::config_store::{ClientConfigFile, ConfigStore};
use crate::import::{render_imported_client_yaml, unique_import_file_path};
use crate::logs::LogBuffer;
use crate::process::ClientProcess;
use eframe::egui;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct ShroudGuiApp {
    config_store: ConfigStore,
    configs: Vec<ClientConfigFile>,
    selected_config: Option<usize>,
    expanded_config: Option<usize>,
    editor_text: String,
    import_dialog_open: bool,
    import_text: String,
    pending_import_path: String,
    status: String,
    logs: LogBuffer,
    client_process: ClientProcess,
}

impl ShroudGuiApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config_store = ConfigStore::default();
        let (configs, status) = match config_store.discover() {
            Ok(configs) => {
                let status = discovered_configs_status(&configs);
                (configs, status)
            }
            Err(err) => (Vec::new(), err.to_string()),
        };

        Self {
            config_store,
            configs,
            selected_config: None,
            expanded_config: None,
            editor_text: String::new(),
            import_dialog_open: false,
            import_text: String::new(),
            pending_import_path: String::new(),
            status,
            logs: LogBuffer::default(),
            client_process: ClientProcess::default(),
        }
    }

    fn refresh_configs(&mut self) {
        let selected_path = self.selected_config_path();
        self.refresh_configs_with_selection(selected_path.as_deref());
    }

    fn refresh_configs_with_selection(&mut self, selected_path: Option<&Path>) {
        match self.config_store.discover() {
            Ok(configs) => {
                self.configs = configs;
                self.selected_config = selected_path
                    .and_then(|path| self.configs.iter().position(|config| &config.path == path));
                self.expanded_config = None;

                if let Some(index) = self.selected_config {
                    if let Some(config) = self.configs.get(index) {
                        self.editor_text = config.raw_yaml.clone();
                    }
                } else {
                    self.editor_text.clear();
                }

                self.status = discovered_configs_status(&self.configs);
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn selected_config_path(&self) -> Option<PathBuf> {
        self.selected_config
            .and_then(|index| self.configs.get(index))
            .map(|config| config.path.clone())
    }

    fn editing_config_path(&self) -> Option<PathBuf> {
        self.expanded_config
            .and_then(|index| self.configs.get(index))
            .map(|config| config.path.clone())
    }

    fn select_config(&mut self, index: usize) {
        self.selected_config = Some(index);
        let Some(config) = self.configs.get(index) else {
            return;
        };

        self.editor_text = config.raw_yaml.clone();
        self.status = if config.is_valid {
            format!("loaded {}", config.path.display())
        } else {
            format!(
                "loaded invalid {}: {}",
                config.path.display(),
                config
                    .error
                    .as_deref()
                    .unwrap_or("unknown validation error")
            )
        };
    }

    fn save_editing_config(&mut self) {
        let Some(path) = self.editing_config_path() else {
            self.status = "open a config before saving".to_string();
            return;
        };

        match self.config_store.save(&path, &self.editor_text) {
            Ok(()) => {
                self.refresh_configs_with_selection(Some(&path));
                self.expanded_config = None;
                self.status = format!("saved {}", path.display());
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn validate_editor(&mut self) {
        if self.editing_config_path().is_none() {
            self.status = "open a config before validating".to_string();
            return;
        }

        match self.config_store.validate(&self.editor_text) {
            Ok(()) => self.status = "config is valid".to_string(),
            Err(err) => self.status = err.to_string(),
        }
    }

    fn suggest_import_file_name(&mut self) {
        match render_imported_client_yaml(&self.import_text) {
            Ok(imported) => {
                let path = unique_import_file_path(Path::new(&imported.default_file_name));
                self.pending_import_path = path.display().to_string();
                self.status = format!("suggested import file {}", path.display());
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn import_connection(&mut self) -> bool {
        let imported = match render_imported_client_yaml(&self.import_text) {
            Ok(imported) => imported,
            Err(err) => {
                self.status = err.to_string();
                return false;
            }
        };

        let requested_path = if self.pending_import_path.trim().is_empty() {
            PathBuf::from(imported.default_file_name)
        } else {
            PathBuf::from(self.pending_import_path.trim())
        };
        let path = unique_import_file_path(&requested_path);

        match self.config_store.save(&path, &imported.yaml) {
            Ok(()) => {
                self.refresh_configs_with_selection(Some(&path));
                self.status = format!("saved {}", path.display());
                self.pending_import_path = path.display().to_string();
                true
            }
            Err(err) => {
                self.status = err.to_string();
                false
            }
        }
    }

    fn show_import_dialog(&mut self, ctx: &egui::Context) {
        let mut open = self.import_dialog_open;
        let mut should_close = false;

        egui::Window::new("Import Connection")
            .open(&mut open)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label("Paste shrd string:");
                ui.add(
                    egui::TextEdit::multiline(&mut self.import_text)
                        .desired_rows(4)
                        .code_editor(),
                );

                ui.horizontal(|ui| {
                    ui.label("Config filename:");
                    ui.text_edit_singleline(&mut self.pending_import_path);
                });

                ui.horizontal(|ui| {
                    if ui.button("Suggest Filename").clicked() {
                        self.suggest_import_file_name();
                    }
                    if ui.button("Import").clicked() && self.import_connection() {
                        should_close = true;
                    }
                    if ui.button("Cancel").clicked() {
                        should_close = true;
                    }
                });
            });

        if should_close {
            open = false;
        }
        self.import_dialog_open = open;
    }

    fn start_client_config(&mut self, index: usize) {
        if self.expanded_config.is_some() {
            self.status = "collapse the open config before starting".to_string();
            return;
        }

        let Some(config) = self.configs.get(index) else {
            self.status = "config not found".to_string();
            return;
        };

        if !config.is_valid {
            self.status = format!("cannot start invalid config {}", config.path.display());
            return;
        }

        let path = config.path.clone();
        self.select_config(index);

        match self.client_process.start(&path, self.logs.sender()) {
            Ok(()) => {
                self.logs
                    .push(format!("started shroud-client {}", path.display()));
                self.status = "client started".to_string();
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn stop_client(&mut self) {
        match self.client_process.stop() {
            Ok(()) => self.status = "client stopped".to_string(),
            Err(err) => self.status = err.to_string(),
        }
    }

    fn show_config_row(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        is_running: bool,
        running_config_path: Option<&Path>,
    ) {
        let Some(config) = self.configs.get(index) else {
            return;
        };

        let summary = config_summary(config);
        let is_expanded = self.expanded_config == Some(index);
        let is_selected = self.selected_config == Some(index);
        let is_valid = config.is_valid;
        let is_running_config = running_config_path
            .map(|path| path == config.path.as_path())
            .unwrap_or(false);

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                let arrow = if is_expanded { "v" } else { ">" };

                if ui.button(arrow).clicked() {
                    if is_expanded {
                        self.expanded_config = None;
                    } else {
                        self.select_config(index);
                        self.expanded_config = Some(index);
                    }
                }

                let label_response = ui.selectable_label(is_selected, summary);
                if label_response.clicked() {
                    if is_expanded {
                        self.expanded_config = None;
                    } else {
                        self.select_config(index);
                        self.expanded_config = Some(index);
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if is_running_config {
                        if ui.button("Stop").clicked() {
                            self.stop_client();
                        }
                    } else if ui
                        .add_enabled(
                            !is_running && self.expanded_config.is_none() && is_valid,
                            egui::Button::new("Start"),
                        )
                        .clicked()
                    {
                        self.start_client_config(index);
                    }
                });
            });

            if is_expanded {
                ui.separator();

                ui.horizontal(|ui| {
                    if ui.button("Validate").clicked() {
                        self.validate_editor();
                    }

                    if ui.button("Save").clicked() {
                        self.save_editing_config();
                    }

                    if ui.button("Cancel editing").clicked() {
                        self.expanded_config = None;
                        if let Some(config) = self.configs.get(index) {
                            self.editor_text = config.raw_yaml.clone();
                        }
                        self.status = "editing cancelled".to_string();
                    }
                });

                ui.add_sized(
                    [ui.available_width(), 360.0],
                    egui::TextEdit::multiline(&mut self.editor_text)
                        .desired_rows(20)
                        .code_editor()
                        .lock_focus(true),
                );
            }
        });
    }
}

impl eframe::App for ShroudGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let drained_logs = self.logs.drain();
        let is_running = self.client_process.is_running();
        let process_state = self.client_process.state();
        let running_config_path = self.client_process.running_config_path();
        if is_running {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        if drained_logs > 0 {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh_configs();
                }

                if ui.button("Import Connection").clicked() {
                    self.import_dialog_open = true;
                }
            });
        });

        self.show_import_dialog(ctx);

        egui::TopBottomPanel::bottom("status")
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(&self.status);
                    ui.label(format!("client: {}", process_state.label()));
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Shroud Client");
            ui.separator();

            ui.heading("Configs");

            if self.configs.is_empty() {
                ui.label("No client*.yaml files found.");
            }

            egui::ScrollArea::vertical()
                .id_source("configs_main_scroll")
                .auto_shrink([false, false])
                .max_height(ui.available_height() * 0.65)
                .show(ui, |ui| {
                    for index in 0..self.configs.len() {
                        self.show_config_row(ui, index, is_running, running_config_path.as_deref());
                        ui.add_space(6.0);
                    }
                });

            ui.separator();

            ui.heading("Client logs");

            let log_text = self.logs.text();

            egui::ScrollArea::vertical()
                .id_source("client_logs_scroll")
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(ui.available_height())
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(egui::RichText::new(log_text).monospace())
                            .selectable(true),
                    );
                });
        });
    }
}

fn config_summary(config: &ClientConfigFile) -> String {
    let address = yaml_value_by_paths(
        &config.raw_yaml,
        &[
            &["transport", "server"],
            &["server", "host"],
            &["server", "address"],
            &["server_addr"],
            &["endpoint", "host"],
            &["remote", "host"],
        ],
    )
    .unwrap_or_else(|| "-".to_string());

    let port = yaml_value_by_paths(
        &config.raw_yaml,
        &[
            &["transport", "port"],
            &["server", "port"],
            &["port"],
            &["endpoint", "port"],
            &["remote", "port"],
        ],
    )
    .unwrap_or_else(|| "-".to_string());

    let transport = yaml_value_by_paths(
        &config.raw_yaml,
        &[
            &["transport"],
            &["transport", "mode"],
            &["transport_mode"],
            &["mode"],
        ],
    )
    .unwrap_or_else(|| "-".to_string());

    let invalid_suffix = if config.is_valid { "" } else { " (invalid)" };
    format!(
        "{}{} - {} - {} - {}",
        config.display_name, invalid_suffix, address, port, transport
    )
}

fn yaml_value_by_paths(raw_yaml: &str, paths: &[&[&str]]) -> Option<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(raw_yaml).ok()?;

    for path in paths {
        if let Some(value) = yaml_value_at_path(&value, path) {
            if let Some(text) = yaml_scalar_to_string(value) {
                return Some(text);
            }
        }
    }

    None
}

fn yaml_value_at_path<'a>(
    value: &'a serde_yaml::Value,
    path: &[&str],
) -> Option<&'a serde_yaml::Value> {
    let mut current = value;

    for key in path {
        current = current.get(*key)?;
    }

    Some(current)
}

fn yaml_scalar_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn discovered_configs_status(configs: &[ClientConfigFile]) -> String {
    let invalid_count = configs.iter().filter(|config| !config.is_valid).count();
    if invalid_count == 0 {
        format!("found {} client config(s)", configs.len())
    } else {
        format!(
            "found {} client config(s), {} invalid",
            configs.len(),
            invalid_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_config_file(raw_yaml: &str, is_valid: bool) -> ClientConfigFile {
        ClientConfigFile {
            path: PathBuf::from("client-laptop.yaml"),
            display_name: "client-laptop.yaml".to_string(),
            raw_yaml: raw_yaml.to_string(),
            is_valid,
            error: None,
        }
    }

    #[test]
    fn config_summary_reads_transport_server_port_and_mode() {
        let config = client_config_file(
            r#"
transport:
  mode: raw_tcp
  server: 104.20.23.154
  port: 8443
"#,
            true,
        );

        assert_eq!(
            config_summary(&config),
            "client-laptop.yaml - 104.20.23.154 - 8443 - raw_tcp"
        );
    }

    #[test]
    fn config_summary_marks_invalid_configs() {
        let config = client_config_file(
            r#"
transport:
  mode: h2
  server: 1.2.3.4
  port: 8443
"#,
            false,
        );

        assert_eq!(
            config_summary(&config),
            "client-laptop.yaml (invalid) - 1.2.3.4 - 8443 - h2"
        );
    }

    #[test]
    fn refresh_configs_with_selection_clears_expanded_config() {
        let mut app = ShroudGuiApp {
            config_store: ConfigStore::default(),
            configs: Vec::new(),
            selected_config: None,
            expanded_config: Some(0),
            editor_text: "unsaved: true".to_string(),
            import_dialog_open: false,
            import_text: String::new(),
            pending_import_path: String::new(),
            status: String::new(),
            logs: LogBuffer::default(),
            client_process: ClientProcess::default(),
        };

        app.refresh_configs_with_selection(None);

        assert_eq!(app.expanded_config, None);
    }
}
