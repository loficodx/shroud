use crate::config_store::{ClientConfigFile, ConfigStore};
use crate::import::{default_import_file_name, render_imported_client_yaml};
use crate::logs::LogBuffer;
use crate::process::ClientProcess;
use eframe::egui;
use std::path::PathBuf;

pub struct ShroudGuiApp {
    config_store: ConfigStore,
    configs: Vec<ClientConfigFile>,
    selected_config: Option<usize>,
    editor_text: String,
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
                let status = format!("found {} client config(s)", configs.len());
                (configs, status)
            }
            Err(err) => (Vec::new(), err.to_string()),
        };

        Self {
            config_store,
            configs,
            selected_config: None,
            editor_text: String::new(),
            import_text: String::new(),
            pending_import_path: String::new(),
            status,
            logs: LogBuffer::default(),
            client_process: ClientProcess::default(),
        }
    }

    fn refresh_configs(&mut self) {
        match self.config_store.discover() {
            Ok(configs) => {
                self.configs = configs;
                if self
                    .selected_config
                    .is_some_and(|selected| selected >= self.configs.len())
                {
                    self.selected_config = None;
                    self.editor_text.clear();
                }
                self.status = format!("found {} client config(s)", self.configs.len());
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn selected_config_path(&self) -> Option<PathBuf> {
        self.selected_config
            .and_then(|index| self.configs.get(index))
            .map(|config| config.path.clone())
    }

    fn select_config(&mut self, index: usize) {
        self.selected_config = Some(index);
        let Some(config) = self.configs.get(index) else {
            return;
        };

        match self.config_store.read_to_string(&config.path) {
            Ok(raw) => {
                self.editor_text = raw;
                self.status = format!("loaded {}", config.path.display());
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn save_selected_config(&mut self) {
        let Some(path) = self.selected_config_path() else {
            self.status = "select a client config before saving".to_string();
            return;
        };

        match self.config_store.save(&path, &self.editor_text) {
            Ok(()) => self.status = format!("saved {}", path.display()),
            Err(err) => self.status = err.to_string(),
        }
    }

    fn validate_editor(&mut self) {
        match self.config_store.validate(&self.editor_text) {
            Ok(()) => self.status = "config is valid".to_string(),
            Err(err) => self.status = err.to_string(),
        }
    }

    fn render_import(&mut self) {
        match render_imported_client_yaml(&self.import_text) {
            Ok((yaml, name)) => {
                self.editor_text = yaml;
                self.pending_import_path = default_import_file_name(name.as_deref());
                self.selected_config = None;
                self.status = format!(
                    "import rendered; save it as {} when ready",
                    self.pending_import_path
                );
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn save_imported_config(&mut self) {
        let path = if self.pending_import_path.trim().is_empty() {
            PathBuf::from(default_import_file_name(None))
        } else {
            PathBuf::from(self.pending_import_path.trim())
        };

        match self.config_store.save(&path, &self.editor_text) {
            Ok(()) => {
                self.status = format!("saved {}", path.display());
                self.refresh_configs();
            }
            Err(err) => self.status = err.to_string(),
        }
    }

    fn start_client(&mut self) {
        let Some(path) = self.selected_config_path() else {
            self.status = "select a saved client config before starting".to_string();
            return;
        };

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
}

impl eframe::App for ShroudGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.logs.drain();
        let is_running = self.client_process.is_running();

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh_configs();
                }

                if ui
                    .add_enabled(self.selected_config.is_some(), egui::Button::new("Save"))
                    .clicked()
                {
                    self.save_selected_config();
                }

                if ui.button("Validate").clicked() {
                    self.validate_editor();
                }

                if ui
                    .add_enabled(!is_running, egui::Button::new("Start"))
                    .clicked()
                {
                    self.start_client();
                }

                if ui
                    .add_enabled(is_running, egui::Button::new("Stop"))
                    .clicked()
                {
                    self.stop_client();
                }
            });
        });

        egui::SidePanel::left("configs")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.heading("Configs");
                ui.separator();

                for index in 0..self.configs.len() {
                    let selected = self.selected_config == Some(index);
                    let label = self.configs[index].label.clone();
                    if ui.selectable_label(selected, label).clicked() {
                        self.select_config(index);
                    }
                }

                if self.configs.is_empty() {
                    ui.label("No client*.yaml files found.");
                }
            });

        egui::TopBottomPanel::bottom("status")
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(&self.status);
                    if is_running {
                        ui.label("client: running");
                    } else {
                        ui.label("client: stopped");
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Shroud Client");
            ui.separator();

            ui.collapsing("Import Connection", |ui| {
                ui.label("Paste a shrd:1:... import string.");
                ui.text_edit_singleline(&mut self.import_text);
                ui.horizontal(|ui| {
                    if ui.button("Render Config").clicked() {
                        self.render_import();
                    }
                    ui.label("Output file:");
                    ui.text_edit_singleline(&mut self.pending_import_path);
                    if ui
                        .add_enabled(
                            !self.editor_text.trim().is_empty(),
                            egui::Button::new("Save Import"),
                        )
                        .clicked()
                    {
                        self.save_imported_config();
                    }
                });
            });

            ui.separator();
            ui.label("Client config YAML");
            ui.add(
                egui::TextEdit::multiline(&mut self.editor_text)
                    .desired_rows(22)
                    .code_editor()
                    .lock_focus(true),
            );

            ui.separator();
            ui.label("Client logs");
            let mut log_text = self.logs.text();
            ui.add(
                egui::TextEdit::multiline(&mut log_text)
                    .desired_rows(8)
                    .code_editor()
                    .interactive(false),
            );
        });
    }
}
