use chatgpt_login_helper::{
    protocol::{self, Envelope},
    server::{self, Event, Pending},
};
use eframe::egui;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
struct App {
    events: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    busy: Arc<AtomicBool>,
    listener: Option<server::Listener>,
    port: String,
    listening_port: Option<u16>,
    pending: Option<Pending>,
    pin: String,
    attempts: u8,
    approved: bool,
    status: String,
    url: Option<String>,
    response: Option<Envelope>,
}
fn theme(ctx: &egui::Context) {
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = egui::Color32::from_rgb(19, 13, 32);
    style.visuals.window_fill = egui::Color32::from_rgb(29, 21, 47);
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(14, 9, 24);
    style.visuals.override_text_color = Some(egui::Color32::from_rgb(235, 226, 255));
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(91, 58, 148);
    style.visuals.hyperlink_color = egui::Color32::from_rgb(193, 165, 255);
    style.visuals.window_corner_radius = egui::CornerRadius::ZERO;
    style.visuals.window_shadow = egui::epaint::Shadow::NONE;
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::ZERO;
        widget.bg_fill = egui::Color32::from_rgb(43, 30, 65);
        widget.weak_bg_fill = widget.bg_fill;
        widget.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(105, 77, 143));
    }
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(70, 47, 105);
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    for font in style.text_styles.values_mut() {
        font.family = egui::FontFamily::Monospace;
    }
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme(&cc.egui_ctx);
        let (tx, events) = mpsc::channel();
        let mut app = Self {
            events,
            tx,
            busy: Arc::new(AtomicBool::new(false)),
            listener: None,
            port: protocol::DEFAULT_PORT.to_string(),
            listening_port: None,
            pending: None,
            pin: String::new(),
            attempts: 0,
            approved: false,
            status: "Ready.".into(),
            url: None,
            response: None,
        };
        app.listen();
        app
    }
    fn listen(&mut self) {
        self.listener = None;
        self.listening_port = None;
        match self
            .port
            .parse::<u16>()
            .map_err(anyhow::Error::from)
            .and_then(|port| {
                server::start(port, self.tx.clone(), self.busy.clone()).map(|l| (port, l))
            }) {
            Ok((port, listener)) => {
                self.listening_port = Some(port);
                self.listener = Some(listener);
                self.status = "Waiting for a website or request file.".into();
            }
            Err(e) => self.status = e.to_string(),
        }
    }
    fn import(&mut self, path: std::path::PathBuf) {
        let result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(
                std::fs::metadata(&path)?.len() <= protocol::LIMIT as u64,
                "Request file too large"
            );
            let raw = protocol::read_package(&std::fs::read(path)?, "request.json")?;
            server::offline(raw, self.tx.clone(), self.busy.clone())
        })();
        if let Err(e) = result {
            self.status = e.to_string();
        }
    }
}
impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Pending(pending) => {
                    self.pending = Some(pending);
                    self.pin.clear();
                    self.attempts = 0;
                    self.approved = false;
                    self.url = None;
                    self.status = "Check the requesting site before continuing.".into();
                }
                Event::Status(status, url) => {
                    self.status = status;
                    self.url = url;
                }
                Event::Finished(result) => {
                    self.pending = None;
                    self.pin.clear();
                    self.url = None;
                    self.approved = false;
                    match result {
                        Ok(Some(response)) => {
                            self.response = Some(response);
                            self.status = "Authorization complete. Save the encrypted response and import it into the requesting page.".into();
                        }
                        Ok(None) => {
                            self.status =
                                "Credentials sent to the paired client. You can close the helper."
                                    .into()
                        }
                        Err(error) => self.status = error,
                    }
                }
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.cancelled.load(Ordering::SeqCst))
        {
            self.pending = None;
        }
        let busy = self.busy.load(Ordering::SeqCst);
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("C H A T G P T   /   L O G I N   H E L P E R").size(18.0).color(egui::Color32::from_rgb(193, 165, 255)));
            ui.label("A local handoff for your ChatGPT plan."); ui.separator();
            ui.horizontal(|ui| {
                ui.label("PORT"); ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.port).desired_width(72.0));
                if ui.add_enabled(!busy, egui::Button::new("Listen")).clicked() { self.listen(); }
                if let Some(port) = self.listening_port { ui.label(format!("127.0.0.1:{port}")); }
            });
            if ui.add_enabled(!busy && self.response.is_none(), egui::Button::new("Open request ZIP…")).clicked()
                && let Some(path) = rfd::FileDialog::new().add_filter("Login request", &["zip"]).pick_file() { self.import(path); }
            if let Some(pending) = &self.pending {
                ui.separator(); ui.label(if pending.origin_verified { "W E B S I T E   R E Q U E S T" } else { "F I L E   R E Q U E S T" });
                ui.heading(&pending.request.app_name); ui.label(egui::RichText::new(&pending.request.origin).strong());
                if !pending.origin_verified { ui.label("The app name and origin above are claims in the file, not browser-verified."); }
                ui.label("Allows this client to use your ChatGPT plan and renew access.");
                ui.label("No email or profile scope. Credentials go to this client; the helper does not save them.");
                if !self.approved {
                    ui.label(format!("Pairing expires in {} s", pending.deadline.saturating_duration_since(Instant::now()).as_secs()));
                    if pending.pin.is_some() {
                        ui.label("Enter the four digits shown on the requesting page:"); ui.add(egui::TextEdit::singleline(&mut self.pin).char_limit(4).desired_width(90.0)); self.pin.retain(|c| c.is_ascii_digit());
                    }
                    if ui.button("Continue with ChatGPT").clicked() {
                        if pending.pin.as_ref().is_none_or(|expected| *expected == self.pin) { let _ = pending.answer.send(true); self.approved = true; self.pin.clear(); }
                        else { self.attempts += 1; self.pin.clear(); self.status = format!("PIN did not match. {} attempts left.", 3 - self.attempts);
                            if self.attempts >= 3 { pending.cancelled.store(true, Ordering::SeqCst); let _ = pending.answer.send(false); }
                        }
                    }
                }
                if ui.button("Cancel request").clicked() { pending.cancelled.store(true, Ordering::SeqCst); let _ = pending.answer.send(false); }
            }
            if let Some(response) = &self.response {
                ui.separator();
                if ui.button("Save encrypted response ZIP…").clicked()
                    && let Some(path) = rfd::FileDialog::new().set_file_name("chatgpt-response.zip").save_file() {
                    let result = serde_json::to_string(response).map_err(anyhow::Error::from).and_then(|json| protocol::package("response.json", &json)).and_then(|bytes| std::fs::write(path, bytes).map_err(Into::into));
                    match result { Ok(()) => { self.response = None; self.status = "Encrypted response saved. Import it into the original client.".into(); }, Err(e) => self.status = e.to_string() }
                }
                if ui.button("Discard encrypted response").clicked() { self.response = None; }
            }
            ui.separator(); ui.label(&self.status); if let Some(url) = &self.url { ui.hyperlink_to("Open OpenAI sign-in", url); }
            ui.add_space(12.0); ui.small("The helper is needed only for sign-in. Your client owns refresh and inference.");
        });
        ctx.request_repaint_after(Duration::from_millis(150));
    }
}
impl Drop for App {
    fn drop(&mut self) {
        if let Some(p) = &self.pending {
            p.cancelled.store(true, Ordering::SeqCst);
        }
    }
}
fn main() -> eframe::Result {
    eframe::run_native(
        "ChatGPT Login Helper",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([660.0, 620.0])
                .with_min_inner_size([480.0, 440.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
