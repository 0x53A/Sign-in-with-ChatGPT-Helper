//! GUI and admission control. One selected login owns the result screen until Close.
#![forbid(unsafe_code)]

use chatgpt_login_helper::{
    protocol, proxy,
    server::{self, Delivery, Event, Pending},
};
use eframe::egui;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
struct Row {
    pending: Pending,
    pin: String,
    attempts: u8,
}
struct ProxyRow {
    pending: proxy::Pending,
    approved: bool,
}
struct App {
    events: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,
    busy: Arc<AtomicBool>,
    listener: Option<server::Listener>,
    port: String,
    listening_port: Option<u16>,
    allow: bool,
    requests: Vec<Row>,
    proxies: Vec<ProxyRow>,
    active: Option<u64>,
    cancelled: Option<Arc<AtomicBool>>,
    result: Option<Result<Delivery, String>>,
    status: String,
    url: Option<String>,
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
        widget.expansion = 0.0;
        widget.bg_fill = egui::Color32::from_rgb(43, 30, 65);
        widget.weak_bg_fill = widget.bg_fill;
        widget.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(105, 77, 143));
    }
    let accent = egui::Color32::from_rgb(193, 165, 255);
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent);
    let pressed = &mut style.visuals.widgets.active;
    pressed.bg_fill = egui::Color32::from_rgb(70, 47, 105);
    pressed.weak_bg_fill = pressed.bg_fill;
    pressed.bg_stroke = egui::Stroke::new(1.0, accent);
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(12.0, 8.0);
    for font in style.text_styles.values_mut() {
        font.family = egui::FontFamily::Monospace;
    }
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_style_of(egui::Theme::Dark, style);
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, port: u16) -> Self {
        theme(&cc.egui_ctx);
        let mut app = Self::idle();
        app.port = port.to_string();
        app.listen();
        app
    }
    fn idle() -> Self {
        let (tx, events) = mpsc::channel();
        Self {
            events,
            tx,
            busy: Arc::new(AtomicBool::new(false)),
            listener: None,
            port: protocol::DEFAULT_PORT.to_string(),
            listening_port: None,
            allow: true,
            requests: Vec::new(),
            proxies: Vec::new(),
            active: None,
            cancelled: None,
            result: None,
            status: String::new(),
            url: None,
        }
    }
    fn receive(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Proxy(pending) => {
                    if self.active.is_some() || !self.allow {
                        pending.session.stop();
                    } else {
                        self.proxies.push(ProxyRow {
                            pending,
                            approved: false,
                        });
                    }
                }
                Event::Pending(p) => {
                    if self.active.is_some() || !self.allow {
                        reject(&p);
                    } else {
                        self.requests.push(Row {
                            pending: p,
                            pin: String::new(),
                            attempts: 0,
                        });
                    }
                }
                Event::Status(id, status, url) if self.active == Some(id) => {
                    self.status = status;
                    self.url = url;
                }
                Event::Finished(id, result) => {
                    self.requests.retain(|r| r.pending.id != id);
                    if self.active == Some(id) {
                        self.result = Some(result);
                        self.url = None;
                        self.status.clear();
                    }
                }
                _ => (),
            }
        }
    }
    fn reject_all(&mut self) {
        for row in &self.proxies {
            if !row.approved {
                row.pending.session.stop();
            }
        }
        for row in self.requests.drain(..) {
            reject(&row.pending);
        }
    }
    fn listen(&mut self) {
        for row in self.proxies.drain(..) {
            row.pending.session.stop();
        }
        self.listener = None;
        self.listening_port = None;
        self.reject_all();
        if !self.allow {
            return;
        }
        match self
            .port
            .parse::<u16>()
            .map_err(anyhow::Error::from)
            .and_then(|port| server::start(port, self.tx.clone(), self.busy.clone()))
        {
            Ok(listener) => {
                self.listening_port = self.port.parse().ok();
                self.listener = Some(listener);
                self.status.clear();
            }
            Err(e) => {
                self.allow = false;
                self.status = e.to_string();
            }
        }
    }
    fn accept(&mut self, index: usize) {
        let row = &mut self.requests[index];
        if row.pending.pin != row.pin {
            row.pin.clear();
            row.attempts += 1;
            self.status = "Incorrect PIN.".into();
            if row.attempts >= 3 {
                reject(&row.pending);
                self.requests.remove(index);
            }
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        let row = self.requests.remove(index);
        self.active = Some(row.pending.id);
        self.cancelled = Some(row.pending.cancelled.clone());
        self.reject_all();
        self.status = "Signing in…".into();
        let _ = row.pending.answer.send(true);
    }
    fn import(&mut self, path: std::path::PathBuf) {
        let result = (|| -> anyhow::Result<String> {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(protocol::LIMIT as u64 + 1)
                .read_to_end(&mut bytes)?;
            let raw = protocol::read_package(&bytes, "request.json")?;
            protocol::Request::parse(&raw)?;
            Ok(raw)
        })();
        match result {
            Ok(raw) => {
                self.busy.store(true, Ordering::SeqCst);
                self.reject_all();
                let cancelled = Arc::new(AtomicBool::new(false));
                match server::offline(raw, self.tx.clone(), cancelled.clone()) {
                    Ok(id) => {
                        self.active = Some(id);
                        self.cancelled = Some(cancelled);
                        self.status = "Signing in…".into();
                    }
                    Err(e) => {
                        self.busy.store(false, Ordering::SeqCst);
                        self.status = e.to_string();
                    }
                }
            }
            Err(e) => self.status = e.to_string(),
        }
    }
    fn close_result(&mut self) {
        self.active = None;
        self.cancelled = None;
        self.result = None;
        self.url = None;
        self.status.clear();
        self.busy.store(false, Ordering::SeqCst);
    }
    fn save(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("chatgpt-response.zip")
            .save_file()
            && let Some(Ok(Delivery::Offline(response))) = &self.result
        {
            let result = serde_json::to_string(response)
                .map_err(anyhow::Error::from)
                .and_then(|json| protocol::package("response.json", &json))
                .and_then(|bytes| std::fs::write(path, bytes).map_err(Into::into));
            self.status = match result {
                Ok(()) => "Result saved.".into(),
                Err(e) => e.to_string(),
            };
        }
    }
    fn content(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Login with OpenAI").strong().size(25.0));
            ui.label(
                egui::RichText::new("HELPER")
                    .size(14.0)
                    .color(egui::Color32::from_rgb(193, 165, 255)),
            );
        });
        ui.add_space(28.0);
        if self.active.is_some() {
            ui.heading(match &self.result {
                Some(Ok(_)) => "Signed in",
                Some(Err(_)) => "Sign-in failed",
                None => "Signing in…",
            });
            ui.add_space(16.0);
            if let Some(result) = &self.result {
                if let Err(error) = result {
                    ui.label(error);
                }
                if !self.status.is_empty() {
                    ui.label(&self.status);
                }
                let offline = matches!(result, Ok(Delivery::Offline(_)));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if offline && ui.button("Save result").clicked() {
                        self.save();
                    }
                    if ui.button("Close").clicked() {
                        self.close_result();
                    }
                });
            } else if let Some(url) = &self.url {
                if ui.button("Open in Browser").clicked() {
                    self.status = match webbrowser::open(url) {
                        Ok(()) => String::new(),
                        Err(_) => "Could not open browser. Copy the link instead.".into(),
                    };
                }
                if ui.button("Copy Link to Clipboard").clicked() {
                    ui.ctx().copy_text(url.clone());
                    self.status = "Link copied.".into();
                }
                if !self.status.is_empty() {
                    ui.label(&self.status);
                }
            }
            self.proxy_list(ui);
            return;
        }
        ui.horizontal(|ui| {
            let changed = ui.checkbox(&mut self.allow, "").changed();
            let port = ui.add(
                egui::TextEdit::singleline(&mut self.port)
                    .desired_width(66.0)
                    .char_limit(5),
            );
            let port_changed = port.lost_focus();
            ui.label("Allow Connections");
            if changed
                || (port_changed
                    && self.allow
                    && self.port.parse::<u16>().ok() != self.listening_port)
            {
                self.listen();
            }
        });
        ui.add_space(8.0);
        if ui.button("Import").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("Login request", &["zip"])
                .pick_file()
        {
            self.import(path);
        }
        ui.add_space(20.0);
        ui.separator();
        ui.add_space(20.0);
        let mut accept = None;
        if self.requests.is_empty() {
            ui.weak("No incoming requests");
        }
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .show(ui, |ui| {
                for (index, row) in self.requests.iter_mut().enumerate() {
                    ui.push_id(row.pending.id, |ui| {
                        ui.horizontal(|ui| {
                            let width = (ui.available_width() - 130.0).max(100.0);
                            ui.allocate_ui_with_layout(
                                egui::vec2(width, 44.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(&row.pending.request.app_name).strong(),
                                    );
                                    ui.add(egui::Label::new(&row.pending.request.origin).wrap());
                                },
                            );
                            let field = ui.add(
                                egui::TextEdit::singleline(&mut row.pin)
                                    .hint_text("PIN")
                                    .char_limit(4)
                                    .desired_width(55.0),
                            );
                            row.pin.retain(|c| c.is_ascii_digit());
                            if ui.button("→").clicked()
                                || (field.lost_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            {
                                accept = Some(index);
                            }
                        });
                        ui.add_space(16.0);
                    });
                }
            });
        if let Some(index) = accept {
            self.accept(index);
        }
        self.proxy_list(ui);
        if !self.status.is_empty() {
            ui.add_space(16.0);
            ui.label(&self.status);
        }
    }
    fn proxy_list(&mut self, ui: &mut egui::Ui) {
        self.proxies
            .retain(|r| !r.pending.session.stopped.load(Ordering::SeqCst));
        if self.proxies.is_empty() {
            return;
        }
        ui.add_space(16.0);
        ui.separator();
        ui.label("Proxy sessions");
        egui::ScrollArea::vertical()
            .id_salt("proxies")
            .max_height(180.0)
            .show(ui, |ui| {
                for row in &mut self.proxies {
                    ui.push_id(row.pending.session.id, |ui| {
                        ui.label(&row.pending.session.origin);
                        ui.horizontal(|ui| {
                            let mut limited = row.pending.session.limited.load(Ordering::SeqCst);
                            if ui
                                .checkbox(&mut limited, "Rate limit")
                                .on_hover_text("30 requests/minute, two at a time")
                                .changed()
                            {
                                row.pending.session.limited.store(limited, Ordering::SeqCst);
                            }
                            if row.approved {
                                ui.weak(format!(
                                    "{} requests",
                                    row.pending.session.requests.load(Ordering::SeqCst)
                                ));
                                if ui.button("Stop").clicked() {
                                    row.pending.session.stop();
                                }
                            } else {
                                if ui
                                    .add_enabled(
                                        self.active.is_none(),
                                        egui::Button::new("Approve"),
                                    )
                                    .clicked()
                                {
                                    row.approved = row.pending.answer.send(true).is_ok();
                                }
                                if ui.button("Reject").clicked() {
                                    row.pending.session.stop();
                                }
                            }
                        });
                        ui.add_space(8.0);
                    });
                }
            });
    }
}
fn reject(p: &Pending) {
    p.cancelled.store(true, Ordering::SeqCst);
    let _ = p.answer.send(false);
}
impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        self.receive();
        self.requests
            .retain(|r| !r.pending.cancelled.load(Ordering::SeqCst));
        egui::CentralPanel::default().show(root, |ui| {
            let width = 480.0_f32.min(ui.available_width() - 32.0);
            let height = if self.active.is_some() {
                240.0 + if self.proxies.is_empty() { 0.0 } else { 150.0 }
            } else {
                (250.0 + self.requests.len() as f32 * 72.0 + self.proxies.len() as f32 * 80.0)
                    .min(530.0)
            };
            let top = ((ui.available_height() - height) / 2.0).max(24.0);
            ui.add_space(top);
            let remaining_height = ui.available_height();
            ui.horizontal(|ui| {
                ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                ui.allocate_ui_with_layout(
                    egui::vec2(width, remaining_height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("content")
                            .max_height(ui.available_height())
                            .show(ui, |ui| self.content(ui));
                    },
                );
            });
        });
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}
impl Drop for App {
    fn drop(&mut self) {
        for row in &self.proxies {
            row.pending.session.stop();
        }
        self.reject_all();
        if let Some(cancelled) = &self.cancelled {
            cancelled.store(true, Ordering::SeqCst);
        }
    }
}
fn main() -> eframe::Result {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let port = match args.as_slice() {
        [] => Some(protocol::DEFAULT_PORT),
        [flag, value] if flag == "--port" => value.parse::<u16>().ok().filter(|p| *p != 0),
        _ => None,
    };
    let Some(port) = port else {
        eprintln!("Usage: chatgpt-login-helper [--port 1..65535]");
        std::process::exit(2);
    };
    eframe::run_native(
        "Login with OpenAI — Helper",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([720.0, 560.0])
                .with_min_inner_size([540.0, 440.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(App::new(cc, port)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn incoming(id: u64) -> (Pending, mpsc::Receiver<bool>) {
        let (answer, receiver) = mpsc::channel();
        let request = protocol::Request {
            version: 2,
            request_id: protocol::random().unwrap(),
            app_name: "Test app".into(),
            origin: "https://example.org".into(),
            host_id: "test".into(),
            client_id: None,
            expires_at: protocol::now() + 120,
            scopes: vec![],
            public_key: protocol::PublicKey {
                kty: "RSA".into(),
                n: String::new(),
                e: String::new(),
            },
        };
        (
            Pending {
                id,
                request,
                pin: "1234".into(),
                answer,
                cancelled: Arc::new(AtomicBool::new(false)),
            },
            receiver,
        )
    }
    #[test]
    fn selecting_one_rejects_others_and_keeps_gate_closed_until_result_closed() {
        let mut app = App::idle();
        let (first, first_answer) = incoming(1);
        let (second, second_answer) = incoming(2);
        app.tx.send(Event::Pending(first)).unwrap();
        app.tx.send(Event::Pending(second)).unwrap();
        app.receive();
        assert_eq!(app.requests.len(), 2);
        app.requests[0].pin = "1234".into();
        app.accept(0);
        assert!(first_answer.recv().unwrap());
        assert!(!second_answer.recv().unwrap());
        assert!(app.busy.load(Ordering::SeqCst));
        let (late, late_answer) = incoming(3);
        app.tx.send(Event::Pending(late)).unwrap();
        app.tx
            .send(Event::Finished(2, Err("Rejected".into())))
            .unwrap();
        app.receive();
        assert!(!late_answer.recv().unwrap());
        assert_eq!(app.active, Some(1));
        assert!(app.result.is_none());
        app.tx
            .send(Event::Finished(1, Ok(Delivery::Online)))
            .unwrap();
        app.receive();
        assert!(matches!(app.result, Some(Ok(Delivery::Online))));
        assert!(app.busy.load(Ordering::SeqCst));
        app.close_result();
        assert!(!app.busy.load(Ordering::SeqCst));
        assert!(app.active.is_none());
    }
    #[test]
    fn three_wrong_pins_reject_only_that_request() {
        let mut app = App::idle();
        let (first, first_answer) = incoming(1);
        let (second, second_answer) = incoming(2);
        app.tx.send(Event::Pending(first)).unwrap();
        app.tx.send(Event::Pending(second)).unwrap();
        app.receive();
        for _ in 0..3 {
            app.accept(0);
        }
        assert!(!first_answer.recv().unwrap());
        assert!(second_answer.try_recv().is_err());
        assert_eq!(app.requests.len(), 1);
        assert!(!app.busy.load(Ordering::SeqCst));
    }
    #[test]
    fn disabled_listener_rejects_late_pending_events() {
        let mut app = App::idle();
        app.allow = false;
        let (pending, answer) = incoming(1);
        app.tx.send(Event::Pending(pending)).unwrap();
        app.receive();
        assert!(!answer.recv().unwrap());
        assert!(app.requests.is_empty());
    }
}
