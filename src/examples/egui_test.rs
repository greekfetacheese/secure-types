use egui::{self};
use secure_types::SecureString;

pub struct App {
    pub secret_text: SecureString,
    pub secret_text2: SecureString,
    pub show_msg: bool,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext) -> Self {
        Self {
            secret_text: SecureString::new_with_capacity(1024),
            secret_text2: SecureString::new_with_capacity(1024),
            show_msg: false,
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([320.0, 240.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Dump Test",
        options,
        Box::new(|cc| {
            let app = App::new(&cc);
            Ok(Box::new(app))
        }),
    )
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.spacing_mut().item_spacing.y = 10.0;

                ui.label("Secret Text:");
                self.secret_text.secure_mut(|text| {
                    let text_edit =
                        egui::TextEdit::singleline(text).min_size(egui::vec2(200.0, 30.0));
                    // This just deallocates the text edit state its possible to still leave some residues in memory
                    let mut output = text_edit.show(ui);
                    output.state.clear_undoer();
                });

                ui.separator();

                ui.label("Secret Text 2:");
                self.secret_text2.secure_mut(|text| {
                    let text_edit =
                        egui::TextEdit::singleline(text).min_size(egui::vec2(200.0, 30.0));
                    let mut output = text_edit.show(ui);
                    output.state.clear_undoer();
                });

                // When you are done with the text erase it from memory
                if ui.button("Erase").clicked() {
                    self.secret_text.erase();
                    self.secret_text2.erase();
                    self.show_msg = true;
                }
            });

            if self.show_msg {
                egui::Window::new("Message")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label("The secret text has been erased");
                        ui.label("Take a memory dump now");
                        if ui.button("Ok").clicked() {
                            self.show_msg = false;
                        }
                    });
            }
        });
    }
}
