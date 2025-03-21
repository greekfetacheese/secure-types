#[path = "../lib.rs"]
mod lib;

use egui::{self};
use lib::SecureString;

pub struct App {
    pub secret_text: SecureString,
    pub show_msg: bool,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext) -> Self {
        Self {
            secret_text: SecureString::new_with_capacity(1024),
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
                self.secret_text.secure_mut(|text| {
                    let text_edit =
                        egui::TextEdit::singleline(text).min_size(egui::vec2(200.0, 30.0));
                    let output = text_edit.show(ui);

                    // When you are done with the text erase it from memory
                    if ui.button("Erase").clicked() {
                        text.erase();
                        self.show_msg = true;
                        // This just deallocates the text edit state its possible to still leave some residues in memory
                        lib::string::clear_text_edit_state(output);
                    }
                });
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
