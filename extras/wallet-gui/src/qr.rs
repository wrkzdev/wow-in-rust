//! An address as a QR code, drawn with egui's own painter: no image crates,
//! and nothing to load.

use egui::{Color32, Rect, Sense, Ui, Vec2};
use qrcodegen::{QrCode, QrCodeEcc};

/// Modules of blank border on each side, which a scanner needs to find the
/// code.
const QUIET: i32 = 4;

/// Draw `text` as a QR code about `size` points across: black on white, with
/// its quiet zone, whatever the theme, since scanners read dark on light.
/// Nothing is drawn for text too long to encode.
pub fn show(ui: &mut Ui, text: &str, size: f32) -> Option<egui::Response> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let modules = code.size();
    let cells = modules + 2 * QUIET;
    // Whole points to a module, so neighbouring modules meet without a seam.
    let cell = (size / cells as f32).floor().max(2.0);
    let side = cell * cells as f32;
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(side), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, Color32::WHITE);
    for y in 0..modules {
        for x in 0..modules {
            if code.get_module(x, y) {
                let min = rect.min
                    + Vec2::new((x + QUIET) as f32 * cell, (y + QUIET) as f32 * cell);
                painter.rect_filled(
                    Rect::from_min_size(min, Vec2::splat(cell)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }
    Some(response)
}
