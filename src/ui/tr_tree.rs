//! Traduction de TOUT ce qui est affiché : parcourt périodiquement les widgets de chaque fenêtre et traduit les textes
//! (étiquettes, boutons, cases, info-bulles, champs de saisie). Couvre ainsi les phrases construites dynamiquement.
//! En français, ne fait que résoudre les accords (singulier/pluriel). Les sorties brutes des outils (zones de texte) ne sont jamais modifiées.

use crate::i18n::tr;
use gtk::{glib, prelude::*};
use gtk4 as gtk;

pub fn install() {
    glib::timeout_add_local(std::time::Duration::from_millis(120), || {
        for w in gtk::Window::list_toplevels() {
            sweep(&w);
        }
        glib::ControlFlow::Continue
    });
}

fn fix(old: &str) -> Option<String> {
    let new = tr(old);
    (new != old).then_some(new)
}

thread_local! {
    /// Évite qu'une traduction déclenche elle-même une nouvelle traduction.
    static BUSY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Marque (par une classe CSS) les étiquettes déjà surveillées.
const HOOKED: &str = "tr-hooked";

/// Traduit une étiquette AU MOMENT où son texte change : sans cela, un texte recalculé en français (rafraîchissement périodique)
/// resterait visible jusqu'au prochain passage du balayage (clignotement).
fn hook(l: &gtk::Label) {
    if l.has_css_class(HOOKED) {
        return;
    }
    l.add_css_class(HOOKED);
    l.connect_notify_local(Some("label"), |l, _| {
        if BUSY.with(|b| b.replace(true)) {
            return;
        }
        if let Some(n) = fix(&l.text()) {
            l.set_text(&n);
        }
        BUSY.with(|b| b.set(false));
    });
}

fn sweep(w: &gtk::Widget) {
    if let Some(l) = w.downcast_ref::<gtk::Label>() {
        hook(l);
        if let Some(n) = fix(&l.text()) {
            l.set_text(&n);
        }

    } else if let Some(b) = w.downcast_ref::<gtk::Button>() {
        if let Some(n) = b.label().and_then(|t| fix(&t)) {
            b.set_label(&n);
        }
    } else if let Some(c) = w.downcast_ref::<gtk::CheckButton>() {
        if let Some(n) = c.label().and_then(|t| fix(&t)) {
            c.set_label(Some(&n));
        }
    } else if let Some(e) = w.downcast_ref::<gtk::Entry>() {
        if let Some(n) = e.placeholder_text().and_then(|t| fix(&t)) {
            e.set_placeholder_text(Some(&n));
        }
    } else if let Some(e) = w.downcast_ref::<gtk::SearchEntry>() {
        if let Some(n) = e.placeholder_text().and_then(|t| fix(&t)) {
            e.set_placeholder_text(Some(&n));
        }
    }
    if let Some(n) = w.tooltip_text().and_then(|t| fix(&t)) {
        w.set_tooltip_text(Some(&n));
    }
    let mut child = w.first_child();
    while let Some(c) = child {
        sweep(&c);
        child = c.next_sibling();
    }
}
