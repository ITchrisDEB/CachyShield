//! Panneau d'options généré à partir des définitions déclaratives des outils.

use crate::tools::{Choices, Def, Kind, OptDef, Val, Values};
use gtk4 as gtk;
use gtk::{gio, prelude::*};
use std::rc::Rc;

pub struct Panel {
    pub root: gtk::Box,
    getters: Vec<(&'static str, Box<dyn Fn() -> Val>)>,
    combos: Vec<(&'static str, gtk::DropDown, Choices)>,
    entries: Vec<(&'static str, gtk::Entry)>,
}

fn def_str(d: Def) -> String {
    match d {
        Def::S(s) => s.to_string(),
        Def::Dyn(f) => f(),
        _ => String::new(),
    }
}

impl Panel {
    pub fn new(defs: &[OptDef], on_change: Rc<dyn Fn()>) -> Panel {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.set_margin_start(6);
        root.set_margin_end(12);
        root.set_margin_top(6);
        root.set_margin_bottom(12);
        let mut getters: Vec<(&'static str, Box<dyn Fn() -> Val>)> = Vec::new();
        let mut combos: Vec<(&'static str, gtk::DropDown, Choices)> = Vec::new();
        let mut entries: Vec<(&'static str, gtk::Entry)> = Vec::new();

        for o in defs {
            let tip = if o.tip.is_empty() { None } else { Some(o.tip) };
            if let Kind::Section = o.kind {
                let l = gtk::Label::new(Some(crate::i18n::tr(o.label).as_str()));
                l.add_css_class("heading");
                l.set_xalign(0.0);
                l.set_margin_top(10);
                root.append(&l);
                continue;
            }
            let key = o.key;
            match o.kind {
                Kind::Section => {}
                Kind::Check => {
                    let c = gtk::CheckButton::with_label(&crate::i18n::tr(o.label));
                    c.set_active(matches!(o.def, Def::B(true)));
                    c.set_tooltip_text(tip);
                    let cb = on_change.clone();
                    c.connect_toggled(move |_| cb());
                    root.append(&c);
                    getters.push((key, Box::new(move || Val::B(c.is_active()))));
                }
                Kind::Text(_) | Kind::Path => {
                    let l = gtk::Label::new(Some(crate::i18n::tr(o.label).as_str()));
                    l.set_xalign(0.0);
                    l.set_tooltip_text(tip);
                    root.append(&l);
                    let e = gtk::Entry::new();
                    e.set_text(&def_str(o.def));
                    e.set_hexpand(true);
                    entries.push((key, e.clone()));
                    e.set_tooltip_text(tip);
                    let cb = on_change.clone();
                    e.connect_changed(move |_| cb());
                    if matches!(o.kind, Kind::Path) {
                        let row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
                        let b = gtk::Button::with_label(&crate::i18n::tr("…"));
                        let e2 = e.clone();
                        b.connect_clicked(move |btn| {
                            let parent = btn.root().and_downcast::<gtk::Window>();
                            let e3 = e2.clone();
                            gtk::FileDialog::new().select_folder(parent.as_ref(), None::<&gio::Cancellable>, move |res| {
                                if let Some(p) = res.ok().and_then(|f| f.path()) {
                                    e3.set_text(&p.to_string_lossy());
                                }
                            });
                        });
                        row.append(&e);
                        row.append(&b);
                        root.append(&row);
                    } else {
                        root.append(&e);
                    }
                    getters.push((key, Box::new(move || Val::S(e.text().to_string()))));
                }
                Kind::Combo(choices) => {
                    let l = gtk::Label::new(Some(crate::i18n::tr(o.label).as_str()));
                    l.set_xalign(0.0);
                    l.set_tooltip_text(tip);
                    root.append(&l);
                    let tl: Vec<String> = choices.iter().map(|c| crate::i18n::tr(c.0)).collect();
                    let labels: Vec<&str> = tl.iter().map(String::as_str).collect();
                    let d = gtk::DropDown::from_strings(&labels);
                    let def = def_str(o.def);
                    d.set_selected(choices.iter().position(|c| c.1 == def).unwrap_or(0) as u32);
                    d.set_tooltip_text(tip);
                    let cb = on_change.clone();
                    d.connect_selected_notify(move |_| cb());
                    root.append(&d);
                    combos.push((key, d.clone(), choices));
                    getters.push((key, Box::new(move || Val::S(choices.get(d.selected() as usize).map(|c| c.1).unwrap_or("").to_string()))));
                }
                Kind::Int(min, max) => {
                    let l = gtk::Label::new(Some(&format!("{} (0 = par défaut)", o.label)));
                    l.set_xalign(0.0);
                    l.set_tooltip_text(tip);
                    root.append(&l);
                    let s = gtk::SpinButton::with_range(min as f64, max as f64, 1.0);
                    s.set_tooltip_text(tip);
                    let cb = on_change.clone();
                    s.connect_value_changed(move |_| cb());
                    root.append(&s);
                    getters.push((key, Box::new(move || Val::I(s.value().max(0.0) as u32))));
                }
                Kind::Multi(choices) => {
                    let l = gtk::Label::new(Some(crate::i18n::tr(o.label).as_str()));
                    l.set_xalign(0.0);
                    l.set_tooltip_text(tip);
                    root.append(&l);
                    let defaults: &[&str] = if let Def::L(d) = o.def { d } else { &[] };
                    let mut boxes = Vec::new();
                    for (label, val) in choices {
                        let c = gtk::CheckButton::with_label(label);
                        c.set_active(defaults.contains(val));
                        let cb = on_change.clone();
                        c.connect_toggled(move |_| cb());
                        root.append(&c);
                        boxes.push((c, *val));
                    }
                    getters.push((key, Box::new(move || Val::L(boxes.iter().filter(|(c, _)| c.is_active()).map(|(_, v)| v.to_string()).collect()))));
                }
            }
        }
        Panel { root, getters, combos, entries }
    }

    /// Sélectionne une valeur d'une liste déroulante (ex. forcer « Analyse complète » pour « Tout analyser »).
    pub fn set_combo(&self, key: &str, value: &str) {
        if let Some((_, d, ch)) = self.combos.iter().find(|(k, _, _)| *k == key) {
            if let Some(i) = ch.iter().position(|c| c.1 == value) {
                d.set_selected(i as u32);
            }
        }
    }

    /// Remplit un champ texte ou dossier (ex. le dossier de projets choisi sur la tuile).
    pub fn set_text(&self, key: &str, value: &str) {
        if let Some((_, e)) = self.entries.iter().find(|(k, _)| *k == key) {
            e.set_text(value);
        }
    }

    pub fn values(&self) -> Values {
        Values(self.getters.iter().map(|(k, g)| (k.to_string(), g())).collect())
    }
}
