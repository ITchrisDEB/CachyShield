//! Tableau de bord : une carte par outil, jauge Lynis, indicateurs en direct.

use super::when;
use crate::model::{Level, ScanResult};
use gtk4 as gtk;
use gtk::prelude::*;
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;

struct Card {
    root: gtk::Box,
    bar: gtk::Box,
    headline: gtk::Label,
    when: gtk::Label,
    gauge: Option<(gtk::DrawingArea, gtk::Label, Rc<Cell<Option<u32>>>)>,
}

pub struct StatCard {
    pub root: gtk::Box,
    value: gtk::Label,
}

impl StatCard {
    pub fn new(title: &str) -> StatCard {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 2);
        root.add_css_class("card");
        root.set_hexpand(true);
        for m in [12, 12] {
            root.set_margin_top(0);
            let _ = m;
        }
        let t = gtk::Label::new(Some(title));
        t.add_css_class("dim-label");
        t.set_xalign(0.0);
        t.set_margin_top(12);
        t.set_margin_start(16);
        // largeur naturelle bornée : un libellé plus long dans une autre langue passe à la ligne au lieu d'élargir la fenêtre
        t.set_wrap(true);
        t.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        t.set_max_width_chars(26);
        t.set_width_chars(8);
        let value = gtk::Label::new(Some(crate::i18n::tr("—").as_str()));
        value.add_css_class("title-2");
        value.set_xalign(0.0);
        value.set_use_markup(false);
        value.set_wrap(true);
        value.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        value.set_max_width_chars(22);
        value.set_width_chars(6);
        value.set_margin_start(16);
        value.set_margin_bottom(12);
        root.append(&t);
        root.append(&value);
        StatCard { root, value }
    }

    pub fn set(&self, text: &str, css: Option<&str>) {
        self.value.set_text(text);
        self.value.remove_css_class("stat-warn");
        self.value.remove_css_class("stat-ok");
        if let Some(c) = css {
            self.value.add_css_class(c);
        }
    }
}

pub struct Dashboard {
    pub root: gtk::ScrolledWindow,
    cards: HashMap<&'static str, Card>,
    pub all_btn: gtk::Button,
    progress: gtk::ProgressBar,
    fw: StatCard,
    exposed: StatCard,
    public: StatCard,
    kev: StatCard,
}

fn make_card(title: &str, desc: &str, with_gauge: bool, key: &'static str, on_run: Rc<dyn Fn(&str)>, on_details: Rc<dyn Fn(&str)>) -> Card {
    let root = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    root.add_css_class("card");
    root.set_hexpand(true);
    let bar = gtk::Box::new(gtk::Orientation::Vertical, 0);
    bar.add_css_class("lvl-bar");
    bar.add_css_class("lvl-none");
    root.append(&bar);

    let body = gtk::Box::new(gtk::Orientation::Vertical, 4);
    body.set_hexpand(true);
    for f in [14, 14] {
        let _ = f;
    }
    body.set_margin_top(14);
    body.set_margin_bottom(14);
    body.set_margin_start(16);
    body.set_margin_end(16);
    let t = gtk::Label::new(Some(title));
    t.add_css_class("heading");
    t.set_xalign(0.0);
    let d = super::plain_label(desc);
    d.add_css_class("dim-label");
    let headline = super::plain_label("—");
    headline.add_css_class("title-3");
    headline.set_margin_top(6);
    let when_l = gtk::Label::new(Some(crate::i18n::tr("jamais analysé").as_str()));
    when_l.add_css_class("dim-label");
    when_l.set_xalign(0.0);
    let btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    btns.set_margin_top(8);
    let run = gtk::Button::with_label(&crate::i18n::tr("Analyser"));
    run.add_css_class("suggested-action");
    let details = gtk::Button::with_label(&crate::i18n::tr("Détails"));
    run.connect_clicked(move |_| on_run(key));
    details.connect_clicked(move |_| on_details(key));
    btns.append(&run);
    btns.append(&details);
    for w in [t.upcast_ref::<gtk::Widget>(), d.upcast_ref(), headline.upcast_ref(), when_l.upcast_ref(), btns.upcast_ref()] {
        body.append(w);
    }
    root.append(&body);

    let gauge = with_gauge.then(|| {
        let score: Rc<Cell<Option<u32>>> = Rc::new(Cell::new(None));
        let s2 = score.clone();
        let area = gtk::DrawingArea::new();
        area.set_content_width(112);
        area.set_content_height(112);
        area.set_draw_func(move |_, cr, w, h| {
            let (w, h) = (w as f64, h as f64);
            let r = w.min(h) / 2.0 - 10.0;
            let (cx, cy) = (w / 2.0, h / 2.0);
            let start = 0.75 * std::f64::consts::PI;
            let sweep = 1.5 * std::f64::consts::PI;
            cr.set_line_width(11.0);
            cr.set_line_cap(gtk::cairo::LineCap::Round);
            cr.set_source_rgba(0.55, 0.55, 0.6, 0.3);
            cr.arc(cx, cy, r, start, start + sweep);
            let _ = cr.stroke();
            if let Some(v) = s2.get() {
                let (cr_, cg, cb) = if v >= 80 { (0.19, 0.64, 0.42) } else if v >= 60 { (0.85, 0.62, 0.0) } else { (0.9, 0.28, 0.3) };
                cr.set_source_rgb(cr_, cg, cb);
                cr.arc(cx, cy, r, start, start + sweep * v.min(100) as f64 / 100.0);
                let _ = cr.stroke();
            }
        });
        let label = gtk::Label::new(Some(crate::i18n::tr("—").as_str()));
        label.add_css_class("title-1");
        let overlay = gtk::Overlay::new();
        overlay.set_child(Some(&area));
        overlay.add_overlay(&label);
        overlay.set_margin_end(16);
        overlay.set_valign(gtk::Align::Center);
        root.append(&overlay);
        (area, label, score)
    });
    Card { root, bar, headline, when: when_l, gauge }
}

impl Dashboard {
    pub fn new(entries: &[(&'static str, &'static str, &'static str, bool)], on_run: Rc<dyn Fn(&str)>, on_details: Rc<dyn Fn(&str)>, on_all: Rc<dyn Fn()>) -> Dashboard {
        let content = gtk::Box::new(gtk::Orientation::Vertical, 14);
        content.set_margin_top(20);
        content.set_margin_bottom(20);
        content.set_margin_start(24);
        content.set_margin_end(24);

        let head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let titles = gtk::Box::new(gtk::Orientation::Vertical, 2);
        titles.set_hexpand(true);
        let h = gtk::Label::new(Some(crate::i18n::tr("Tableau de bord").as_str()));
        h.add_css_class("title-1");
        h.set_xalign(0.0);
        let sub = gtk::Label::new(Some(crate::i18n::tr("Vue d'ensemble de la sécurité de votre système.").as_str()));
        sub.add_css_class("dim-label");
        sub.set_xalign(0.0);
        titles.append(&h);
        titles.append(&sub);
        let all_btn = gtk::Button::with_label(&crate::i18n::tr("Tout analyser"));
        all_btn.add_css_class("suggested-action");
        all_btn.set_valign(gtk::Align::Center);
        all_btn.connect_clicked(move |_| on_all());
        head.append(&titles);
        head.append(&all_btn);
        content.append(&head);
        let progress = gtk::ProgressBar::new();
        progress.set_show_text(true);
        progress.set_visible(false);
        content.append(&progress);

        let grid = gtk::Grid::new();
        grid.set_row_spacing(14);
        grid.set_column_spacing(14);
        grid.set_column_homogeneous(true);
        let mut cards = HashMap::new();
        for (i, (key, title, desc, gauge)) in entries.iter().enumerate() {
            let c = make_card(title, desc, *gauge, key, on_run.clone(), on_details.clone());
            grid.attach(&c.root, (i % 2) as i32, (i / 2) as i32, 1, 1);
            cards.insert(*key, c);
        }
        content.append(&grid);

        let live = gtk::Label::new(Some(crate::i18n::tr("En direct").as_str()));
        live.add_css_class("heading");
        live.set_xalign(0.0);
        live.set_margin_top(8);
        content.append(&live);
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        row.set_homogeneous(true);
        let (fw, exposed, public, kev) = (StatCard::new("Pare-feu"), StatCard::new("Ports exposés au réseau"), StatCard::new("Connexions vers Internet"), StatCard::new("Failles exploitées (vos logiciels)"));
        for s in [&fw, &exposed, &public, &kev] {
            row.append(&s.root);
        }
        content.append(&row);

        let root = gtk::ScrolledWindow::builder().child(&content).hscrollbar_policy(gtk::PolicyType::Never).build();
        Dashboard { root, cards, all_btn, progress, fw, exposed, public, kev }
    }

    /// « Tout analyser » : bandeau d'avancement (étape i / N) visible sur le tableau de bord.
    pub fn all_progress(&self, frac: f64, text: &str) {
        self.progress.set_visible(true);
        self.progress.set_fraction(frac.clamp(0.0, 1.0));
        self.progress.set_text(Some(&format!("{} % — {}", (frac.clamp(0.0, 1.0) * 100.0).floor() as u32, crate::i18n::tr(text))));
    }

    pub fn all_finished(&self, text: &str) {
        self.progress.set_fraction(1.0);
        self.progress.set_text(Some(&format!("100 % — {}", crate::i18n::tr(text))));
    }

    /// Indique sur la carte qu'une analyse est en cours.
    pub fn card_running(&self, key: &str) {
        if let Some(c) = self.cards.get(key) {
            c.when.set_text(&crate::i18n::tr("Analyse en cours…"));
        }
    }

    pub fn show_result(&self, key: &str, r: &ScanResult) {
        let Some(c) = self.cards.get(key) else { return };
        for cls in ["lvl-ok", "lvl-warn", "lvl-bad", "lvl-none"] {
            c.bar.remove_css_class(cls);
        }
        c.bar.add_css_class(match r.level {
            Level::Ok => "lvl-ok",
            Level::Warn => "lvl-warn",
            Level::Bad => "lvl-bad",
            Level::None => "lvl-none",
        });
        c.headline.set_text(if r.headline.is_empty() { "—" } else { &r.headline });
        c.when.set_text(&when(r.time));
        if let Some((area, label, score)) = &c.gauge {
            score.set(r.score);
            label.set_text(&r.score.map(|s| s.to_string()).unwrap_or_else(|| "—".into()));
            area.queue_draw();
        }
        let _ = &c.root;
    }

    pub fn show_live(&self, firewall: Option<&str>, to_check: usize, wanted: usize, public: usize) {
        match firewall {
            Some(f) => self.fw.set(&format!("Actif ({f})"), Some("stat-ok")),
            None => self.fw.set("Inactif", Some("stat-warn")),
        }
        let mut t = format!("{to_check} à vérifier");
        if wanted > 0 {
            t += &format!(" · {wanted} autorisés");
        }
        self.exposed.set(&t, Some(if to_check > 0 { "stat-warn" } else { "stat-ok" }));
        self.public.set(&public.to_string(), None);
    }
}

impl Dashboard {
    /// Failles activement exploitées (CISA KEV) qui correspondent possiblement à un logiciel installé.
    pub fn show_kev(&self, matches: Option<(usize, usize)>) {
        match matches {
            None => self.kev.set("catalogue absent", None),
            Some((0, _)) => self.kev.set("aucune", Some("stat-ok")),
            Some((n, k)) => self.kev.set(&format!("{k} logiciel(s) · {n} faille(s)"), Some("stat-warn")),
        }
    }
}
