//! Soin intelligent : le même parcours que CleanMyMac — Analyser, Voir, Corriger.
//! Un seul bouton rond, cinq tuiles en langage clair, des cases à cocher, « Revoir » pour le détail.

use super::auto::update_cve_data;
use super::dialogs::{pending_updates_blocking, system_update};
use super::global_page::GlobalPage;
use super::tool_page::{Progress, ToolPage};
use super::{Ctx, plain_label, when};
use crate::live::{self, Snapshot};
use crate::risk::{self, Risk, RiskLevel, Update};
use crate::tools::Plan;
use crate::util::now_unix;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Welcome,
    Scanning,
    Results,
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fix {
    SystemUpdate,
    AdminScans,
    Firewall,
}

struct Tile {
    key: &'static str,
    frame: gtk::Box,
    check: gtk::CheckButton,
    value: gtk::Label,
    verb: gtk::Label,
    fix: Cell<Option<Fix>>,
}

#[derive(Default)]
struct ScanData {
    updates: Vec<Update>,
    risks: Vec<Risk>,
    wanted: usize,
    to_check: usize,
    firewall: Option<String>,
    fw_ports: Vec<String>,
}

pub struct SmartPage {
    pub root: gtk::Box,
    ctx: Rc<Ctx>,
    pages: Rc<HashMap<&'static str, Rc<ToolPage>>>,
    global: Rc<GlobalPage>,
    tiles: Vec<Tile>,
    title: gtk::Label,
    sub: gtk::Label,
    detail: gtk::Label,
    bar: gtk::ProgressBar,
    pulsing: Cell<bool>,
    tiles_box: gtk::Box,
    center: gtk::Button,
    center_label: gtk::Label,
    restart: gtk::Button,
    options: gtk::Box,
    strip: gtk::Label,
    state: Cell<State>,
    stopped: Cell<bool>,
    busy: Cell<bool>,
    data: RefCell<ScanData>,
    failed: RefCell<Vec<String>>,
}

fn make_tile(key: &'static str, css: &str, name: &str, icon: &str, go_to: Rc<dyn Fn(&str)>, page: &'static str) -> Tile {
    let frame = gtk::Box::new(gtk::Orientation::Vertical, 6);
    frame.add_css_class("tile");
    frame.add_css_class(css);
    frame.set_hexpand(true);
    let top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let check = gtk::CheckButton::new();
    check.set_active(true);
    let n = gtk::Label::new(Some(crate::i18n::tr(name).as_str()));
    n.add_css_class("tile-name");
    n.set_hexpand(true);
    n.set_xalign(0.0);
    let img = gtk::Image::from_icon_name(icon);
    img.set_pixel_size(40);
    img.set_opacity(0.85);
    top.append(&check);
    top.append(&n);
    top.append(&img);
    let value = plain_label("—");
    value.add_css_class("tile-value");
    let verb = plain_label("");
    verb.add_css_class("soft");
    verb.set_vexpand(true);
    verb.set_yalign(0.0);
    let review = gtk::Button::with_label(&crate::i18n::tr("Revoir"));
    review.add_css_class("glass-btn");
    review.set_halign(gtk::Align::End);
    review.connect_clicked(move |_| go_to(page));
    frame.append(&top);
    frame.append(&value);
    frame.append(&verb);
    frame.append(&review);
    let f2 = frame.clone();
    check.connect_toggled(move |c| {
        if c.is_active() {
            f2.remove_css_class("tile-off");
        } else {
            f2.add_css_class("tile-off");
        }
    });
    Tile { key, frame, check, value, verb, fix: Cell::new(None) }
}

/// Lot administrateur : Lynis puis rkhunter derrière UNE SEULE demande de mot de passe.
/// Script CONSTANT (aucune donnée externe), options par défaut ; les résultats reviennent entre marqueurs nommés.
pub const ADMIN_BUNDLE_SCRIPT: &str = r#"d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
echo '@@CS-STEP:lynis@@'
/usr/bin/lynis audit system --no-colors --quick --report-file "$d/lynis" 2>&1
printf '\n@@CS-OUTPUT-BEGIN:lynis@@\n'; cat "$d/lynis" 2>/dev/null; printf '\n@@CS-OUTPUT-END@@\n'
echo '@@CS-STEP:rkhunter@@'
/usr/bin/rkhunter --check --skip-keypress --nocolors --no-mail-on-warning --pkgmgr NONE --lang en --logfile "$d/rkhunter" 2>&1
printf '\n@@CS-OUTPUT-BEGIN:rkhunter@@\n'; cat "$d/rkhunter" 2>/dev/null; printf '\n@@CS-OUTPUT-END@@\n'
"#;

/// Découpe la sortie du lot en sections par outil (marqueurs « @@CS-STEP:nom@@ »).
/// Sélecteur de langue (automatique = langue du système, ou choix manuel) : placé en bas de la barre latérale ;
/// le choix s'applique au prochain lancement.
pub fn language_selector(ctx: &Rc<Ctx>) -> gtk::DropDown {
        let langs = crate::i18n::available_languages();
        let mut labels: Vec<String> = vec![crate::i18n::tr("Langue : automatique")];
        labels.extend(langs.iter().map(|c| crate::i18n::lang_name(c)));
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let dd = gtk::DropDown::from_strings(&refs);
    dd.add_css_class("lang-select");
        dd.set_valign(gtk::Align::Center);
        dd.set_tooltip_text(Some(&crate::i18n::tr("Langue de l'application. « Automatique » suit la langue de votre système.")));
        let cur = ctx.state.borrow().settings.language.clone();
        dd.set_selected(langs.iter().position(|c| *c == cur).map(|i| i as u32 + 1).unwrap_or(0));
        let (c6, langs2) = (ctx.clone(), langs.clone());
        dd.connect_selected_notify(move |d| {
            let new = if d.selected() == 0 { "auto".to_string() } else { langs2.get(d.selected() as usize - 1).cloned().unwrap_or_else(|| "auto".into()) };
            if new == c6.state.borrow().settings.language {
                return;
            }
            c6.state.borrow_mut().settings.language = new;
            c6.save();
            let c7 = c6.clone();
            glib::spawn_future_local(async move {
                use libadwaita::prelude::*;
                let a = libadwaita::AlertDialog::new(Some(&crate::i18n::tr("Changer de langue")), Some(&crate::i18n::tr("Le changement s'applique au prochain lancement. Relancer l'application maintenant ?")));
                a.add_response("later", &crate::i18n::tr("Plus tard"));
                a.add_response("now", &crate::i18n::tr("Relancer maintenant"));
                a.set_response_appearance("now", libadwaita::ResponseAppearance::Suggested);
                a.set_default_response(Some("now"));
                a.set_close_response("later");
                if a.choose_future(c7.window().as_ref()).await == "now" {
                    // le nouveau processus attend un instant que celui-ci ait quitté (une seule instance à la fois)
                    if let Ok(exe) = std::env::current_exe() {
                        let _ = std::process::Command::new(crate::util::SH).args(["-c", "sleep 1; exec \"$0\"", &exe.to_string_lossy()]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
                        c7.app.quit();
                    }
                }
            });
        });
    dd
}

fn split_steps(text: &str) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if let Some(name) = line.trim().strip_prefix("@@CS-STEP:").and_then(|s| s.strip_suffix("@@")) {
            cur = Some(name.to_string());
            continue;
        }
        if let Some(c) = &cur {
            let e = out.entry(c.clone()).or_default();
            e.push_str(line);
            e.push('\n');
        }
    }
    out
}

fn step_name(key: &str) -> &'static str {
    match key {
        "arch-audit" => "Paquets du système",
        "trivy" => "Bibliothèques et secrets",
        "osv-scanner" => "Dépendances de vos projets",
        "lynis" => "Configuration du système",
        "rkhunter" => "Recherche de rootkits",
        _ => "Analyse",
    }
}

impl SmartPage {
    pub fn new(ctx: Rc<Ctx>, pages: Rc<HashMap<&'static str, Rc<ToolPage>>>, global: Rc<GlobalPage>, go_to: Rc<dyn Fn(&str)>) -> Rc<SmartPage> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 14);
        root.add_css_class("smart-bg");
        for f in [24, 24] {
            let _ = f;
        }
        root.set_margin_top(0);

        let wrap = gtk::Box::new(gtk::Orientation::Vertical, 14);
        wrap.set_margin_top(18);
        wrap.set_margin_bottom(18);
        wrap.set_margin_start(30);
        wrap.set_margin_end(30);
        wrap.set_vexpand(true);

        let restart = gtk::Button::with_label(&crate::i18n::tr("‹ Recommencer"));
        restart.add_css_class("glass-btn");
        restart.set_halign(gtk::Align::Start);
        restart.set_visible(false);

        let title = gtk::Label::new(Some(crate::i18n::tr("Bienvenue").as_str()));
        title.add_css_class("smart-title");
        title.set_wrap(true);
        title.set_justify(gtk::Justification::Center);
        let sub = gtk::Label::new(Some(crate::i18n::tr("Lancez une analyse rapide et complète : failles, mises à jour, protection et réseau.").as_str()));
        sub.add_css_class("smart-sub");
        sub.add_css_class("soft");
        sub.set_wrap(true);
        sub.set_justify(gtk::Justification::Center);

        let tiles = vec![
            make_tile("protection", "tile-protection", "PROTECTION", "security-high-symbolic", go_to.clone(), "protection"),
            make_tile("failles", "tile-failles", "FAILLES", "dialog-warning-symbolic", go_to.clone(), "failles"),
            make_tile("maj", "tile-maj", "MISES À JOUR", "software-update-available-symbolic", go_to.clone(), "maj"),
            make_tile("config", "tile-config", "CONFIGURATION", "preferences-system-symbolic", go_to.clone(), "config"),
            make_tile("reseau", "tile-reseau", "RÉSEAU", "network-wired-symbolic", go_to.clone(), "reseau"),
        ];
        let grid = gtk::Grid::new();
        grid.set_row_spacing(14);
        grid.set_column_spacing(14);
        grid.set_column_homogeneous(true);
        for (i, t) in tiles.iter().enumerate() {
            if i < 3 {
                grid.attach(&t.frame, (i * 2) as i32, 0, 2, 1);
            } else {
                grid.attach(&t.frame, ((i - 3) * 3) as i32, 1, 3, 1);
            }
        }
        let tiles_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        tiles_box.append(&grid);
        tiles_box.set_visible(false);
        tiles_box.set_valign(gtk::Align::Center);

        let center_label = gtk::Label::new(Some(crate::i18n::tr("Analyser").as_str()));
        let center = gtk::Button::new();
        center.set_child(Some(&center_label));
        center.add_css_class("round-btn");
        center.set_halign(gtk::Align::Center);
        center.set_margin_top(10);

        let options = gtk::Box::new(gtk::Orientation::Vertical, 8);
        options.set_halign(gtk::Align::Center);
        let admin = gtk::CheckButton::with_label(&crate::i18n::tr("Inclure les analyses administrateur (Lynis, rkhunter) — votre mot de passe sera demandé"));
        admin.set_active(ctx.state.borrow().settings.include_admin);
        let c2 = ctx.clone();
        admin.connect_toggled(move |b| {
            c2.state.borrow_mut().settings.include_admin = b.is_active();
            c2.save();
        });
        options.append(&admin);

        // bande du bas : dernière analyse, état des bases de CVE, mise à jour automatique
        let strip_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        strip_box.add_css_class("strip");
        let strip = plain_label("");
        strip.set_hexpand(true);
        // largeur naturelle bornée : un texte long (autre langue) ne doit jamais élargir la fenêtre
        strip.set_max_width_chars(60);
        strip.set_width_chars(20);
        strip.add_css_class("soft");
        let auto_lbl = gtk::Label::new(Some(crate::i18n::tr("Mise à jour automatique des CVE").as_str()));
        auto_lbl.add_css_class("soft");
        let sw = gtk::Switch::new();
        sw.set_active(ctx.state.borrow().settings.auto_update);
        sw.set_valign(gtk::Align::Center);
        let c3 = ctx.clone();
        sw.connect_state_set(move |_, on| {
            c3.state.borrow_mut().settings.auto_update = on;
            c3.save();
            glib::Propagation::Proceed
        });
        strip_box.append(&strip);
        strip_box.append(&auto_lbl);
        strip_box.append(&sw);
        let notif_lbl = gtk::Label::new(Some(crate::i18n::tr("Notifications").as_str()));
        notif_lbl.add_css_class("soft");
        let nsw = gtk::Switch::new();
        nsw.set_active(ctx.state.borrow().settings.notifications);
        nsw.set_valign(gtk::Align::Center);
        let c4 = ctx.clone();
        nsw.connect_state_set(move |_, on| {
            c4.state.borrow_mut().settings.notifications = on;
            c4.save();
            glib::Propagation::Proceed
        });
        strip_box.append(&notif_lbl);
        strip_box.append(&nsw);

        wrap.append(&restart);
        let head = gtk::Box::new(gtk::Orientation::Vertical, 6);
        head.set_valign(gtk::Align::Center);
        let detail = gtk::Label::new(None);
        detail.add_css_class("soft");
        detail.set_ellipsize(gtk::pango::EllipsizeMode::End);
        detail.set_max_width_chars(90);
        let bar = gtk::ProgressBar::new();
        bar.set_visible(false);
        bar.set_halign(gtk::Align::Center);
        bar.set_size_request(380, -1);
        bar.set_margin_top(8);
        head.append(&title);
        head.append(&sub);
        head.append(&detail);
        head.append(&bar);
        wrap.append(&head);
        wrap.append(&tiles_box);
        wrap.append(&center);
        wrap.append(&options);
        root.append(&wrap);
        let foot = gtk::Box::new(gtk::Orientation::Vertical, 0);
        foot.set_margin_start(30);
        foot.set_margin_end(30);
        foot.set_margin_bottom(18);
        foot.append(&strip_box);
        root.append(&foot);

        let page = Rc::new(SmartPage { root, ctx, pages, global, tiles, title, sub, detail, bar, pulsing: Cell::new(false), tiles_box, center, center_label, restart, options, strip, state: Cell::new(State::Welcome), stopped: Cell::new(false), busy: Cell::new(false), data: RefCell::new(ScanData::default()), failed: RefCell::new(Vec::new()) });
        let p = page.clone();
        page.center.connect_clicked(move |_| p.on_center());
        let p = page.clone();
        page.restart.connect_clicked(move |_| p.set_state(State::Welcome));
        for p in page.pages.values() {
            let (d, w) = (page.detail.clone(), Rc::downgrade(&page));
            p.on_progress(move |ev| {
                let Some(me) = w.upgrade() else { return };
                if !me.busy.get() {
                    return; // une analyse lancée depuis une autre page ne doit pas écrire ici
                }
                match ev {
                    Progress::Start { elevated } => d.set_text(if *elevated { "En attente de votre mot de passe administrateur (fenêtre d'authentification de KDE)…" } else { "" }),
                    Progress::Line(l) => d.set_text(l),
                    Progress::End => {}
                }
            });
        }
        page.refresh_strip();
        // la bande reflète en direct la vérification automatique des CVE
        let p = page.clone();
        glib::timeout_add_seconds_local(2, move || {
            p.refresh_strip();
            glib::ControlFlow::Continue
        });
        page
    }

    fn set_state(&self, st: State) {
        self.state.set(st);
        self.bar.set_visible(st == State::Scanning);
        if st != State::Scanning {
            self.pulsing.set(false);
            self.detail.set_text("");
        }
        let (results, label) = match st {
            State::Welcome => (false, "Analyser"),
            State::Scanning => (false, "Arrêter"),
            State::Results => (true, "Corriger"),
            State::Done => (true, "Analyser"),
        };
        self.tiles_box.set_visible(results);
        self.restart.set_visible(results);
        self.options.set_visible(st == State::Welcome);
        self.center_label.set_text(label);
        match st {
            State::Welcome => {
                self.title.set_text(&crate::i18n::tr("Bienvenue"));
                self.sub.set_text(&crate::i18n::tr("Lancez une analyse rapide et complète : failles, mises à jour, protection et réseau."));
            }
            State::Scanning => {
                self.title.set_text(&crate::i18n::tr("Analyse en cours…"));
                if !self.pulsing.replace(true) {
                    let bar = self.bar.clone();
                    glib::timeout_add_local(std::time::Duration::from_millis(120), move || {
                        if bar.is_visible() {
                            bar.pulse();
                            glib::ControlFlow::Continue
                        } else {
                            glib::ControlFlow::Break
                        }
                    });
                }
            }
            State::Results | State::Done => {}
        }
        self.refresh_strip();
    }

    fn step(&self, text: &str) {
        self.sub.set_text(text);
    }

    fn refresh_strip(&self) {
        // chaque morceau est traduit séparément : le texte final ne dépend d'aucune règle globale et ne repasse jamais en français
        let t = |s: &str| crate::i18n::tr(s);
        let st = self.ctx.state.borrow();
        let d = |k: &str| st.db.get(k).filter(|s| s.ok).map(|s| t(&when(s.time).replace("analysé le ", ""))).unwrap_or_else(|| t("jamais"));
        let sep = "   ·   ";
        let mut parts = vec![
            t("Dernière analyse : {d}").replace("{d}", &t(&when(st.last_smart).replace("analysé le ", ""))),
            t("Bases de CVE vérifiées — CISA : {k} · Trivy : {v}").replace("{k}", &d("kev")).replace("{v}", &d("trivy")),
        ];
        if self.ctx.updating.get() > 0 {
            parts.push(t("⟳ vérification des bases en cours…"));
        }
        let auth = match crate::privileged::status() {
            crate::privileged::Status::Active => t("Administrateur : autorisé pour cette session"),
            crate::privileged::Status::Asking => t("Administrateur : en attente de votre mot de passe…"),
            crate::privileged::Status::Declined => t("Administrateur : non accordé (mot de passe demandé à chaque action)"),
            crate::privileged::Status::Unavailable => t("Administrateur : mot de passe demandé à chaque action (installez le programme pour une seule demande)"),
            _ => String::new(),
        };
        if !auth.is_empty() {
            parts.push(auth);
        }
        self.strip.set_text(&parts.join(sep));
    }

    fn on_center(self: &Rc<Self>) {
        match self.state.get() {
            State::Welcome | State::Done => self.scan(),
            State::Scanning => {
                self.stopped.set(true);
                for p in self.pages.values() {
                    p.stop();
                }
            }
            State::Results => self.run_fixes(),
        }
    }

    fn scan(self: &Rc<Self>) {
        if self.busy.replace(true) {
            return;
        }
        self.stopped.set(false);
        self.set_state(State::Scanning);
        let me = self.clone();
        glib::spawn_future_local(async move {
            let admin = me.ctx.state.borrow().settings.include_admin;
            // Le mot de passe est demandé UNE SEULE FOIS, tout de suite : le lot administrateur démarre en premier
            // et tourne en parallèle des analyses qui n'en ont pas besoin.
            let admin_task = admin.then(|| {
                let m = me.clone();
                glib::spawn_future_local(async move { m.admin_bundle().await })
            });
            me.step("Mise à jour des bases de CVE…");
            update_cve_data(&me.ctx, &me.global, 1).await;
            let mut failed: Vec<String> = Vec::new();
            for k in ["arch-audit", "trivy", "osv-scanner"] {
                if me.stopped.get() {
                    break;
                }
                if k == "osv-scanner" && me.ctx.state.borrow().settings.project_dirs.is_empty() {
                    continue; // aucun dossier de projets choisi : rien à analyser (ce n'est pas une erreur)
                }
                me.step(&format!("{}…", step_name(k)));
                if me.pages[k].run_await().await.is_none() {
                    failed.push(format!("{} : {}", step_name(k), me.pages[k].last_error().unwrap_or_else(|| "analyse déjà en cours".into())));
                }
            }
            if let Some(task) = admin_task {
                if !me.stopped.get() {
                    me.step("Analyses administrateur (Lynis, rkhunter)…");
                    if !matches!(task.await, Ok(true)) {
                        failed.push("Analyses administrateur : autorisation refusée, annulée ou en échec".into());
                    }
                }
            }
            *me.failed.borrow_mut() = failed;
            if me.stopped.get() {
                me.set_state(State::Welcome);
            } else {
                me.step("Recherche des mises à jour…");
                let data = me.collect().await;
                *me.data.borrow_mut() = data;
                me.ctx.state.borrow_mut().last_smart = now_unix();
                me.ctx.save();
                me.fill();
                me.set_state(State::Results);
                me.ctx.notify("analyse-terminee", &me.title.text(), &me.sub.text());
            }
            me.busy.set(false);
        });
    }

    /// Lynis puis rkhunter derrière UNE SEULE autorisation administrateur. Renvoie true si le lot s'est exécuté.
    async fn admin_bundle(self: &Rc<Self>) -> bool {
        let plan = Plan { argv: vec![crate::util::SH.into(), "-c".into(), ADMIN_BUNDLE_SCRIPT.into()], elevated: true, out_flag: None, out_pos: 0 };
        let Ok(run) = crate::runner::spawn(&plan, &[], None) else { return false };
        let (lynis, rk) = (self.pages["lynis"].clone(), self.pages["rkhunter"].clone());
        lynis.emit(Progress::Start { elevated: crate::privileged::session().is_none() });
        let mut current = String::from("lynis");
        while let Ok(msg) = run.rx.recv().await {
            match msg {
                crate::runner::Msg::Line(l) => {
                    if let Some(name) = l.trim().strip_prefix("@@CS-STEP:").and_then(|s| s.strip_suffix("@@")) {
                        if name == "rkhunter" {
                            lynis.emit(Progress::End);
                            rk.emit(Progress::Start { elevated: false });
                        }
                        current = name.to_string();
                        continue;
                    }
                    (if current == "rkhunter" { &rk } else { &lynis }).emit(Progress::Line(l));
                }
                crate::runner::Msg::Done { code, blobs, text, .. } => {
                    if blobs.is_empty() {
                        // autorisation refusée ou outil absent : on ne mémorise aucun faux résultat
                        lynis.emit(Progress::End);
                        rk.emit(Progress::End);
                        return false;
                    }
                    let steps = split_steps(&text);
                    let get = |k: &str| steps.get(k).map(String::as_str).unwrap_or("").to_string();
                    lynis.ingest(&lynis.values(), code, blobs.get("lynis").cloned(), &get("lynis"));
                    let v = crate::tools::Values(HashMap::from([("action".to_string(), crate::tools::Val::S("--check".into()))]));
                    rk.ingest(&v, code, blobs.get("rkhunter").cloned(), &get("rkhunter"));
                    return true;
                }
            }
        }
        false
    }

    async fn collect(&self) -> ScanData {
        let (tx, rx) = async_channel::bounded::<(Vec<Update>, Snapshot)>(1);
        std::thread::spawn(move || {
            let ups = risk::parse_updates(&pending_updates_blocking());
            let _ = tx.send_blocking((ups, live::snapshot()));
        });
        let (updates, snap) = rx.recv().await.unwrap_or_default();
        let allowed: HashSet<String> = self.ctx.state.borrow().allowed.clone().unwrap_or_default().into_iter().collect();
        let (wanted, to_check) = live::exposure(&snap, &allowed);
        let l: Vec<(String, String, String)> = snap.listeners.iter().filter(|l| l.expo == live::Expo::All).map(|l| (l.proc.clone(), l.port.clone(), l.proto.clone())).collect();
        let fw_ports = crate::procctl::firewall_args(&l, &allowed, &self.ctx.state.borrow().fw_rules, self.ctx.state.borrow().settings.fw_log);
        let own = crate::ui::dialogs::firewall_on(&self.ctx);
        ScanData { risks: risk::assess(&updates), updates, wanted, to_check, firewall: snap.firewall.or(own.then(|| "Cachy Shield".to_string())), fw_ports }
    }

    fn tile(&self, key: &str) -> &Tile {
        self.tiles.iter().find(|t| t.key == key).expect("tuile")
    }

    fn fill(&self) {
        let d = self.data.borrow();
        let st = self.ctx.state.borrow();
        let res = |k: &str| st.tools.get(k).map(|s| (s.result.clone(), s.rows.len()));
        let mut todo = 0;

        // Protection (rkhunter)
        let t = self.tile("protection");
        match res("rkhunter") {
            Some((r, _)) => {
                let rk = r.counts.get("rootkits").copied().unwrap_or(0);
                let w = r.counts.get("warning").copied().unwrap_or(0);
                if rk > 0 {
                    t.value.set_text(&format!("{rk} menace(s)"));
                    t.verb.set_text(&crate::i18n::tr("Rootkit possible : à examiner tout de suite."));
                    todo += 1;
                } else if w > 0 {
                    t.value.set_text(&format!("{w} alerte(s)"));
                    t.verb.set_text(&crate::i18n::tr("Souvent des faux positifs : ouvrez « Revoir » pour les explications."));
                    todo += 1;
                } else {
                    t.value.set_text(&crate::i18n::tr("Aucune menace"));
                    t.verb.set_text(&crate::i18n::tr("Votre système est sain."));
                }
                t.fix.set(None);
            }
            None => {
                t.value.set_text(&crate::i18n::tr("Non analysé"));
                t.verb.set_text(&crate::i18n::tr("à analyser (droits administrateur) · correctif disponible"));
                t.fix.set(Some(Fix::AdminScans));
            }
        }

        // Failles
        let t = self.tile("failles");
        let arch = res("arch-audit").map(|(_, n)| n).unwrap_or(0);
        let osv = res("osv-scanner").map(|(_, n)| n).unwrap_or(0);
        let kev = self.global.kev_summary();
        t.value.set_text(&if arch == 0 { "Aucune faille".to_string() } else { format!("{arch} paquet(s) vulnérable(s)") });
        let mut v = vec![format!("{osv} faille(s) dans vos projets")];
        if let Some((n, k)) = kev {
            v.push(if n > 0 { format!("{k} logiciel(s) ciblé(s) par des attaques réelles") } else { "aucune attaque réelle connue sur vos logiciels".into() });
        }
        t.verb.set_text(&v.join(" · "));
        if arch > 0 || kev.is_some_and(|(n, _)| n > 0) {
            todo += 1;
        }
        t.fix.set(None);

        // Mises à jour
        let t = self.tile("maj");
        if d.updates.is_empty() {
            t.value.set_text(&crate::i18n::tr("Système à jour"));
            t.verb.set_text(&crate::i18n::tr("Aucune mise à jour en attente."));
            t.fix.set(None);
        } else {
            let high = d.risks.iter().filter(|r| r.level == RiskLevel::High).count();
            t.value.set_text(&format!("{} mise(s) à jour", d.updates.len()));
            t.verb.set_text(&if high > 0 { format!("à installer · ⚠ {high} point(s) à risque élevé : vous serez prévenu avant") } else { "à installer · aucun risque particulier détecté".to_string() });
            t.fix.set(Some(Fix::SystemUpdate));
            todo += 1;
        }

        // Configuration (Lynis)
        let t = self.tile("config");
        match res("lynis") {
            Some((r, _)) => {
                t.value.set_text(&r.score.map(|s| format!("Score {s}/100")).unwrap_or_else(|| "Analysé".into()));
                let w = r.counts.get("warning").copied().unwrap_or(0);
                let s = r.counts.get("suggestion").copied().unwrap_or(0);
                t.verb.set_text(&format!("{w} alerte(s), {s} suggestion(s) pour renforcer le système"));
                t.fix.set(None);
                if r.score.is_some_and(|x| x < 80) || w > 0 {
                    todo += 1;
                }
            }
            None => {
                t.value.set_text(&crate::i18n::tr("Non analysé"));
                t.verb.set_text(&crate::i18n::tr("à analyser (droits administrateur) · correctif disponible"));
                t.fix.set(Some(Fix::AdminScans));
            }
        }

        // Réseau
        let t = self.tile("reseau");
        if d.to_check == 0 {
            t.value.set_text(&crate::i18n::tr("Aucun port suspect"));
        } else {
            t.value.set_text(&format!("{} port(s) à vérifier", d.to_check));
            todo += 1;
        }
        t.verb.set_text(&format!("{} service(s) autorisé(s) · pare-feu {}", d.wanted, d.firewall.as_deref().map(|f| format!("actif ({f})")).unwrap_or_else(|| "inactif".into())));
        if d.firewall.is_none() {
            t.fix.set(Some(Fix::Firewall));
        } else {
            t.fix.set(None);
        }

        let failed = self.failed.borrow().clone();
        if !failed.is_empty() {
            self.sub.set_text(&format!("⚠ {} analyse(s) n'ont pas pu démarrer : {}", failed.len(), failed.join(" · ")));
            self.title.set_text(&crate::i18n::tr("Résultats incomplets"));
            return;
        }
        if todo == 0 {
            self.title.set_text(&crate::i18n::tr("Votre ordinateur est en bonne santé !"));
            self.sub.set_text(&crate::i18n::tr("Voici ce que nous avons trouvé lors de la dernière analyse."));
        } else {
            self.title.set_text(&crate::i18n::tr("Vos résultats sont prêts. Voici ce que nous avons trouvé :"));
            self.sub.set_text(&crate::i18n::tr("Cochez ce que vous voulez corriger, puis appuyez sur Corriger. « Revoir » ouvre le détail."));
        }
    }

    fn selected_fixes(&self) -> Vec<Fix> {
        let mut v: Vec<Fix> = Vec::new();
        for t in &self.tiles {
            if let (true, Some(f)) = (t.check.is_active(), t.fix.get()) {
                if !v.contains(&f) {
                    v.push(f);
                }
            }
        }
        v
    }

    fn run_fixes(self: &Rc<Self>) {
        let fixes = self.selected_fixes();
        if fixes.is_empty() {
            self.title.set_text(&crate::i18n::tr("Rien à corriger dans votre sélection"));
            self.sub.set_text(&crate::i18n::tr("Cochez une tuile qui propose un correctif, ou ouvrez « Revoir » pour traiter un point à la main."));
            return;
        }
        let me = self.clone();
        self.center.set_sensitive(false);
        glib::spawn_future_local(async move {
            let mut done = 0;
            for f in fixes {
                match f {
                    Fix::AdminScans => {
                        me.step("Analyses administrateur en cours (une seule autorisation)…");
                        me.admin_bundle().await;
                        done += 1;
                    }
                    Fix::Firewall => {
                        let ports = me.data.borrow().fw_ports.clone();
                        let (tx, rx) = async_channel::bounded::<()>(1);
                        crate::ui::dialogs::enable_firewall(&me.ctx, ports, Box::new(move || {
                            let _ = tx.try_send(());
                        }));
                        let _ = rx.recv().await;
                        done += 1;
                    }
                    Fix::SystemUpdate => {
                        let (tx, rx) = async_channel::bounded::<()>(1);
                        system_update(&me.ctx, Box::new(move || {
                            let _ = tx.try_send(());
                        }));
                        let _ = rx.recv().await;
                        done += 1;
                    }
                }
            }
            let data = me.collect().await;
            *me.data.borrow_mut() = data;
            me.fill();
            me.title.set_text(&crate::i18n::tr("Terminé !"));
            me.sub.set_text(&format!("{done} tâche(s) traitée(s). Relancez une analyse pour vérifier le résultat."));
            me.set_state(State::Done);
            me.center.set_sensitive(true);
        });
    }
}
