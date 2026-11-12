#![forbid(unsafe_code)]
//! Cachy Shield : arch-audit, Lynis, rkhunter, Trivy et OSV-Scanner dans une seule interface.
//! Aucun shell dynamique, aucune donnée externe interprétée comme du balisage, aucun mot de passe manipulé.

mod advice;
mod aur;
mod clean;
mod depfix;
mod fwd;
mod global;
mod harden;
mod i18n;
mod live;
mod maint;
mod model;
mod pkginfo;
mod privileged;
mod procctl;
mod risk;
mod runner;
mod sshcfg;
mod tools;
mod tray;
mod tracker;
mod ufwrules;
mod verify;
mod ui;
mod util;

use adw::prelude::*;
use gtk::glib;
use gtk4 as gtk;
use libadwaita as adw;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use ui::{Ctx, dashboard::Dashboard, databases_page::DatabasesPage, global_page::GlobalPage, live_page::LivePage, tool_page::ToolPage};

const APP_ID: &str = "io.github.cachy_shield.CachyShield";

/// Lancé en arrière-plan (session ouverte) : seule l'icône de la zone de notification apparaît, sans fenêtre.
static BACKGROUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
const BACKGROUND_FLAG: &str = "--background";

fn main() -> glib::ExitCode {
    // mode assistant : lancé par pkexec (root) par ce même programme, sans interface graphique
    if std::env::args().nth(1).as_deref() == Some(privileged::HELPER_FLAG) {
        std::process::exit(privileged::helper_main());
    }
    util::migrate_legacy_dirs();
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    let args: Vec<String> = std::env::args().collect();
    BACKGROUND.store(args.iter().skip(1).any(|a| a == BACKGROUND_FLAG), std::sync::atomic::Ordering::Relaxed);
    // l'option est à nous : GTK ne doit pas la voir (il la refuserait)
    let rest: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != BACKGROUND_FLAG).collect();
    app.run_with_args(&rest)
}

fn build_ui(app: &adw::Application) {
    // déjà lancé (par exemple en arrière-plan) : on montre simplement la fenêtre existante
    if let Some(w) = app.windows().first() {
        w.present();
        return;
    }
    let background = BACKGROUND.load(std::sync::atomic::Ordering::Relaxed);
    let provider = gtk::CssProvider::new();
    provider.load_from_string(&format!("{}{}{}{}", ui::CSS, ui::CSS_SMART, ui::CSS_MODULES, ui::CSS_CLICK));
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
    }

    let loaded = util::load_state();
    // démarrage de session : seulement si l'icône est voulue et si la configuration initiale a été faite (sinon, rien ne s'affiche)
    if background && (!loaded.settings.tray || !loaded.settings.first_run_done) {
        app.quit();
        return;
    }
    i18n::set_override(&loaded.settings.language); // choix manuel de la langue, avant tout texte affiché
    let ctx = Rc::new(Ctx { state: RefCell::new(loaded), app: app.clone(), pending: RefCell::new(None), updating: std::cell::Cell::new(0), on_dirs: RefCell::new(None), tray: RefCell::new(None) });
    ctx.purge_stale(); // retire les résultats qui ne correspondent plus aux réglages
    // une seule demande de mot de passe administrateur, à la première action qui en a besoin ; les suivantes la réutilisent
    procctl::set_backend_pref(&ctx.state.borrow().settings.fw_backend);
    privileged::init(ctx.state.borrow().settings.single_auth);
    let stack = gtk::Stack::new();
    stack.set_hexpand(true);
    stack.set_transition_type(gtk::StackTransitionType::Crossfade);

    let order = ["arch-audit", "lynis", "rkhunter", "trivy", "osv-scanner"];
    let mut pages: HashMap<&'static str, Rc<ToolPage>> = HashMap::new();
    for tool in tools::all() {
        let key = tool.key;
        pages.insert(key, ToolPage::new(ctx.clone(), tool));
    }
    let pages = Rc::new(pages);

    // boutons « Corriger »
    let fix = gtk::Button::with_label(&crate::i18n::tr("Corriger : mettre à jour le système…"));
    fix.set_tooltip_text(Some("Liste les mises à jour, signale celles qui risquent de bloquer le système, puis demande confirmation."));
    let c = ctx.clone();
    fix.connect_clicked(move |_| ui::dialogs::system_update(&c, Box::new(|| {})));
    pages["arch-audit"].add_button(&fix);
    let fix2 = gtk::Button::with_label(&crate::i18n::tr("Corriger : proposer les correctifs…"));
    fix2.set_tooltip_text(Some("Aperçu sur une copie du projet (npm / Maven) avec évaluation du risque de casse. Vos fichiers ne sont pas modifiés."));
    let (c, p) = (ctx.clone(), pages["osv-scanner"].clone());
    fix2.connect_clicked(move |_| {
        let start = match p.values().0.get("target") {
            Some(tools::Val::S(s)) => s.clone(),
            _ => String::new(),
        };
        ui::dialogs::osv_fix_preview(&c, start, Box::new(|| {}));
    });
    pages["osv-scanner"].add_button(&fix2);

    let live = LivePage::new(ctx.clone());
    let global = GlobalPage::new(ctx.clone());
    let update_kev: Rc<dyn Fn()> = {
        let g = global.clone();
        Rc::new(move || g.update_kev())
    };
    let databases = DatabasesPage::new(ctx.clone(), update_kev);

    // tableau de bord
    let entries: Vec<(&'static str, &'static str, &'static str, bool)> = vec![
        ("arch-audit", "Paquets vulnérables", "Failles connues dans vos paquets pacman.", false),
        ("lynis", "Configuration (score Lynis)", "Score et recommandations de configuration.", true),
        ("rkhunter", "Rootkits", "Fichiers modifiés et portes dérobées.", false),
        ("trivy", "Bibliothèques et secrets", "Dépendances vulnérables et secrets exposés.", false),
        ("osv-scanner", "Dépendances de vos projets", "Failles de la base OSV dans vos fichiers de dépendances.", false),
    ];
    // « Avancé » : les tableaux techniques (un onglet par outil), pour ceux qui veulent tous les détails
    let advanced = gtk::Notebook::new();
    advanced.set_scrollable(true);
    let adv_idx: Rc<RefCell<HashMap<&'static str, u32>>> = Rc::new(RefCell::new(HashMap::new()));
    let go_to: Rc<dyn Fn(&str)> = {
        let (stack, adv, idx) = (stack.clone(), advanced.clone(), adv_idx.clone());
        Rc::new(move |k: &str| {
            if let Some(i) = idx.borrow().get(k) {
                stack.set_visible_child_name("advanced");
                adv.set_current_page(Some(*i));
            } else {
                stack.set_visible_child_name(k);
            }
        })
    };
    // un clic sur la notification des mises à jour ouvre la fenêtre sur la page « Mises à jour »
    {
        let (app2, go) = (app.clone(), go_to.clone());
        let act = gtk::gio::SimpleAction::new("show-updates", None);
        act.connect_activate(move |_, _| {
            if let Some(w) = app2.windows().first() {
                w.present();
            }
            go("maj");
        });
        app.add_action(&act);
    }
    let on_run: Rc<dyn Fn(&str)> = {
        let (pages, go_to)
 = (pages.clone(), go_to.clone());
        Rc::new(move |k: &str| {
            go_to(k);
            if let Some(p) = pages.get(k) {
                p.run();
            }
        })
    };
    let queue: Rc<RefCell<VecDeque<&'static str>>> = Rc::new(RefCell::new(VecDeque::new()));
    let all_running = Rc::new(Cell::new(false));
    let dash_cell: Rc<RefCell<Option<Rc<Dashboard>>>> = Rc::new(RefCell::new(None));

    let next: Rc<dyn Fn()> = {
        let (queue, pages, all_running, dash_cell, stack) = (queue.clone(), pages.clone(), all_running.clone(), dash_cell.clone(), stack.clone());
        let (entries2, ctx2) = (entries.clone(), ctx.clone());
        Rc::new(move || {
            loop {
                let Some(key) = queue.borrow_mut().pop_front() else {
                    all_running.set(false);
                    if let Some(d) = dash_cell.borrow().as_ref() {
                        d.all_btn.set_sensitive(true);
                        d.all_finished("Toutes les analyses sont terminées");
                    }
                    ctx2.notify("analyses-terminees", "Analyses terminées", "Toutes les analyses sont terminées : les résultats sont sur le tableau de bord.");
                    stack.set_visible_child_name("dashboard");
                    return;
                };
                if pages[key].run() {
                    let total = order.len();
                    let idx = total - queue.borrow().len();
                    if let Some(d) = dash_cell.borrow().as_ref() {
                        let title = entries2.iter().find(|e| e.0 == key).map(|e| e.1).unwrap_or(key);
                        d.all_progress((idx - 1) as f64 / total as f64, &format!("Analyse {idx} / {total} : {title}"));
                        d.card_running(key);
                    }
                    return;
                }
            }
        })
    };
    let on_all: Rc<dyn Fn()> = {
        let (queue, pages, all_running, dash_cell, next) = (queue.clone(), pages.clone(), all_running.clone(), dash_cell.clone(), next.clone());
        Rc::new(move || {
            if all_running.get() {
                return;
            }
            all_running.set(true);
            if let Some(d) = dash_cell.borrow().as_ref() {
                d.all_btn.set_sensitive(false);
            }
            pages["rkhunter"].panel.set_combo("action", "--check"); // « Tout analyser » = analyses, jamais une mise à jour
            *queue.borrow_mut() = order.iter().copied().collect();
            next();
        })
    };
    let dash = Rc::new(Dashboard::new(&entries, on_run, go_to.clone(), on_all));
    *dash_cell.borrow_mut() = Some(dash.clone());
    for (k, s) in ctx.state.borrow().tools.iter() {
        dash.show_result(k, &s.result);
    }
    for p in pages.values() {
        let (dash, all_running, next) = (dash.clone(), all_running.clone(), next.clone());
        p.on_done(move |key, res| {
            dash.show_result(key, res);
            if all_running.get() {
                next();
            }
        });
    }
    let d2 = dash.clone();
    live.on_update(move |fw, s| d2.show_live(fw, s.to_check, s.wanted, s.public));
    let d3 = dash.clone();
    global.on_kev(move |n| d3.show_kev(n));

    {
        // le champ « Dossiers à analyser » de l'outil suit la liste choisie par l'utilisateur
        let (c, p) = (ctx.clone(), pages["osv-scanner"].clone());
        let sync: Rc<dyn Fn()> = Rc::new(move || {
            let v: Vec<String> = c.state.borrow().settings.project_dirs.iter().filter(|d| ui::wizard::dir_ok(d)).cloned().collect();
            p.panel.set_text("target", &v.join(";"));
        });
        sync();
        *ctx.on_dirs.borrow_mut() = Some(sync);
    }
    let smart = ui::smart::SmartPage::new(ctx.clone(), pages.clone(), global.clone(), go_to.clone());
    let modules = ui::modules::build(ctx.clone(), pages.clone(), global.clone());
    ui::auto::start(ctx.clone(), global.clone());

    // Pages avancées : onglets techniques
    let adv_pages: Vec<(&'static str, &str, gtk::Widget)> = vec![
        ("dashboard", "Vue d'ensemble", dash.root.clone().upcast()),
        ("arch-audit", "Failles système", pages["arch-audit"].root.clone().upcast()),
        ("trivy", "Bibliothèques", pages["trivy"].root.clone().upcast()),
        ("osv-scanner", "Projets", pages["osv-scanner"].root.clone().upcast()),
        ("rkhunter", "Rootkits", pages["rkhunter"].root.clone().upcast()),
        ("lynis", "Configuration", pages["lynis"].root.clone().upcast()),
        ("global", "Failles mondiales", global.root.clone().upcast()),
        ("databases", "Bases de données", databases.root.clone().upcast()),
        ("live", "Réseau (détail)", live.root.clone().upcast()),
    ];
    for (i, (key, title, w)) in adv_pages.iter().enumerate() {
        advanced.append_page(w, Some(&gtk::Label::new(Some(title))));
        adv_idx.borrow_mut().insert(key, i as u32);
    }

    // Pages principales : le parcours simple, un module par couleur
    stack.add_named(&smart.root, Some("smart"));
    stack.add_named(&modules.protection, Some("protection"));
    stack.add_named(&modules.failles, Some("failles"));
    stack.add_named(&modules.maj, Some("maj"));
    stack.add_named(&modules.clean, Some("clean"));
    stack.add_named(&modules.reseau, Some("reseau"));
    stack.add_named(&modules.config, Some("config"));
    stack.add_named(&advanced, Some("advanced"));

    // barre latérale avec icônes
    let nav = gtk::ListBox::new();
    nav.add_css_class("navigation-sidebar");
    nav.set_selection_mode(gtk::SelectionMode::Single);
    let entries_nav = [
        ("smart", "Soin intelligent", "starred-symbolic"),
        ("protection", "Protection", "security-high-symbolic"),
        ("failles", "Failles", "dialog-warning-symbolic"),
        ("maj", "Mises à jour", "software-update-available-symbolic"),
        ("clean", "Nettoyage", "user-trash-symbolic"),
        ("reseau", "Réseau", "network-wired-symbolic"),
        ("config", "Configuration", "preferences-system-symbolic"),
        ("advanced", "Avancé", "applications-engineering-symbolic"),
    ];
    for (name, label, icon) in entries_nav {
        let r = gtk::ListBoxRow::new();
        r.set_widget_name(name);
        let b = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        b.add_css_class("nav-row");
        b.append(&gtk::Image::from_icon_name(icon));
        b.append(&gtk::Label::new(Some(crate::i18n::tr(label).as_str())));
        r.set_child(Some(&b));
        nav.append(&r);
    }
    let st2 = stack.clone();
    nav.connect_row_selected(move |_, row| {
        if let Some(r) = row {
            st2.set_visible_child_name(&r.widget_name());
        }
    });
    let nav2 = nav.clone();
    stack.connect_visible_child_name_notify(move |s| {
        let Some(name) = s.visible_child_name() else { return };
        let mut i = 0;
        while let Some(r) = nav2.row_at_index(i) {
            if r.widget_name() == name.as_str() {
                nav2.select_row(Some(&r));
                break;
            }
            i += 1;
        }
    });
    stack.set_visible_child_name("smart");
    nav.select_row(nav.row_at_index(0).as_ref());

    // sélecteur de langue : en bas de la barre latérale
    let side_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    nav.set_vexpand(false);
    side_box.append(&nav);
    let spacer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    spacer.set_vexpand(true);
    side_box.append(&spacer);
    let lang_dd = ui::smart::language_selector(&ctx);
    lang_dd.set_margin_start(12);
    lang_dd.set_margin_end(12);
    lang_dd.set_margin_top(8);
    lang_dd.set_margin_bottom(14);
    side_box.append(&lang_dd);
    let side = gtk::ScrolledWindow::builder().child(&side_box).hscrollbar_policy(gtk::PolicyType::Never).width_request(230).build();
    // le menu prend le dégradé de la page affichée : même couleur des deux côtés
    side.add_css_class("side");
    let side_class = Rc::new(std::cell::RefCell::new(String::from("side-smart")));
    let (side2, sc2) = (side.clone(), side_class.clone());
    stack.connect_visible_child_name_notify(move |s| {
        let Some(name) = s.visible_child_name() else { return };
        let new = format!("side-{name}");
        side2.remove_css_class(&sc2.borrow());
        side2.add_css_class(&new);
        *sc2.borrow_mut() = new;
    });
    side.add_css_class("side-smart");
    let body = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    body.append(&side);
    body.append(&stack);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&body));
    let win = adw::ApplicationWindow::builder().application(app).title(crate::i18n::tr("Cachy Shield").as_str()).default_width(1360).default_height(860).content(&toolbar).build();
    gtk::Window::set_default_icon_name("cachy-shield");
    if background {
        std::mem::forget(app.hold()); // le programme reste actif sans fenêtre visible
    } else {
        win.present();
    }
    ui::tr_tree::install();
    // icône de la zone de notification : seulement si le bureau en offre une et si l'utilisateur ne l'a pas désactivée
    if ctx.state.borrow().settings.tray {
        let (tx, rx) = async_channel::unbounded::<tray::Cmd>();
        match tray::start(tx) {
            Ok(handle) => {
                win.set_hide_on_close(true); // la croix de la fenêtre la cache ; « Quitter » de l'icône ferme le programme
                *ctx.tray.borrow_mut() = Some(handle.clone());
                let (w, st, a) = (win.clone(), stack.clone(), app.clone());
                glib::spawn_future_local(async move {
                    let _keep = handle;
                    while let Ok(cmd) = rx.recv().await {
                        match cmd {
                            tray::Cmd::Open => w.present(),
                            tray::Cmd::Page(p) => {
                                st.set_visible_child_name(p);
                                w.present();
                            }
                            tray::Cmd::Quit => a.quit(),
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("icône de notification indisponible : {e}");
                if background {
                    app.quit(); // sans icône ni fenêtre, rien ne servirait de rester
                }
            }
        }
    }
    // premier lancement : assistant de configuration (outils détectés, dossiers de projets, préférences)
    if !ctx.state.borrow().settings.first_run_done {
        let c = ctx.clone();
        glib::timeout_add_local_once(std::time::Duration::from_millis(600), move || ui::wizard::show_wizard(&c));
    }

    // Accès de test, compilé UNIQUEMENT en version de débogage (absent de la version de production).
    #[cfg(debug_assertions)]
    {
        if let Ok(p) = std::env::var("CS_PAGE") {
            stack.set_visible_child_name(&p);
        }
        if let Ok(kind) = std::env::var("CS_DEMO_DIALOG") {
            let ctx2 = ctx.clone();
            glib::timeout_add_seconds_local_once(2, move || {
                let up = |n: &str| risk::Update { name: n.into(), old: "1.0-1".into(), new: "1.1-1".into() };
                let (title, intro, adv) = match kind.as_str() {
                    "kev" => ("chromium", "Logiciel ciblé par des attaques réelles.", advice::for_kev("chromium", &[global::KevVuln { cve: "CVE-2026-87491".into(), name: "Google Chromium V8 Out-of-Bounds Write".into(), added: "2026-09-09".into(), due: "2026-09-23".into(), action: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.".into(), description: "d".into(), ..Default::default() }], &[up("chromium")])),
                    "dep" => ("pillow 9.5.0", "Bibliothèque d'un de vos projets avec une faille connue.", advice::for_dependency("PyPI", "pillow", "9.5.0", "10.0.1", &["/home/user/projet/requirements.txt".into()])),
                    "nofix" => ("grub", "Logiciel installé avec une faille connue.", advice::for_system_package("grub", "aucun", "CVE-2022-28737", &[])),
                    _ => ("openssl", "Logiciel installé avec une faille connue.", advice::for_system_package("openssl", "3.5.1", "CVE-2025-1000", &[up("openssl")])),
                };
                ui::actions::show_advice(&ctx2, title, intro, adv, vec![], Rc::new(|| {}));
            });
        }
    }
}
