//! Interface GTK4 / libadwaita.

pub mod actions;
pub mod auto;
pub mod dashboard;
pub mod databases_page;
pub mod global_page;
pub mod dialogs;
pub mod fwpanel;
pub mod live_page;
pub mod modules;
pub mod smart;
pub mod sshpanel;
pub mod options;
pub mod results;
pub mod tr_tree;
pub mod tool_page;
pub mod wizard;

use crate::util::{State, save_state};
use gtk4 as gtk;
use gtk::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Contexte partagé de l'application.
pub struct Ctx {
    pub state: RefCell<State>,
    pub app: libadwaita::Application,
    /// Mises à jour en attente (mises en cache 60 s).
    pub pending: RefCell<Option<(i64, Vec<crate::risk::Update>)>>,
    /// Nombre de mises à jour de bases de CVE en cours (affiché dans la bande du bas).
    pub updating: Cell<u32>,
    /// Appelé quand la liste des dossiers de projets change (met à jour l'analyse des projets).
    pub on_dirs: RefCell<Option<Rc<dyn Fn()>>>,
    /// Icône de la zone de notification (si elle existe) : reçoit le nombre de mises à jour en attente.
    pub tray: RefCell<Option<crate::tray::Handle>>,
}

impl Ctx {
    /// Met à jour l'icône de la zone de notification (état « attention » et nombre dans le menu).
    pub fn set_tray_updates(&self, n: usize) {
        if let Some(h) = self.tray.borrow().as_ref() {
            let _ = h.update(|t| t.updates = n);
        }
    }

    pub fn save(&self) {
        if let Err(e) = save_state(&self.state.borrow()) {
            eprintln!("sauvegarde de l'état impossible : {e}");
        }
    }

    /// La liste des dossiers a changé : l'ancien résultat de l'analyse des projets ne décrit plus ces dossiers, il est retiré.
    pub fn dirs_changed(&self) {
        if self.state.borrow_mut().tools.remove("osv-scanner").is_some() {
            self.save();
        }
        let f = self.on_dirs.borrow().clone();
        if let Some(f) = f {
            f();
        }
    }

    /// Au démarrage : retire les résultats qui ne correspondent plus aux réglages (aucun dossier de projets ; ancien périmètre Trivy).
    pub fn purge_stale(&self) {
        let mut changed = false;
        {
            let mut st = self.state.borrow_mut();
            if st.settings.project_dirs.is_empty() && st.tools.remove("osv-scanner").is_some() {
                changed = true;
            }
            if !st.settings.sys_scope_v2 {
                st.settings.sys_scope_v2 = true;
                st.tools.remove("trivy");
                changed = true;
            }
        }
        if changed {
            self.save();
        }
    }

    pub fn window(&self) -> Option<gtk::Window> {
        self.app.active_window()
    }

    /// Notification du bureau (KDE, GNOME, XFCE, Sway… via GNotification : portail ou serveur de notifications du bureau).
    /// Respecte le réglage « Notifications » ; le texte est traduit dans la langue du système.
    pub fn notify(&self, id: &str, title: &str, body: &str) {
        self.notify_action(id, title, body, None);
    }

    /// Comme `notify`, avec une action exécutée au clic sur la notification (ex. « app.show-updates »).
    pub fn notify_action(&self, id: &str, title: &str, body: &str, action: Option<&str>) {
        if !self.state.borrow().settings.notifications {
            return;
        }
        let n = gtk::gio::Notification::new(&crate::i18n::tr(title));
        if let Some(a) = action {
            n.set_default_action(a);
        }
        n.set_body(Some(&crate::i18n::tr(body)));
        n.set_priority(gtk::gio::NotificationPriority::High);
        n.set_icon(&gtk::gio::ThemedIcon::new("security-high"));
        self.app.send_notification(Some(id), &n);
    }
}

pub fn when(ts: i64) -> String {
    if ts <= 0 {
        return "jamais analysé".into();
    }
    gtk::glib::DateTime::from_unix_local(ts)
        .ok()
        .and_then(|d| d.format("%d/%m/%Y à %H:%M").ok())
        .map(|s| format!("analysé le {s}"))
        .unwrap_or_default()
}

/// Étiquette de texte brut (jamais de balisage : les données viennent de sources externes).
pub fn plain_label(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(crate::i18n::tr(text).as_str()));
    l.set_use_markup(false);
    l.set_xalign(0.0);
    l.set_wrap(true);
    l.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    l
}

pub const CSS: &str = r#"
.sev-pill { border-radius: 6px; padding: 1px 8px; font-weight: 600; }
.sev-critical { background: @error_bg_color; color: @error_fg_color; }
.sev-high { background: #e66100; color: white; }
.sev-medium { background: @warning_bg_color; color: @warning_fg_color; }
.sev-low { background: @accent_bg_color; color: @accent_fg_color; }
.sev-ok { background: @success_bg_color; color: @success_fg_color; }
.sev-unknown { background: alpha(@window_fg_color, 0.25); }
.lvl-bar { min-width: 6px; border-radius: 12px 0 0 12px; }
.lvl-ok { background: @success_bg_color; }
.lvl-warn { background: @warning_bg_color; }
.lvl-bad { background: @error_bg_color; }
.lvl-none { background: alpha(@window_fg_color, 0.25); }
.stat-warn { color: @warning_color; }
.stat-ok { color: @success_color; }
.mono { font-family: monospace; }
"#;

/// Ouvre une adresse https dans le navigateur par défaut (jamais un autre schéma).
pub fn open_https(url: &str) {
    if url.starts_with("https://") {
        let _ = gtk::gio::AppInfo::launch_default_for_uri(url, None::<&gtk::gio::AppLaunchContext>);
    }
}

pub const CSS_SMART: &str = r#"
.smart-bg { background: linear-gradient(160deg, #2b0a5c 0%, #5a1b8f 55%, #8c1f8f 100%); }
.smart-bg label { color: white; }
.smart-bg label.soft { color: alpha(white, 0.72); }
.smart-title { font-size: 30px; font-weight: 800; }
.smart-sub { font-size: 15px; }
.tile { background: alpha(white, 0.10); border: 1px solid alpha(white, 0.20); border-radius: 20px; padding: 14px 16px; }
.tile-protection { background: linear-gradient(145deg, alpha(#ff3da8, 0.42), alpha(white, 0.06)); }
.tile-failles { background: linear-gradient(145deg, alpha(#ff8a3d, 0.42), alpha(white, 0.06)); }
.tile-maj { background: linear-gradient(145deg, alpha(#35c46e, 0.40), alpha(white, 0.06)); }
.tile-config { background: linear-gradient(145deg, alpha(#3d8bff, 0.42), alpha(white, 0.06)); }
.tile-reseau { background: linear-gradient(145deg, alpha(#22c3b5, 0.40), alpha(white, 0.06)); }
.tile-clean { background: linear-gradient(145deg, alpha(#ffc83d, 0.42), alpha(white, 0.06)); }
.tile-off { opacity: 0.45; }
.tile-value { font-size: 25px; font-weight: 800; }
.tile-name { font-size: 12px; font-weight: 700; letter-spacing: 1px; }
.glass-btn { background: alpha(white, 0.16); color: white; border-radius: 12px; border: 1px solid alpha(white, 0.32); padding: 5px 14px; box-shadow: none; }
.glass-btn:hover { background: alpha(white, 0.28); }
.glass-btn label { color: white; }
.round-btn { min-width: 104px; min-height: 104px; border-radius: 52px; padding: 0; background: linear-gradient(145deg, #ff55dc, #9a1fe8); border: 2px solid alpha(white, 0.65); box-shadow: 0 0 34px alpha(#ff55dc, 0.75); }
.round-btn:hover { box-shadow: 0 0 46px alpha(#ff55dc, 0.95); }
.round-btn label { color: white; font-weight: 800; font-size: 17px; }
.strip { background: alpha(white, 0.10); border: 1px solid alpha(white, 0.16); border-radius: 16px; padding: 10px 16px; }
"#;

pub const CSS_MODULES: &str = r#"
.themed label { color: white; }
.themed label.soft { color: alpha(white, 0.72); }
.mod-protection { background: linear-gradient(160deg, #3d0a3a 0%, #7d1559 55%, #b81f78 100%); }
.mod-failles { background: linear-gradient(160deg, #431707 0%, #8a3a10 55%, #d0661e 100%); }
.mod-maj { background: linear-gradient(160deg, #0a3118 0%, #12663a 55%, #22a35a 100%); }
.mod-reseau { background: linear-gradient(160deg, #04272f 0%, #0b6a6c 55%, #16b0a4 100%); }
.mod-config { background: linear-gradient(160deg, #0a1a4d 0%, #1e3fa0 55%, #3a76e8 100%); }
.mod-clean { background: linear-gradient(160deg, #3a2a05 0%, #8a6410 55%, #d9a520 100%); }
.glass-row { background: alpha(white, 0.10); border: 1px solid alpha(white, 0.16); border-radius: 14px; padding: 10px 14px; }
.row-title { font-weight: 700; }
.section-title { font-weight: 800; font-size: 13px; letter-spacing: 1px; margin-top: 10px; }
.nav-row { padding: 9px 12px; border-radius: 10px; }
.nav-row image { opacity: 0.9; }
.side { background: linear-gradient(160deg, #2b0a5c 0%, #5a1b8f 55%, #8c1f8f 100%); }
.side-smart { background: linear-gradient(160deg, #2b0a5c 0%, #5a1b8f 55%, #8c1f8f 100%); }
.side-protection { background: linear-gradient(160deg, #3d0a3a 0%, #7d1559 55%, #b81f78 100%); }
.side-failles { background: linear-gradient(160deg, #431707 0%, #8a3a10 55%, #d0661e 100%); }
.side-maj { background: linear-gradient(160deg, #0a3118 0%, #12663a 55%, #22a35a 100%); }
.side-reseau { background: linear-gradient(160deg, #04272f 0%, #0b6a6c 55%, #16b0a4 100%); }
.side-config { background: linear-gradient(160deg, #0a1a4d 0%, #1e3fa0 55%, #3a76e8 100%); }
.side-advanced { background: linear-gradient(160deg, #1b1b24 0%, #2d2d3d 55%, #44445a 100%); }
.side-clean { background: linear-gradient(160deg, #3a2a05 0%, #8a6410 55%, #d9a520 100%); }
.side list, .side row, .side scrolledwindow, .side viewport { background: transparent; }
.side label { color: white; }
.side image { color: white; }
.side row { border-radius: 10px; margin: 2px 8px; }
.side row:hover { background: alpha(white, 0.12); }
.side row:selected { background: alpha(white, 0.24); }
"#;

pub const CSS_CLICK: &str = r#"
.clickable:hover { background: alpha(white, 0.20); }
.clickable { transition: background 120ms; }
.tile-click:hover { background: alpha(white, 0.16); }
.tile-click { transition: background 120ms; }
"#;
