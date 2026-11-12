//! Lignes cliquables et fenêtre de détail : « ce que l'application peut faire directement » séparé de
//! « la recommandation de la source (CVE, éditeur, outil) ». Une action n'est proposée que si elle est réellement possible.

use super::dialogs;
use super::{Ctx, open_https, plain_label};
use crate::advice::{self, Advice, Direct};
use crate::risk::{self, Update};
use crate::util::now_unix;
use adw::prelude::*;
use gtk4 as gtk;
use gtk::{gio, glib};
use libadwaita as adw;
use std::rc::Rc;

/// Mises à jour en attente, avec un cache de 60 s (évite de relancer checkupdates à chaque page).
pub async fn pending(ctx: &Rc<Ctx>) -> Vec<Update> {
    if let Some((t, v)) = ctx.pending.borrow().as_ref() {
        if now_unix() - *t < 60 {
            return v.clone();
        }
    }
    let (tx, rx) = async_channel::bounded::<Vec<Update>>(1);
    std::thread::spawn(move || {
        let _ = tx.send_blocking(risk::parse_updates(&dialogs::pending_updates_blocking()));
    });
    let v = rx.recv().await.unwrap_or_default();
    *ctx.pending.borrow_mut() = Some((now_unix(), v.clone()));
    v
}

pub fn invalidate_pending(ctx: &Ctx) {
    *ctx.pending.borrow_mut() = None;
}

/// Rend une ligne cliquable (chevron, survol, clic n'importe où sur la ligne).
pub fn clickable(row: gtk::Box, tip: &str, f: Rc<dyn Fn()>) -> gtk::Box {
    row.add_css_class("clickable");
    row.set_tooltip_text(Some(tip));
    row.set_cursor_from_name(Some("pointer"));
    let chevron = gtk::Image::from_icon_name("go-next-symbolic");
    chevron.set_valign(gtk::Align::Center);
    chevron.set_opacity(0.8);
    row.append(&chevron);
    let g = gtk::GestureClick::new();
    g.connect_released(move |_, _, _, _| f());
    row.add_controller(g);
    row
}

pub type Handler = (Direct, Rc<dyn Fn()>);

fn short_label(d: &Direct) -> String {
    match d {
        Direct::SystemUpdate { .. } => "Mettre à jour le système".into(),
        Direct::SshFix => "Interdire root en SSH".into(),
        Direct::SshRevert => "Annuler la correction".into(),
        Direct::IgnoreAlert => "C'est normal : ne plus signaler".into(),
        Direct::MarkWanted => "Autoriser".into(),
        Direct::OsvFixPreview => "Aperçu des correctifs".into(),
        Direct::CopyCommand { .. } => "Copier la commande".into(),
        Direct::StopProcess { .. } => "Arrêter le programme".into(),
        Direct::BlockPort { port, .. } => format!("Bloquer le port {port}"),
        Direct::UnblockPort { port, .. } => format!("Débloquer le port {port}"),
        Direct::BlockHosts { .. } => "Bloquer ces serveurs".into(),
        Direct::NpmFix { .. } => "Mettre à jour dans le projet".into(),
        Direct::AurUpdate { terminal: false, .. } => "Mettre à jour (relecture dans l'application)".into(),
        Direct::AurUpdate { .. } => "Mettre à jour dans un terminal".into(),
        Direct::LibFix { .. } => "Corriger…".into(),
        Direct::Reboot => "Redémarrer maintenant".into(),
    }
}

fn default_handler(ctx: &Rc<Ctx>, d: &Direct, handlers: &[Handler], refresh: Rc<dyn Fn()>) -> Rc<dyn Fn()> {
    if let Some((_, h)) = handlers.iter().find(|(k, _)| k == d) {
        return h.clone();
    }
    let ctx = ctx.clone();
    let after = move |ctx: &Rc<Ctx>, r: Rc<dyn Fn()>| -> Box<dyn FnOnce()> {
        invalidate_pending(ctx);
        let _ = ctx;
        Box::new(move || r())
    };
    match d.clone() {
        Direct::SystemUpdate { .. } => Rc::new(move || dialogs::system_update(&ctx, after(&ctx, refresh.clone()))),
        Direct::SshFix => Rc::new(move || dialogs::apply_ssh_fix(&ctx, after(&ctx, refresh.clone()))),
        Direct::SshRevert => Rc::new(move || dialogs::revert_ssh_fix(&ctx, after(&ctx, refresh.clone()))),
        Direct::OsvFixPreview => Rc::new(move || dialogs::osv_fix_preview(&ctx, String::new(), after(&ctx, refresh.clone()))),
        Direct::CopyCommand { command } => Rc::new(move || {
            if let Some(disp) = gtk::gdk::Display::default() {
                disp.clipboard().set_text(&command);
            }
            let n = gio::Notification::new("Commande copiée");
            n.set_body(Some(&command));
            ctx.app.send_notification(Some("commande-copiee"), &n);
        }),
        Direct::StopProcess { name, pids } => Rc::new(move || dialogs::stop_process(&ctx, &name, pids.clone(), after(&ctx, refresh.clone()))),
        Direct::BlockPort { proto, port } => Rc::new(move || dialogs::block_port(&ctx, proto.clone(), port, after(&ctx, refresh.clone()))),
        Direct::UnblockPort { proto, port } => Rc::new(move || dialogs::unblock_port(&ctx, proto.clone(), port, after(&ctx, refresh.clone()))),
        Direct::BlockHosts { ips } => Rc::new(move || dialogs::block_hosts(&ctx, ips.clone(), after(&ctx, refresh.clone()))),
        Direct::NpmFix { dir, name, fixed } => Rc::new(move || dialogs::npm_fix(&ctx, dir.clone(), name.clone(), fixed.clone(), after(&ctx, refresh.clone()))),
        Direct::AurUpdate { packages, terminal: false, .. } => Rc::new(move || dialogs::aur_inapp(&ctx, packages.clone(), after(&ctx, refresh.clone()))),
        Direct::AurUpdate { helper, packages, .. } => Rc::new(move || dialogs::aur_update(&ctx, helper.clone(), packages.clone(), after(&ctx, refresh.clone()))),
        Direct::Reboot => Rc::new(move || dialogs::reboot(&ctx, after(&ctx, refresh.clone()))),
        // sans gestionnaire fourni par l'appelant, une action locale est sans effet
        Direct::IgnoreAlert | Direct::MarkWanted | Direct::LibFix { .. } => Rc::new(|| {}),
    }
}

/// Fenêtre de détail d'un point : actions directes (boutons) + recommandation de la source + liens officiels.
pub fn show_advice(ctx: &Rc<Ctx>, heading: &str, intro: &str, a: Advice, handlers: Vec<Handler>, refresh: Rc<dyn Fn()>) {
    let d = adw::AlertDialog::new(Some(heading), Some(intro));
    let lbl = plain_label(&advice::render(&a));
    lbl.set_selectable(true);
    let sc = gtk::ScrolledWindow::builder().child(&lbl).min_content_height(170).max_content_height(380).min_content_width(540).build();
    d.set_extra_child(Some(&sc));
    d.add_response("close", "Fermer");
    d.set_close_response("close");
    d.set_default_response(Some("close"));
    let mut actions: Vec<(String, Rc<dyn Fn()>)> = Vec::new();
    for (i, direct) in a.direct.iter().enumerate() {
        let id = format!("d{i}");
        d.add_response(&id, &short_label(direct));
        if i == 0 {
            d.set_response_appearance(&id, adw::ResponseAppearance::Suggested);
        }
        actions.push((id, default_handler(ctx, direct, &handlers, refresh.clone())));
    }
    for (i, (label, url)) in a.links.iter().take(2).enumerate() {
        let id = format!("l{i}");
        d.add_response(&id, label);
        let url = url.clone();
        actions.push((id, Rc::new(move || open_https(&url))));
    }
    let parent = ctx.window();
    glib::spawn_future_local(async move {
        let r = d.choose_future(parent.as_ref()).await;
        if let Some((_, f)) = actions.iter().find(|(id, _)| id == r.as_str()) {
            f();
        }
    });
}

/// Mises à jour de l'AUR en attente (paru ou yay, lecture seule). Jamais installées automatiquement : relecture des PKGBUILD obligatoire.
pub async fn pending_aur() -> Vec<Update> {
    let (tx, rx) = async_channel::bounded::<Vec<Update>>(1);
    std::thread::spawn(move || {
        let _ = tx.send_blocking(risk::parse_updates(&dialogs::pending_aur_blocking()));
    });
    rx.recv().await.unwrap_or_default()
}
