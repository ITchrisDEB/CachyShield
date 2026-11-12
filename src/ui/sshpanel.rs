//! Fenêtre « Réglages SSH » : toutes les options courantes de sshd, groupées par thème, avec explications, valeur par défaut,
//! valeur recommandée et mises en garde. Les changements vont dans UN fichier géré (10-cachy-shield.conf) via un script
//! contrôlé : sauvegarde, `sshd -t`, retour arrière automatique, rechargement sans couper les sessions ouvertes.

use super::{Ctx, dialogs};
use crate::sshcfg::{self, CATALOGUE, CATEGORIES, Kind, Level, Opt};
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use libadwaita as adw;
use adw::prelude::*;
use std::collections::HashMap;
use std::rc::Rc;

fn t(s: &str) -> String {
    crate::i18n::tr(s)
}

enum Control {
    /// valeurs possibles ("" = par défaut), menu déroulant
    Combo(gtk::DropDown, Vec<&'static str>),
    Entry(gtk::Entry),
}

impl Control {
    fn get(&self) -> Option<String> {
        match self {
            Control::Combo(d, vals) => vals.get(d.selected() as usize).filter(|v| !v.is_empty()).map(|v| v.to_string()),
            Control::Entry(e) => Some(e.text().trim().to_string()).filter(|s| !s.is_empty()),
        }
    }

    fn set(&self, v: Option<&str>) {
        match self {
            Control::Combo(d, vals) => d.set_selected(v.and_then(|v| vals.iter().position(|x| *x == v)).unwrap_or(0) as u32),
            Control::Entry(e) => e.set_text(v.unwrap_or("")),
        }
    }
}

fn service_active() -> bool {
    crate::util::abs_prog("systemctl").is_some_and(|p| ["sshd", "ssh"].iter().any(|u| std::process::Command::new(&p).args(["is-active", u]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false)))
}

fn installed() -> bool {
    std::path::Path::new(sshcfg::MAIN_CONF).exists() && crate::util::abs_prog("sshd").is_some()
}

/// Ouvre la fenêtre des réglages SSH.
pub fn show(ctx: &Rc<Ctx>, on_close: Rc<dyn Fn()>) {
    let body = gtk::Box::new(gtk::Orientation::Vertical, 14);
    for m in [body.clone()] {
        m.set_margin_top(14);
        m.set_margin_bottom(18);
        m.set_margin_start(18);
        m.set_margin_end(18);
    }
    let scroll = gtk::ScrolledWindow::builder().child(&body).vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&scroll));
    let dialog = adw::Dialog::builder().title(t("Réglages SSH")).content_width(780).content_height(720).child(&toolbar).build();

    let title = gtk::Label::new(Some(&t("Réglages du serveur SSH")));
    title.add_css_class("title-3");
    title.set_xalign(0.0);
    body.append(&title);
    if !installed() {
        let l = gtk::Label::new(Some(&t("Le serveur SSH (OpenSSH) n'est pas installé sur cet ordinateur : il n'y a rien à régler. Installez le paquet « openssh » si vous voulez vous connecter à distance.")));
        l.set_wrap(true);
        l.set_xalign(0.0);
        body.append(&l);
        dialog.connect_closed(move |_| on_close());
        dialog.present(ctx.window().as_ref());
        return;
    }
    let active = service_active();
    let status = gtk::Label::new(Some(&format!("{} : {}", t("État du service SSH"), if active { t("actif") } else { t("arrêté (les réglages s'appliqueront à son démarrage)") })));
    status.set_xalign(0.0);
    status.set_wrap(true);
    body.append(&status);
    let intro = gtk::Label::new(Some(&t("Chaque ligne laissée sur « Par défaut » n'est pas modifiée : SSH garde sa valeur d'origine. Vos choix sont écrits dans un seul fichier de l'application, jamais dans votre sshd_config. Avant d'appliquer : sauvegarde, contrôle de la configuration, retour arrière automatique si elle est invalide, rechargement sans couper vos sessions ouvertes. Gardez une session ouverte et testez une nouvelle connexion avant de la fermer.")));
    intro.set_wrap(true);
    intro.set_xalign(0.0);
    intro.add_css_class("dim-label");
    body.append(&intro);

    let current = sshcfg::effective_from_files(true);
    let managed = sshcfg::read_managed();
    let mut controls: Vec<(&'static Opt, Control)> = Vec::new();
    for cat in CATEGORIES {
        let group = adw::PreferencesGroup::new();
        group.set_title(&t(cat));
        for o in CATALOGUE.iter().filter(|o| o.cat == cat) {
            let row = adw::ActionRow::new();
            row.set_use_markup(false);
            row.set_title(&t(o.label));
            let mut sub = t(o.desc);
            sub += &format!("\n{} : {}", t("Par défaut"), t(o.default));
            if let Some(r) = o.rec {
                sub += &format!(" · {} : {}", t("Recommandé"), r);
            }
            if let Some(c) = current.get(o.key) {
                sub += &format!(" · {} : {}", t("En vigueur"), c);
            }
            if let Some(w) = o.risk {
                sub += &format!("\n⚠ {}", t(w));
            }
            row.set_subtitle(&sub);
            row.set_subtitle_lines(0);
            let ctl = match o.kind {
                Kind::Bool => {
                    let d = gtk::DropDown::from_strings(&[&t("Par défaut"), &t("Oui"), &t("Non")]);
                    Control::Combo(d, vec!["", "yes", "no"])
                }
                Kind::Enum(vals) => {
                    let mut labels = vec![t("Par défaut")];
                    labels.extend(vals.iter().map(|v| v.to_string()));
                    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
                    let mut values = vec![""];
                    values.extend(vals.iter().copied());
                    Control::Combo(gtk::DropDown::from_strings(&refs), values)
                }
                Kind::Int(..) | Kind::Text(_) => {
                    let e = gtk::Entry::builder().placeholder_text(t("Par défaut")).width_chars(if matches!(o.kind, Kind::Int(..)) { 8 } else { 26 }).build();
                    e.set_valign(gtk::Align::Center);
                    Control::Entry(e)
                }
            };
            match &ctl {
                Control::Combo(d, _) => {
                    d.set_valign(gtk::Align::Center);
                    row.add_suffix(d);
                }
                Control::Entry(e) => row.add_suffix(e),
            }
            ctl.set(managed.get(o.key).map(String::as_str));
            group.add(&row);
            controls.push((o, ctl));
        }
        body.append(&group);
    }
    let controls = Rc::new(controls);

    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    bar.set_halign(gtk::Align::End);
    let rec = gtk::Button::with_label(&t("Remplir les valeurs recommandées"));
    rec.set_tooltip_text(Some(&t("Remplit les champs avec les valeurs de durcissement courantes. Rien n'est appliqué tant que vous ne cliquez pas sur « Appliquer ».")));
    let c1 = controls.clone();
    rec.connect_clicked(move |_| {
        for (o, c) in c1.iter() {
            if let Some(r) = o.rec {
                c.set(Some(r));
            }
        }
    });
    let reset = gtk::Button::with_label(&t("Tout remettre par défaut"));
    let c2 = controls.clone();
    reset.connect_clicked(move |_| {
        for (_, c) in c2.iter() {
            c.set(None);
        }
    });
    let apply = gtk::Button::with_label(&t("Appliquer"));
    apply.add_css_class("suggested-action");
    let (ctx2, c3, d3) = (ctx.clone(), controls.clone(), dialog.clone());
    apply.connect_clicked(move |_| {
        let (ctx, c, d) = (ctx2.clone(), c3.clone(), d3.clone());
        glib::spawn_future_local(async move {
            let mut chosen: Vec<(&'static str, String)> = Vec::new();
            for (o, ctl) in c.iter() {
                if let Some(raw) = ctl.get() {
                    match sshcfg::validate(o, &raw) {
                        Ok(v) => chosen.push((o.key, v)),
                        Err(e) => {
                            let a = dialogs::alert("Valeur invalide", &format!("{} : {}", t(o.label), t(&e)), &[("ok", "Fermer")]);
                            let _ = a.choose_future(ctx.window().as_ref()).await;
                            return;
                        }
                    }
                }
            }
            let d2 = d.clone();
            apply_changes(&ctx, chosen, Box::new(move || {
                d2.close();
            }));
        });
    });
    for b in [&rec, &reset, &apply] {
        bar.append(b);
    }
    body.append(&bar);
    dialog.connect_closed(move |_| on_close());
    dialog.present(ctx.window().as_ref());
}

/// Applique un ensemble de réglages (le fichier géré est entièrement remplacé par `chosen` ; vide = retrait du fichier).
/// Vérifie les risques de verrouillage, demande confirmation, puis lance le script contrôlé.
pub fn apply_changes(ctx: &Rc<Ctx>, chosen: Vec<(&'static str, String)>, then: Box<dyn FnOnce()>) {
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        let guard = Guard(Some(then));
        let old = sshcfg::read_managed();
        let new: HashMap<&'static str, String> = chosen.iter().cloned().collect();
        if old == new {
            let a = dialogs::alert("Aucun changement", "Les réglages choisis sont déjà ceux du fichier de l'application.", &[("ok", "Fermer")]);
            let _ = a.choose_future(ctx.window().as_ref()).await;
            return;
        }
        // risques de verrouillage
        let env = sshcfg::detect_env();
        let found = sshcfg::risks(&new, &sshcfg::effective_from_files(true), &env);
        let blocks: Vec<&str> = found.iter().filter(|(l, _)| *l == Level::Block).map(|(_, m)| m.as_str()).collect();
        if !blocks.is_empty() {
            let msg = blocks.iter().map(|m| format!("• {}", t(m))).collect::<Vec<_>>().join("\n");
            let a = dialogs::alert("Réglage refusé : vous seriez enfermé dehors", &msg, &[("ok", "Fermer")]);
            let _ = a.choose_future(ctx.window().as_ref()).await;
            return;
        }
        let confirms: Vec<&str> = found.iter().filter(|(l, _)| *l == Level::Confirm).map(|(_, m)| m.as_str()).collect();
        if !confirms.is_empty() {
            let msg = confirms.iter().map(|m| format!("• {}", t(m))).collect::<Vec<_>>().join("\n");
            let a = dialogs::alert("Attention : risque de perdre l'accès à distance", &msg, &[("cancel", "Annuler"), ("go", "Appliquer quand même")]);
            a.set_response_appearance("go", adw::ResponseAppearance::Destructive);
            a.set_default_response(Some("cancel"));
            a.set_close_response("cancel");
            if a.choose_future(ctx.window().as_ref()).await != "go" {
                return;
            }
        }
        // résumé des changements
        let mut lines: Vec<String> = Vec::new();
        for o in CATALOGUE {
            match (old.get(o.key), new.get(o.key)) {
                (None, Some(n)) => lines.push(format!("• {} : {} → {}", o.key, t("par défaut"), n)),
                (Some(a), Some(b)) if a != b => lines.push(format!("• {} : {} → {}", o.key, a, b)),
                (Some(a), None) => lines.push(format!("• {} : {} → {}", o.key, a, t("par défaut"))),
                _ => {}
            }
        }
        let body = format!("{}\n\n{}", lines.join("\n"), t("Sécurités : instantané de secours (snapper) · contrôle « sshd -t » · retour arrière automatique si la configuration est invalide · rechargement sans couper vos sessions ouvertes. Gardez une session ouverte et testez une nouvelle connexion avant de la fermer."));
        let a = dialogs::alert("Appliquer ces réglages SSH ?", &body, &[("cancel", "Annuler"), ("go", "Appliquer")]);
        a.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        a.set_default_response(Some("cancel"));
        a.set_close_response("cancel");
        if a.choose_future(ctx.window().as_ref()).await != "go" {
            return;
        }
        let content = sshcfg::render(&chosen);
        let plan = dialogs::admin_args_plan(sshcfg::APPLY_SCRIPT, &[content]);
        dialogs::run_command(ctx.window(), "Réglages SSH", plan, None, move |dlg, code, _| {
            let _g = guard;
            match code {
                0 => dlg.notice("Réglages appliqués. Testez une nouvelle connexion avant de fermer votre session actuelle."),
                2..=9 => dlg.notice("Rien n'a été conservé : un contrôle de sécurité a empêché la modification (voir le message ci-dessus)."),
                _ => dlg.notice("L'opération a échoué ou a été annulée : rien n'a été modifié."),
            }
        });
    });
}

/// Exécute une action à sa destruction (comme dans dialogs : prévenir l'appelant à chaque sortie).
struct Guard(Option<Box<dyn FnOnce()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// « Interdire la connexion root » (correction rapide) : fusionne ce réglage avec ceux déjà enregistrés.
pub fn set_root_login_no(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let mut m: Vec<(&'static str, String)> = sshcfg::read_managed().into_iter().filter(|(k, _)| *k != "PermitRootLogin").collect();
    m.push(("PermitRootLogin", "no".into()));
    apply_changes(ctx, m, then);
}

/// Annule « Interdire la connexion root » sans toucher aux autres réglages.
pub fn unset_root_login(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let m: Vec<(&'static str, String)> = sshcfg::read_managed().into_iter().filter(|(k, _)| *k != "PermitRootLogin").collect();
    apply_changes(ctx, m, then);
}

pub fn root_login_blocked() -> bool {
    sshcfg::read_managed().get("PermitRootLogin").is_some_and(|v| v == "no")
}
