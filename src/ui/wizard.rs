//! Assistant de premier lancement et gestion des dossiers de projets à analyser.
//! Rien n'est supposé de la machine : les outils présents sont détectés, les dossiers de projets sont choisis par l'utilisateur.

use super::{Ctx, plain_label};
use crate::util::abs_prog;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use libadwaita as adw;
use adw::prelude::*;
use std::rc::Rc;

/// (programme, paquet Arch, obligatoire pour une fonction essentielle ?)
const TOOLS: &[(&str, &str, &str)] = &[
    ("arch-audit", "arch-audit", "Failles connues des paquets Arch"),
    ("lynis", "lynis", "Audit de la configuration"),
    ("rkhunter", "rkhunter", "Recherche de rootkits"),
    ("trivy", "trivy", "Bibliothèques et secrets"),
    ("osv-scanner", "osv-scanner", "Dépendances de vos projets"),
    ("checkupdates", "pacman-contrib", "Liste des mises à jour"),
    ("ufw", "ufw", "Pare-feu (facultatif : ufw ou firewalld, sinon nftables)"),
    ("snapper", "snapper", "Instantanés de secours (facultatif)"),
];

/// Dossier de projet acceptable : chemin absolu, existant, ni la racine, ni un nom contenant le séparateur « ; » ou des caractères de contrôle.
pub fn dir_ok(p: &str) -> bool {
    p.starts_with('/') && p.len() > 1 && !p.contains(';') && !p.chars().any(|c| c.is_control()) && std::path::Path::new(p).is_dir()
}

fn fill(ctx: &Rc<Ctx>, list: &gtk::Box) {
    while let Some(c) = list.first_child() {
        list.remove(&c);
    }
    let dirs = ctx.state.borrow().settings.project_dirs.clone();
    if dirs.is_empty() {
        let l = plain_label("Aucun dossier pour le moment. Ajoutez les dossiers qui contiennent vos projets (Python, Node, Rust, Go…).");
        l.add_css_class("dim-label");
        list.append(&l);
    }
    for (i, d) in dirs.iter().enumerate() {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let l = gtk::Label::new(Some(d));
        l.set_xalign(0.0);
        l.set_hexpand(true);
        l.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        l.set_tooltip_text(Some(d));
        let b = gtk::Button::with_label(&crate::i18n::tr("Retirer"));
        let (ctx2, list2) = (ctx.clone(), list.clone());
        b.connect_clicked(move |_| {
            {
                let mut st = ctx2.state.borrow_mut();
                if i < st.settings.project_dirs.len() {
                    st.settings.project_dirs.remove(i);
                }
            }
            ctx2.save();
            ctx2.dirs_changed();
            fill(&ctx2, &list2);
        });
        row.append(&l);
        row.append(&b);
        list.append(&row);
    }
}

/// Liste modifiable des dossiers de projets + bouton d'ajout.
pub fn folders_editor(ctx: &Rc<Ctx>) -> gtk::Box {
    let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
    let list = gtk::Box::new(gtk::Orientation::Vertical, 6);
    fill(ctx, &list);
    let add = gtk::Button::with_label(&crate::i18n::tr("Ajouter un dossier…"));
    add.add_css_class("suggested-action");
    add.set_halign(gtk::Align::Start);
    let (ctx2, list2) = (ctx.clone(), list.clone());
    add.connect_clicked(move |_| {
        let (ctx3, list3) = (ctx2.clone(), list2.clone());
        glib::spawn_future_local(async move {
            let parent = ctx3.window();
            let Ok(f) = gtk::FileDialog::new().select_folder_future(parent.as_ref()).await else { return };
            let Some(p) = f.path() else { return };
            let dir = p.to_string_lossy().to_string();
            if !dir_ok(&dir) {
                let d = adw::AlertDialog::new(Some(&crate::i18n::tr("Dossier refusé")), Some(&crate::i18n::tr("Choisissez un dossier de projets précis (pas la racine du système), sans le caractère « ; » dans son chemin.")));
                d.add_response("close", &crate::i18n::tr("Fermer"));
                let _ = d.choose_future(parent.as_ref()).await;
                return;
            }
            {
                let mut st = ctx3.state.borrow_mut();
                if !st.settings.project_dirs.contains(&dir) {
                    st.settings.project_dirs.push(dir);
                }
            }
            ctx3.save();
            ctx3.dirs_changed();
            fill(&ctx3, &list3);
        });
    });
    root.append(&list);
    root.append(&add);
    root
}

/// Fenêtre « Dossiers de projets » (ouverte depuis la tuile « Vos projets »).
pub fn show_folders_dialog(ctx: &Rc<Ctx>, on_close: Rc<dyn Fn()>) {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    for m in [content.clone()] {
        m.set_margin_top(18);
        m.set_margin_bottom(18);
        m.set_margin_start(18);
        m.set_margin_end(18);
    }
    let t = plain_label("Dossiers de projets à analyser");
    t.add_css_class("title-3");
    t.set_xalign(0.0);
    let s = plain_label("L'analyse cherche, dans ces dossiers et leurs sous-dossiers, les fichiers de dépendances (requirements.txt, package-lock.json, Cargo.lock, go.mod…) et signale les bibliothèques qui ont une faille connue. Vos fichiers ne sont jamais modifiés sans votre accord.");
    s.set_xalign(0.0);
    s.set_wrap(true);
    content.append(&t);
    content.append(&s);
    content.append(&folders_editor(ctx));
    let done = gtk::Button::with_label(&crate::i18n::tr("Terminer"));
    done.add_css_class("suggested-action");
    done.set_halign(gtk::Align::End);
    done.set_margin_top(10);
    content.append(&done);
    // barre de titre avec croix de fermeture (la touche Échap ferme aussi la fenêtre)
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&content));
    let d = adw::Dialog::builder().title(crate::i18n::tr("Vos projets")).content_width(560).child(&toolbar).build();
    let d2 = d.clone();
    done.connect_clicked(move |_| {
        d2.close();
    });
    d.connect_closed(move |_| on_close());
    d.present(ctx.window().as_ref());
}

/// Assistant en trois étapes : outils détectés, dossiers de projets, préférences.
pub fn show_wizard(ctx: &Rc<Ctx>) {
    let stack = gtk::Stack::new();
    stack.set_vexpand(true);
    let page = |children: Vec<gtk::Widget>| {
        let b = gtk::Box::new(gtk::Orientation::Vertical, 10);
        b.set_margin_top(6);
        for c in children {
            b.append(&c);
        }
        b
    };
    let heading = |s: &str| {
        let l = plain_label(s);
        l.add_css_class("title-2");
        l.set_xalign(0.0);
        l
    };
    let text = |s: &str| {
        let l = plain_label(s);
        l.set_wrap(true);
        l.set_xalign(0.0);
        l
    };

    // 1 : outils
    let mut rows: Vec<gtk::Widget> = vec![heading("Bienvenue").upcast(), text("Ce programme analyse la sécurité de votre ordinateur en s'appuyant sur des outils reconnus. Voici ceux qui sont installés ici :").upcast()];
    let mut missing: Vec<&str> = Vec::new();
    for (prog, pkg, what) in TOOLS {
        let found = abs_prog(prog).is_some();
        if !found {
            missing.push(pkg);
        }
        let l = plain_label(&format!("{} {} — {}", if found { "✔" } else { "✘" }, prog, crate::i18n::tr(what)));
        l.set_xalign(0.0);
        rows.push(l.upcast());
    }
    if !missing.is_empty() {
        let cmd = format!("sudo pacman -S --needed {}", missing.join(" "));
        rows.push(text("Les outils absents ne bloquent pas le programme : les fonctions qui en dépendent sont simplement indisponibles. Pour les installer :").upcast());
        let c = gtk::Label::new(Some(&cmd));
        c.set_selectable(true);
        c.add_css_class("monospace");
        c.set_xalign(0.0);
        c.set_wrap(true);
        rows.push(c.clone().upcast());
        let b = gtk::Button::with_label(&crate::i18n::tr("Copier la commande"));
        b.set_halign(gtk::Align::Start);
        b.connect_clicked(move |btn| btn.display().clipboard().set_text(&cmd));
        rows.push(b.upcast());
    }
    stack.add_named(&page(rows), Some("tools"));

    // 2 : dossiers
    stack.add_named(&page(vec![heading("Vos projets").upcast(), text("Ajoutez les dossiers qui contiennent vos projets de programmation. Vous pourrez en ajouter ou en retirer plus tard (page Failles, tuile « Vos projets »). Cette étape est facultative.").upcast(), folders_editor(ctx).upcast()]), Some("dirs"));

    // 3 : préférences
    let sw = |label: &str, active: bool, set: Rc<dyn Fn(&crate::ui::Ctx, bool)>, ctx: &Rc<Ctx>| {
        let r = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let l = plain_label(label);
        l.set_hexpand(true);
        l.set_xalign(0.0);
        l.set_wrap(true);
        let s = gtk::Switch::new();
        s.set_active(active);
        s.set_valign(gtk::Align::Center);
        let c = ctx.clone();
        s.connect_state_set(move |_, on| {
            set(&c, on);
            c.save();
            glib::Propagation::Proceed
        });
        r.append(&l);
        r.append(&s);
        r
    };
    let st = ctx.state.borrow().settings.clone();
    stack.add_named(
        &page(vec![
            heading("Préférences").upcast(),
            sw("Mettre à jour automatiquement les bases de failles (CVE)", st.auto_update, Rc::new(|c, on| c.state.borrow_mut().settings.auto_update = on), ctx).upcast(),
            sw("Notifications du bureau (nouveau port ouvert, tentatives d'intrusion, fin d'analyse)", st.notifications, Rc::new(|c, on| c.state.borrow_mut().settings.notifications = on), ctx).upcast(),
            sw("Icône dans la zone de notification (au prochain lancement ; la croix de la fenêtre laisse alors le programme actif en arrière-plan)", st.tray, Rc::new(|c, on| c.state.borrow_mut().settings.tray = on), ctx).upcast(),
            sw("Demander le mot de passe administrateur une seule fois, au démarrage (au prochain lancement ; sinon il est redemandé à chaque action)", st.single_auth, Rc::new(|c, on| c.state.borrow_mut().settings.single_auth = on), ctx).upcast(),
            sw("Inclure les analyses administrateur (Lynis, rkhunter) dans « Analyser » : votre mot de passe sera demandé une fois", st.include_admin, Rc::new(|c, on| c.state.borrow_mut().settings.include_admin = on), ctx).upcast(),
            text("Rien n'est modifié sur votre système sans une confirmation de votre part, et le pare-feu n'est jamais activé automatiquement.").upcast(),
        ]),
        Some("prefs"),
    );

    let order = ["tools", "dirs", "prefs"];
    let back = gtk::Button::with_label(&crate::i18n::tr("Précédent"));
    let next = gtk::Button::with_label(&crate::i18n::tr("Suivant"));
    next.add_css_class("suggested-action");
    let skip = gtk::Button::with_label(&crate::i18n::tr("Passer"));
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    bar.set_margin_top(10);
    bar.append(&skip);
    let sp = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    sp.set_hexpand(true);
    bar.append(&sp);
    bar.append(&back);
    bar.append(&next);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    for m in [content.clone()] {
        m.set_margin_top(18);
        m.set_margin_bottom(18);
        m.set_margin_start(22);
        m.set_margin_end(22);
    }
    content.append(&stack);
    content.append(&bar);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&content));
    let d = adw::Dialog::builder().title(crate::i18n::tr("Assistant de configuration")).content_width(620).content_height(560).child(&toolbar).build();

    let idx = Rc::new(std::cell::Cell::new(0usize));
    let update: Rc<dyn Fn()> = {
        let (stack, back, next, idx) = (stack.clone(), back.clone(), next.clone(), idx.clone());
        Rc::new(move || {
            stack.set_visible_child_name(order[idx.get()]);
            back.set_sensitive(idx.get() > 0);
            next.set_label(&crate::i18n::tr(if idx.get() + 1 == order.len() { "Terminer" } else { "Suivant" }));
        })
    };
    update();
    let (idx2, upd2) = (idx.clone(), update.clone());
    back.connect_clicked(move |_| {
        idx2.set(idx2.get().saturating_sub(1));
        upd2();
    });
    let (idx3, upd3, d3, ctx3) = (idx.clone(), update.clone(), d.clone(), ctx.clone());
    next.connect_clicked(move |_| {
        if idx3.get() + 1 >= order.len() {
            ctx3.state.borrow_mut().settings.first_run_done = true;
            ctx3.save();
            d3.close();
        } else {
            idx3.set(idx3.get() + 1);
            upd3();
        }
    });
    let (d4, ctx4) = (d.clone(), ctx.clone());
    skip.connect_clicked(move |_| {
        ctx4.state.borrow_mut().settings.first_run_done = true;
        ctx4.save();
        d4.close();
    });
    d.present(ctx.window().as_ref());
}

// ───────────────────── éditeur de règles de pare-feu (sans rien activer) ─────────────────────

pub fn fill_rules_pub(ctx: &Rc<Ctx>, list: &gtk::Box) {
    fill_rules(ctx, list)
}

fn fill_rules(ctx: &Rc<Ctx>, list: &gtk::Box) {
    while let Some(c) = list.first_child() {
        list.remove(&c);
    }
    let rules = ctx.state.borrow().fw_rules.clone();
    if rules.is_empty() {
        let l = plain_label("Aucune règle personnalisée. Les services que vous avez marqués « autorisés » restent autorisés automatiquement.");
        l.add_css_class("dim-label");
        l.set_wrap(true);
        l.set_xalign(0.0);
        list.append(&l);
    }
    for (i, r) in rules.iter().enumerate() {
        let verb = match r.action.as_str() {
            "deny" => crate::i18n::tr("Refuser"),
            "limit" => crate::i18n::tr("Limiter"),
            _ => crate::i18n::tr("Autoriser"),
        };
        let from = if r.from.is_empty() { crate::i18n::tr("depuis n'importe où") } else { format!("{} {}", crate::i18n::tr("depuis"), r.from) };
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let l = gtk::Label::new(Some(&format!("{verb} · {} {} · {from}", r.proto.to_uppercase(), r.port)));
        l.set_xalign(0.0);
        l.set_hexpand(true);
        let b = gtk::Button::with_label(&crate::i18n::tr("Supprimer"));
        let (ctx2, list2) = (ctx.clone(), list.clone());
        b.connect_clicked(move |_| {
            {
                let mut st = ctx2.state.borrow_mut();
                if i < st.fw_rules.len() {
                    st.fw_rules.remove(i);
                }
            }
            ctx2.save();
            fill_rules(&ctx2, &list2);
        });
        row.append(&l);
        row.append(&b);
        list.append(&row);
    }
}

/// Fenêtre « Règles du pare-feu » : on modifie les règles à tout moment, pare-feu éteint ou allumé.
/// Rien n'est appliqué au système ici : les règles sont enregistrées et appliquées à l'activation (ou à la mise à jour).
pub fn show_fw_editor(ctx: &Rc<Ctx>, on_close: Rc<dyn Fn()>) {
    super::fwpanel::show(ctx, on_close)
}

#[allow(dead_code)]
fn show_fw_editor_own(ctx: &Rc<Ctx>, on_close: Rc<dyn Fn()>) {
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    for m in [content.clone()] {
        m.set_margin_top(18);
        m.set_margin_bottom(18);
        m.set_margin_start(18);
        m.set_margin_end(18);
    }
    let t = plain_label("Règles du pare-feu");
    t.add_css_class("title-3");
    t.set_xalign(0.0);
    let s = plain_label("Modifiez vos règles ici, même si le pare-feu est éteint : rien n'est changé sur votre système maintenant. Les règles sont appliquées quand vous activez le pare-feu (ou le mettez à jour). Les services marqués « autorisés » sont toujours autorisés.");
    s.set_xalign(0.0);
    s.set_wrap(true);
    let list = gtk::Box::new(gtk::Orientation::Vertical, 6);
    fill_rules(ctx, &list);
    let add = gtk::Button::with_label(&crate::i18n::tr("Ajouter une règle…"));
    add.add_css_class("suggested-action");
    add.set_halign(gtk::Align::Start);
    let (ctx2, list2) = (ctx.clone(), list.clone());
    add.connect_clicked(move |_| {
        let (ctx3, list3) = (ctx2.clone(), list2.clone());
        super::dialogs::add_fw_rule(&ctx2, Box::new(move || fill_rules(&ctx3, &list3)));
    });
    let log = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let sw = gtk::Switch::new();
    sw.set_valign(gtk::Align::Center);
    sw.set_active(ctx.state.borrow().settings.fw_log);
    let c4 = ctx.clone();
    sw.connect_state_set(move |_, on| {
        c4.state.borrow_mut().settings.fw_log = on;
        c4.save();
        glib::Propagation::Proceed
    });
    log.append(&sw);
    log.append(&plain_label("Journaliser les connexions refusées"));
    let done = gtk::Button::with_label(&crate::i18n::tr("Terminer"));
    done.add_css_class("suggested-action");
    done.set_halign(gtk::Align::End);
    for w in [t.upcast::<gtk::Widget>(), s.upcast(), list.upcast(), add.upcast(), log.upcast(), done.clone().upcast()] {
        content.append(&w);
    }
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&content));
    let d = adw::Dialog::builder().title(crate::i18n::tr("Pare-feu")).content_width(580).child(&toolbar).build();
    let d2 = d.clone();
    done.connect_clicked(move |_| {
        d2.close();
    });
    d.connect_closed(move |_| on_close());
    d.present(ctx.window().as_ref());
}
