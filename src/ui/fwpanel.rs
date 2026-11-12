//! Fenêtre « Pare-feu » : s'adapte au pare-feu détecté (ufw, firewalld ou nftables intégré) et laisse choisir quand plusieurs sont installés.
//! • ufw : règles enregistrées dans /etc/ufw (lecture et écriture avec droits administrateur, pare-feu actif ou non).
//! • firewalld : zones, services, ports, sources, règles riches, blocs ICMP… lus dans /etc/firewalld sans droits, modifiés dans la configuration permanente.
//! • nftables intégré : l'ancien éditeur de règles de l'application.
//! Rien ici n'active ni ne désactive le pare-feu : les changements sont enregistrés et s'appliquent à l'activation (ou, s'il est déjà actif, selon la mention affichée).

use super::{Ctx, dialogs, plain_label};
use crate::fwd;
use crate::procctl::{self, FwBackend};
use crate::ufwrules;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use libadwaita as adw;
use adw::prelude::*;
use std::rc::Rc;

thread_local! {
    /// Bandeau « opération en cours » de la fenêtre ouverte.
    static BUSY: std::cell::RefCell<Option<gtk::Box>> = const { std::cell::RefCell::new(None) };
}

/// Exécute une commande administrateur en montrant « Opération en cours… » (le mot de passe peut être demandé).
async fn run_root(plan: &crate::tools::Plan) -> (i32, String) {
    let busy = BUSY.with(|b| b.borrow().clone());
    if let Some(b) = &busy {
        b.set_visible(true);
    }
    let r = dialogs::run_capture(plan).await;
    if let Some(b) = &busy {
        b.set_visible(false);
    }
    r
}

fn t(s: &str) -> String {
    crate::i18n::tr(s)
}

fn backend_label(b: FwBackend) -> String {
    match b {
        FwBackend::Ufw => "ufw".into(),
        FwBackend::Firewalld => "firewalld".into(),
        FwBackend::Own => t("nftables (intégré à l'application)"),
    }
}

fn clear(b: &gtk::Box) {
    while let Some(c) = b.first_child() {
        b.remove(&c);
    }
}

fn heading(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(&t(text)));
    l.add_css_class("heading");
    l.set_xalign(0.0);
    l.set_margin_top(10);
    l
}

fn note(text: &str) -> gtk::Label {
    let l = plain_label(text);
    l.add_css_class("dim-label");
    l.set_wrap(true);
    l.set_xalign(0.0);
    l
}

fn line(text: &str, btn: Option<(&str, Box<dyn Fn()>)>) -> gtk::Box {
    let r = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let l = gtk::Label::new(Some(text));
    l.set_xalign(0.0);
    l.set_hexpand(true);
    l.set_wrap(true);
    r.append(&l);
    if let Some((label, f)) = btn {
        let b = gtk::Button::with_label(&t(label));
        b.connect_clicked(move |_| f());
        r.append(&b);
    }
    r
}

fn button(label: &str, f: impl Fn() + 'static) -> gtk::Button {
    let b = gtk::Button::with_label(&t(label));
    b.set_halign(gtk::Align::Start);
    b.connect_clicked(move |_| f());
    b
}

/// Relance l'affichage du panneau (après une modification).
fn refill_later(ctx: &Rc<Ctx>, body: &gtk::Box) {
    let (c, b) = (ctx.clone(), body.clone());
    glib::idle_add_local_once(move || fill(&c, &b));
}

async fn info(ctx: &Rc<Ctx>, heading_text: &str, text: &str) {
    let d = dialogs::alert(heading_text, text, &[("ok", "Fermer")]);
    let _ = d.choose_future(ctx.window().as_ref()).await;
}

/// Demande confirmation (réponse « go »).
async fn confirm(ctx: &Rc<Ctx>, title: &str, text: &str, go: &str) -> bool {
    let d = dialogs::alert(title, text, &[("cancel", "Annuler"), ("go", go)]);
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    d.choose_future(ctx.window().as_ref()).await == "go"
}

/// Formulaire : lignes « libellé : champ ». Renvoie true si l'utilisateur valide.
async fn form(ctx: &Rc<Ctx>, title: &str, intro: &str, rows: Vec<(&str, gtk::Widget)>, ok: &str) -> bool {
    let d = adw::AlertDialog::new(Some(&t(title)), Some(&t(intro)));
    let grid = gtk::Grid::builder().row_spacing(8).column_spacing(10).margin_top(6).build();
    for (i, (label, w)) in rows.iter().enumerate() {
        let l = gtk::Label::new(Some(&t(label)));
        l.set_xalign(0.0);
        grid.attach(&l, 0, i as i32, 1, 1);
        w.set_hexpand(true);
        grid.attach(w, 1, i as i32, 1, 1);
    }
    d.set_extra_child(Some(&grid));
    d.add_response("cancel", &t("Annuler"));
    d.add_response("ok", &t(ok));
    d.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    d.set_default_response(Some("ok"));
    d.set_close_response("cancel");
    d.choose_future(ctx.window().as_ref()).await == "ok"
}

fn dropdown(items: &[&str], selected: u32) -> gtk::DropDown {
    let tr: Vec<String> = items.iter().map(|s| t(s)).collect();
    let refs: Vec<&str> = tr.iter().map(String::as_str).collect();
    let d = gtk::DropDown::from_strings(&refs);
    d.set_selected(selected);
    d
}

fn entry(placeholder: &str) -> gtk::Entry {
    gtk::Entry::builder().placeholder_text(t(placeholder)).hexpand(true).build()
}

fn sel(d: &gtk::DropDown, values: &[&'static str]) -> &'static str {
    values.get(d.selected() as usize).copied().unwrap_or(values[0])
}

/// Ouvre la fenêtre « Pare-feu ».
pub fn show(ctx: &Rc<Ctx>, on_close: Rc<dyn Fn()>) {
    let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
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
    let d = adw::Dialog::builder().title(t("Pare-feu")).content_width(720).content_height(680).child(&toolbar).build();
    fill(ctx, &body);
    d.connect_closed(move |_| on_close());
    d.present(ctx.window().as_ref());
}

fn fill(ctx: &Rc<Ctx>, body: &gtk::Box) {
    clear(body);
    let avail = procctl::available_backends();
    let cur = procctl::fw_backend();
    let title = plain_label("Règles du pare-feu");
    title.add_css_class("title-3");
    title.set_xalign(0.0);
    body.append(&title);
    let busy = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let sp = gtk::Spinner::new();
    sp.start();
    busy.append(&sp);
    busy.append(&plain_label("Opération en cours… (une fenêtre peut demander votre mot de passe)"));
    busy.set_visible(false);
    BUSY.with(|b| *b.borrow_mut() = Some(busy.clone()));
    body.append(&busy);
    // choix du pare-feu quand plusieurs sont disponibles
    if avail.iter().filter(|b| **b != FwBackend::Own).count() > 1 {
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
        row.append(&plain_label("Pare-feu utilisé"));
        let labels: Vec<String> = avail.iter().map(|b| backend_label(*b)).collect();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        let dd = gtk::DropDown::from_strings(&refs);
        dd.set_selected(avail.iter().position(|b| *b == cur).unwrap_or(0) as u32);
        let (c, b2, av) = (ctx.clone(), body.clone(), avail.clone());
        dd.connect_selected_notify(move |d| {
            if let Some(b) = av.get(d.selected() as usize) {
                if *b != procctl::fw_backend() {
                    c.state.borrow_mut().settings.fw_backend = b.id().to_string();
                    c.save();
                    procctl::set_backend_pref(b.id());
                    refill_later(&c, &b2);
                }
            }
        });
        row.append(&dd);
        body.append(&row);
        body.append(&note("Plusieurs pare-feux sont installés : choisissez celui que l'application doit utiliser. Un seul doit être actif à la fois."));
    } else {
        body.append(&note(&format!("{} {}", t("Pare-feu utilisé :"), backend_label(cur))));
    }
    match cur {
        FwBackend::Ufw => fill_ufw(ctx, body),
        FwBackend::Firewalld => fill_fwd(ctx, body),
        FwBackend::Own => fill_own(ctx, body),
    }
}

// ───────────────────────────────── nftables intégré ─────────────────────────────────

fn fill_own(ctx: &Rc<Ctx>, body: &gtk::Box) {
    body.append(&note("Aucun pare-feu système (ufw, firewalld) n'est installé : l'application utilise sa propre table nftables. Les règles ci-dessous sont enregistrées et appliquées à l'activation. Pour piloter ufw ou firewalld, installez-en un : cette fenêtre s'adaptera."));
    let list = gtk::Box::new(gtk::Orientation::Vertical, 6);
    super::wizard::fill_rules_pub(ctx, &list);
    body.append(&list);
    let (c, l) = (ctx.clone(), list.clone());
    body.append(&button("Ajouter une règle…", move || {
        let (c2, l2) = (c.clone(), l.clone());
        dialogs::add_fw_rule(&c, Box::new(move || super::wizard::fill_rules_pub(&c2, &l2)));
    }));
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
    body.append(&log);
}

// ───────────────────────────────────── ufw ─────────────────────────────────────

fn fill_ufw(ctx: &Rc<Ctx>, body: &gtk::Box) {
    let d = ufwrules::read_defaults();
    let state = if d.enabled { t("Actif") } else { t("Désactivé") };
    body.append(&note(&format!("{} : {} · {} : {} · {} : {} · {} : {}", t("État d'ufw"), state, t("entrant par défaut"), d.incoming, t("sortant par défaut"), d.outgoing, t("journal"), d.log)));
    body.append(&note(if d.enabled {
        "ufw est actif : chaque changement s'applique immédiatement (vous serez prévenu avant)."
    } else {
        "ufw est désactivé : vous pouvez lire et modifier ses règles, elles ne s'appliqueront qu'à l'activation. Rien n'est activé depuis cette fenêtre."
    }));

    // politiques par défaut et journal
    body.append(&heading("Comportement par défaut"));
    let pol = ["deny", "allow", "reject"];
    let pol_labels = ["Refuser (recommandé)", "Autoriser", "Rejeter (avec message)"];
    let pos = |v: &str| pol.iter().position(|p| *p == v).unwrap_or(0) as u32;
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let inc = dropdown(&pol_labels, pos(&d.incoming));
    let out = dropdown(&pol_labels, pos(&d.outgoing));
    row.append(&plain_label("Entrant"));
    row.append(&inc);
    row.append(&plain_label("Sortant"));
    row.append(&out);
    let (c, b2, enabled, (i2, o2)) = (ctx.clone(), body.clone(), d.enabled, (inc.clone(), out.clone()));
    row.append(&button("Appliquer", move || {
        let (c, b2, i, o) = (c.clone(), b2.clone(), sel(&i2, &pol), sel(&o2, &pol));
        glib::spawn_future_local(async move {
            if enabled && !confirm(&c, "Modifier le comportement par défaut ?", "ufw est actif : le changement s'applique tout de suite. Refuser le sortant peut couper votre accès à Internet.", "Appliquer").await {
                return;
            }
            for (dir, p) in [("incoming", i), ("outgoing", o)] {
                let (code, text) = run_root(&dialogs::admin_args_plan(ufwrules::DEFAULT_SCRIPT, &["default".into(), p.into(), dir.into()])).await;
                if code != 0 {
                    info(&c, "Échec", &text).await;
                    break;
                }
            }
            refill_later(&c, &b2);
        });
    }));
    body.append(&row);
    let lv = ["off", "low", "medium", "high", "full"];
    let lrow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let ldd = dropdown(&["Désactivé", "Bas (recommandé)", "Moyen", "Élevé", "Complet"], lv.iter().position(|x| *x == d.log).unwrap_or(1) as u32);
    lrow.append(&plain_label("Journal des paquets refusés"));
    lrow.append(&ldd);
    let (c, b2) = (ctx.clone(), body.clone());
    lrow.append(&button("Appliquer", move || {
        let (c, b2, l) = (c.clone(), b2.clone(), sel(&ldd, &lv));
        glib::spawn_future_local(async move {
            let (code, text) = run_root(&dialogs::admin_args_plan(ufwrules::DEFAULT_SCRIPT, &["logging".into(), l.into()])).await;
            if code != 0 {
                info(&c, "Échec", &text).await;
            }
            refill_later(&c, &b2);
        });
    }));
    body.append(&lrow);

    // règles enregistrées
    body.append(&heading("Règles enregistrées dans ufw"));
    body.append(&note("Les règles d'ufw ne sont lisibles qu'avec les droits administrateur : le mot de passe vous est demandé quand vous cliquez sur « Afficher les règles »."));
    let list = gtk::Box::new(gtk::Orientation::Vertical, 6);
    body.append(&list);
    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let (c, l, b2) = (ctx.clone(), list.clone(), body.clone());
    let load: Rc<dyn Fn()> = Rc::new(move || ufw_load(&c, &l, &b2, enabled));
    let lo = load.clone();
    bar.append(&button("Afficher les règles", move || lo()));
    let (c, lo) = (ctx.clone(), load.clone());
    bar.append(&button("Ajouter une règle…", move || {
        let (c, lo) = (c.clone(), lo.clone());
        glib::spawn_future_local(async move {
            ufw_add(&c, enabled).await;
            lo();
        });
    }));
    body.append(&bar);
}

fn ufw_load(ctx: &Rc<Ctx>, list: &gtk::Box, body: &gtk::Box, enabled: bool) {
    let (ctx, list, body) = (ctx.clone(), list.clone(), body.clone());
    glib::spawn_future_local(async move {
        let (code, text) = run_root(&dialogs::admin_args_plan(ufwrules::READ_SCRIPT, &[])).await;
        clear(&list);
        if code != 0 {
            list.append(&note("Lecture impossible (autorisation refusée ou erreur)."));
            return;
        }
        let added = text.split("@@STATUS").next().unwrap_or("").to_string();
        let rules = ufwrules::parse_added(&added);
        if rules.is_empty() {
            list.append(&note("Aucune règle enregistrée pour le moment."));
            let raw: String = added.lines().filter(|l| !l.starts_with("@@")).collect::<Vec<_>>().join("\n").trim().chars().take(600).collect();
            let l = plain_label(&format!("{} (code {code}) :\n{}", t("Réponse d'ufw"), if raw.is_empty() { t("(vide)") } else { raw }));
            l.add_css_class("dim-label");
            l.add_css_class("mono");
            l.set_xalign(0.0);
            l.set_selectable(true);
            list.append(&l);
        }
        for r in rules {
            let (verb, rest) = ufwrules::summary(&r.tokens);
            let verb_t = match verb.as_str() {
                "allow" => t("Autoriser"),
                "deny" => t("Refuser"),
                "reject" => t("Rejeter"),
                "limit" => t("Limiter"),
                other => other.to_string(),
            };
            let tokens = r.tokens.clone();
            let btn: Option<(&str, Box<dyn Fn()>)> = r.deletable.then(|| {
                let (c, l, b) = (ctx.clone(), list.clone(), body.clone());
                let f: Box<dyn Fn()> = Box::new(move || {
                    let (c, l, b, tokens) = (c.clone(), l.clone(), b.clone(), tokens.clone());
                    glib::spawn_future_local(async move {
                        let what = tokens.join(" ");
                        let msg = if enabled { format!("{}\n\n{}", what, t("ufw est actif : la règle disparaît tout de suite. Si c'est celle qui autorise SSH, vous pourriez perdre l'accès à distance.")) } else { what };
                        if !confirm(&c, "Supprimer cette règle ?", &msg, "Supprimer").await {
                            return;
                        }
                        let mut args = vec!["del".to_string()];
                        args.extend(tokens);
                        let (code, text) = run_root(&dialogs::admin_args_plan(ufwrules::RULE_SCRIPT, &args)).await;
                        if code != 0 {
                            info(&c, "Échec", &text).await;
                        }
                        ufw_load(&c, &l, &b, enabled);
                    });
                });
                ("Supprimer", f)
            });
            list.append(&line(&format!("{verb_t} · {rest}"), btn));
        }
    });
}

async fn ufw_add(ctx: &Rc<Ctx>, enabled: bool) {
    let acts = ["allow", "deny", "reject", "limit"];
    let action = dropdown(&["Autoriser", "Refuser", "Rejeter (avec message)", "Limiter (anti-abus : 6 connexions / 30 s)"], 0);
    let dirs = ["in", "out"];
    let dir = dropdown(&["Entrant (vers cet ordinateur)", "Sortant (depuis cet ordinateur)"], 0);
    let protos = ["tcp", "udp", "any", "icmp"];
    let proto = dropdown(&["TCP", "UDP", "Tous", "ICMP (ping)"], 0);
    let port = entry("Port, plage 8000:8100 ou liste 80,443");
    let from = entry("Source : IP ou réseau (vide = n'importe où)");
    let to = entry("Destination : IP ou réseau (vide = n'importe où)");
    let iface = entry("Interface, ex. enp5s0 (facultatif)");
    let log = gtk::CheckButton::with_label(&t("Journaliser cette règle"));
    let intro = if enabled { "ufw est actif : la règle s'applique tout de suite." } else { "ufw est désactivé : la règle est enregistrée et s'appliquera à l'activation." };
    let ok = form(
        ctx,
        "Ajouter une règle ufw",
        intro,
        vec![("Action", action.clone().upcast()), ("Sens", dir.clone().upcast()), ("Protocole", proto.clone().upcast()), ("Port", port.clone().upcast()), ("Source", from.clone().upcast()), ("Destination", to.clone().upcast()), ("Interface", iface.clone().upcast()), ("Journal", log.clone().upcast())],
        "Ajouter",
    )
    .await;
    if !ok {
        return;
    }
    let rule = ufwrules::NewRule {
        action: sel(&action, &acts).into(),
        dir: sel(&dir, &dirs).into(),
        proto: sel(&proto, &protos).into(),
        from: from.text().trim().into(),
        to: to.text().trim().into(),
        port: port.text().trim().into(),
        iface: iface.text().trim().into(),
        log: log.is_active(),
    };
    let tokens = match ufwrules::build_tokens(&rule) {
        Ok(t) => t,
        Err(e) => {
            info(ctx, "Règle invalide", &e).await;
            return;
        }
    };
    if enabled && !confirm(ctx, "Appliquer cette règle maintenant ?", &tokens.join(" "), "Ajouter").await {
        return;
    }
    let mut args = vec!["add".to_string()];
    args.extend(tokens);
    let (code, text) = run_root(&dialogs::admin_args_plan(ufwrules::RULE_SCRIPT, &args)).await;
    if code != 0 {
        info(ctx, "Échec", &text).await;
    }
}

// ─────────────────────────────────── firewalld ───────────────────────────────────

/// Applique une modification de la configuration firewalld (script constant, droits administrateur). Renvoie true si elle a réussi.
async fn fwd_edit(ctx: &Rc<Ctx>, op: &str, zone: &str, val: &str) -> bool {
    let (code, text) = run_root(&dialogs::admin_args_plan(fwd::EDIT_SCRIPT, &[op.into(), zone.into(), val.into()])).await;
    if code != 0 {
        info(ctx, "Échec", &text).await;
    }
    code == 0
}

fn fill_fwd(ctx: &Rc<Ctx>, body: &gtk::Box) {
    let conf = fwd::read_conf();
    let zones = fwd::zone_names();
    let running = fwd::running();
    body.append(&note(&format!("{} : {} · {} : {} · {} : {}", t("État de firewalld"), if running { t("Actif") } else { t("Désactivé") }, t("zone par défaut"), conf.default_zone, t("journal des refus"), conf.log_denied)));
    body.append(&note(if running {
        "firewalld est actif : vos modifications sont enregistrées dans la configuration permanente et ne s'appliquent qu'au rechargement (bouton ci-dessous)."
    } else {
        "firewalld est désactivé : vous pouvez lire et modifier ses règles ; elles s'appliqueront à l'activation. Rien n'est activé depuis cette fenêtre."
    }));
    if zones.is_empty() {
        body.append(&note("Aucune zone firewalld trouvée dans /etc/firewalld ni /usr/lib/firewalld : vérifiez que le paquet firewalld est complètement installé."));
        return;
    }
    // zone affichée : celle par défaut au départ
    let start = zones.iter().position(|z| *z == conf.default_zone).unwrap_or(0);
    let zrow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    zrow.append(&plain_label("Zone"));
    let refs: Vec<&str> = zones.iter().map(String::as_str).collect();
    let zdd = gtk::DropDown::from_strings(&refs);
    zdd.set_selected(start as u32);
    zrow.append(&zdd);
    body.append(&zrow);
    let zone_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    body.append(&zone_box);
    let (c, zb, zs) = (ctx.clone(), zone_box.clone(), zones.clone());
    let show_zone: Rc<dyn Fn(u32)> = Rc::new(move |i| {
        if let Some(name) = zs.get(i as usize) {
            fill_zone(&c, &zb, name);
        }
    });
    show_zone(start as u32);
    let sz = show_zone.clone();
    zdd.connect_selected_notify(move |d| sz(d.selected()));

    // réglages généraux
    body.append(&heading("Réglages généraux"));
    let lv = ["off", "all", "unicast", "broadcast", "multicast"];
    let lrow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let ldd = dropdown(&["Désactivé", "Tous les refus", "Refus unicast", "Refus broadcast", "Refus multicast"], lv.iter().position(|x| *x == conf.log_denied).unwrap_or(0) as u32);
    lrow.append(&plain_label("Journal des paquets refusés"));
    lrow.append(&ldd);
    let (c, b2) = (ctx.clone(), body.clone());
    lrow.append(&button("Appliquer", move || {
        let (c, b2, v) = (c.clone(), b2.clone(), sel(&ldd, &lv));
        glib::spawn_future_local(async move {
            fwd_edit(&c, "set-log-denied", "", v).await;
            refill_later(&c, &b2);
        });
    }));
    body.append(&lrow);
    if running {
        let (c, b2) = (ctx.clone(), body.clone());
        body.append(&button("Appliquer maintenant (recharger firewalld)", move || {
            let (c, b2) = (c.clone(), b2.clone());
            glib::spawn_future_local(async move {
                if confirm(&c, "Recharger firewalld ?", "Les règles enregistrées s'appliquent tout de suite. Si vous avez retiré le service qui autorise SSH, vous pourriez perdre l'accès à distance.", "Recharger").await {
                    fwd_edit(&c, "reload", "", "").await;
                    refill_later(&c, &b2);
                }
            });
        }));
    }
}

fn fill_zone(ctx: &Rc<Ctx>, zb: &gtk::Box, name: &str) {
    clear(zb);
    let Some(z) = fwd::load_zone(name) else {
        zb.append(&note("Zone illisible."));
        return;
    };
    let conf = fwd::read_conf();
    let (ctxc, zbc, zn) = (ctx.clone(), zb.clone(), name.to_string());
    let redo: Rc<dyn Fn()> = Rc::new(move || {
        let (c, b, n) = (ctxc.clone(), zbc.clone(), zn.clone());
        glib::idle_add_local_once(move || fill_zone(&c, &b, &n));
    });
    if !z.short.is_empty() {
        zb.append(&note(&format!("{} — {}", z.name, z.short)));
    }
    // zone par défaut et cible
    let trow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let labels: Vec<&str> = fwd::TARGETS.iter().map(|(_, l)| *l).collect();
    let tdd = dropdown(&labels, fwd::TARGETS.iter().position(|(v, _)| *v == z.target).unwrap_or(0) as u32);
    trow.append(&plain_label("Trafic non prévu par les règles"));
    trow.append(&tdd);
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    trow.append(&button("Appliquer", move || {
        let (c, zn, rd, v) = (c.clone(), zn.clone(), rd.clone(), fwd::TARGETS.get(tdd.selected() as usize).map(|t| t.0).unwrap_or("default"));
        glib::spawn_future_local(async move {
            if fwd_edit(&c, "set-target", &zn, v).await {
                rd();
            }
        });
    }));
    zb.append(&trow);
    if conf.default_zone != name {
        let (c, zn) = (ctx.clone(), name.to_string());
        let (zbb, rd) = (zb.clone(), redo.clone());
        zb.append(&button("Utiliser cette zone par défaut", move || {
            let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
            let _ = &zbb;
            glib::spawn_future_local(async move {
                if confirm(&c, "Changer la zone par défaut ?", &format!("{zn} deviendra la zone par défaut de firewalld. Ses règles (services, ports) s'appliqueront aux connexions qui ne sont rattachées à aucune autre zone."), "Changer").await && fwd_edit(&c, "set-default-zone", &zn, "").await {
                    rd();
                }
            });
        }));
    }
    if !z.interfaces.is_empty() {
        zb.append(&note(&format!("{} : {}", t("Interfaces réseau de cette zone (gérées par NetworkManager ou firewalld)"), z.interfaces.join(", "))));
    }

    // services
    zb.append(&heading("Services autorisés"));
    for s in &z.services {
        let (c, zn, rd, sn) = (ctx.clone(), name.to_string(), redo.clone(), s.clone());
        zb.append(&line(s, Some(("Retirer", Box::new(move || remove_item(&c, &zn, "remove-service", &sn, &rd))))));
    }
    if z.services.is_empty() {
        zb.append(&note("Aucun service."));
    }
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    zb.append(&button("Ajouter un service…", move || {
        let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
        glib::spawn_future_local(async move {
            let all = fwd::services_available();
            if all.is_empty() {
                info(&c, "Aucun service", "Aucun service prédéfini trouvé (paquet firewalld incomplet ?).").await;
                return;
            }
            let refs: Vec<&str> = all.iter().map(String::as_str).collect();
            let dd = gtk::DropDown::from_strings(&refs);
            dd.set_enable_search(true);
            if form(&c, "Ajouter un service", "Choisissez un service prédéfini (ssh, http, samba…). Il sera autorisé dans cette zone.", vec![("Service", dd.clone().upcast())], "Ajouter").await {
                if let Some(s) = all.get(dd.selected() as usize) {
                    if fwd_edit(&c, "add-service", &zn, s).await {
                        rd();
                    }
                }
            }
        });
    }));

    // ports
    zb.append(&heading("Ports autorisés"));
    for (p, pr) in &z.ports {
        let spec = format!("{p}/{pr}");
        let (c, zn, rd, sp) = (ctx.clone(), name.to_string(), redo.clone(), spec.clone());
        zb.append(&line(&spec, Some(("Retirer", Box::new(move || remove_item(&c, &zn, "remove-port", &sp, &rd))))));
    }
    if z.ports.is_empty() {
        zb.append(&note("Aucun port."));
    }
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    zb.append(&button("Ajouter un port…", move || {
        let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
        glib::spawn_future_local(async move {
            let port = entry("Port (1 à 65535) ou plage 8000-8100");
            let protos = ["tcp", "udp", "sctp", "dccp"];
            let proto = dropdown(&["TCP", "UDP", "SCTP", "DCCP"], 0);
            if form(&c, "Ajouter un port", "Le port sera autorisé dans cette zone.", vec![("Port", port.clone().upcast()), ("Protocole", proto.clone().upcast())], "Ajouter").await {
                match fwd::port_spec(port.text().trim(), sel(&proto, &protos)) {
                    Ok(spec) => {
                        if fwd_edit(&c, "add-port", &zn, &spec).await {
                            rd();
                        }
                    }
                    Err(e) => info(&c, "Port invalide", &e).await,
                }
            }
        });
    }));

    // sources
    zb.append(&heading("Adresses sources rattachées à cette zone"));
    for s in &z.sources {
        let (c, zn, rd, sn) = (ctx.clone(), name.to_string(), redo.clone(), s.clone());
        zb.append(&line(s, Some(("Retirer", Box::new(move || remove_item(&c, &zn, "remove-source", &sn, &rd))))));
    }
    if z.sources.is_empty() {
        zb.append(&note("Aucune. Rattacher un réseau (ex. 192.168.0.0/24) à une zone lui applique les règles de cette zone."));
    }
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    zb.append(&button("Ajouter une adresse ou un réseau…", move || {
        let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
        glib::spawn_future_local(async move {
            let a = entry("ex. 192.168.0.0/24 ou 2001:db8::/32");
            if form(&c, "Rattacher une source à cette zone", "Les connexions venant de cette adresse suivront les règles de cette zone.", vec![("Adresse", a.clone().upcast())], "Ajouter").await {
                let v = a.text().trim().to_string();
                if !fwd::addr_ok(&v, None) {
                    info(&c, "Adresse invalide", "Indiquez une adresse IPv4 ou IPv6, éventuellement avec /réseau.").await;
                } else if fwd_edit(&c, "add-source", &zn, &v).await {
                    rd();
                }
            }
        });
    }));

    // règles riches
    zb.append(&heading("Règles détaillées"));
    for r in &z.rich {
        let btn: Option<(&str, Box<dyn Fn()>)> = r.canonical.clone().map(|canon| {
            let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
            let f: Box<dyn Fn()> = Box::new(move || remove_item(&c, &zn, "remove-rich", &canon, &rd));
            ("Retirer", f)
        });
        let txt = if btn.is_some() { r.text.clone() } else { format!("{} ({})", r.text, t("lecture seule")) };
        zb.append(&line(&txt, btn));
    }
    if z.rich.is_empty() {
        zb.append(&note("Aucune règle détaillée."));
    }
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    zb.append(&button("Ajouter une règle détaillée…", move || {
        let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
        glib::spawn_future_local(async move { add_rich(&c, &zn, &rd).await });
    }));

    // blocs ICMP
    zb.append(&heading("Types ICMP bloqués"));
    for i in &z.icmp_blocks {
        let (c, zn, rd, n) = (ctx.clone(), name.to_string(), redo.clone(), i.clone());
        zb.append(&line(i, Some(("Retirer", Box::new(move || remove_item(&c, &zn, "remove-icmp-block", &n, &rd))))));
    }
    if z.icmp_blocks.is_empty() {
        zb.append(&note("Aucun. Bloquer « echo-request » rend l'ordinateur muet au ping."));
    }
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    zb.append(&button("Bloquer un type ICMP…", move || {
        let (c, zn, rd) = (c.clone(), zn.clone(), rd.clone());
        glib::spawn_future_local(async move {
            let all = fwd::icmp_types();
            if all.is_empty() {
                info(&c, "Aucun type", "Aucun type ICMP trouvé (paquet firewalld incomplet ?).").await;
                return;
            }
            let refs: Vec<&str> = all.iter().map(String::as_str).collect();
            let dd = gtk::DropDown::from_strings(&refs);
            dd.set_enable_search(true);
            if form(&c, "Bloquer un type ICMP", "Exemple : echo-request bloque le ping entrant.", vec![("Type", dd.clone().upcast())], "Bloquer").await {
                if let Some(n) = all.get(dd.selected() as usize) {
                    if fwd_edit(&c, "add-icmp-block", &zn, n).await {
                        rd();
                    }
                }
            }
        });
    }));

    // masquerade
    zb.append(&heading("Partage de connexion (masquerade)"));
    let mrow = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let msw = gtk::Switch::new();
    msw.set_valign(gtk::Align::Center);
    msw.set_active(z.masquerade);
    let (c, zn, rd) = (ctx.clone(), name.to_string(), redo.clone());
    msw.connect_state_set(move |sw, on| {
        if on != z_masq(&zn) {
            let (c, zn, rd, sw) = (c.clone(), zn.clone(), rd.clone(), sw.clone());
            glib::spawn_future_local(async move {
                let ok = fwd_edit(&c, if on { "add-masquerade" } else { "remove-masquerade" }, &zn, "").await;
                if !ok {
                    sw.set_active(!on);
                }
                rd();
            });
        }
        glib::Propagation::Proceed
    });
    mrow.append(&msw);
    mrow.append(&plain_label("Traduction d'adresses (NAT) pour partager la connexion de cet ordinateur"));
    zb.append(&mrow);
}

fn z_masq(zone: &str) -> bool {
    fwd::load_zone(zone).is_some_and(|z| z.masquerade)
}

fn remove_item(ctx: &Rc<Ctx>, zone: &str, op: &'static str, val: &str, redo: &Rc<dyn Fn()>) {
    let (c, zn, v, rd) = (ctx.clone(), zone.to_string(), val.to_string(), redo.clone());
    glib::spawn_future_local(async move {
        let running = fwd::running();
        let msg = if running { format!("{v}\n\n{}", t("firewalld est actif : le retrait est enregistré dans la configuration permanente et s'applique au prochain rechargement.")) } else { v.clone() };
        if confirm(&c, "Retirer cet élément ?", &msg, "Retirer").await && fwd_edit(&c, op, &zn, &v).await {
            rd();
        }
    });
}

async fn add_rich(ctx: &Rc<Ctx>, zone: &str, redo: &Rc<dyn Fn()>) {
    let acts = ["accept", "reject", "drop"];
    let action = dropdown(&["Autoriser", "Rejeter (avec message)", "Bloquer en silence"], 0);
    let fams = ["ipv4", "ipv6"];
    let fam = dropdown(&["IPv4", "IPv6"], 0);
    let source = entry("Source : IP ou réseau (vide = n'importe où)");
    let svcs = fwd::services_available();
    let mut names: Vec<String> = vec![t("(aucun)")];
    names.extend(svcs.iter().cloned());
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let svc = gtk::DropDown::from_strings(&refs);
    svc.set_enable_search(true);
    let port = entry("… ou un port, ex. 8080 ou 8000-8100");
    let protos = ["tcp", "udp", "sctp", "dccp"];
    let proto = dropdown(&["TCP", "UDP", "SCTP", "DCCP"], 0);
    let limit = entry("Limite, ex. 10/m (facultatif)");
    let ok = form(
        ctx,
        "Ajouter une règle détaillée",
        "Combinez une source et un service OU un port. Cette règle est enregistrée dans la configuration permanente de la zone.",
        vec![("Action", action.clone().upcast()), ("Famille", fam.clone().upcast()), ("Source", source.clone().upcast()), ("Service", svc.clone().upcast()), ("Port", port.clone().upcast()), ("Protocole", proto.clone().upcast()), ("Limite", limit.clone().upcast())],
        "Ajouter",
    )
    .await;
    if !ok {
        return;
    }
    let svc_name = if svc.selected() == 0 { String::new() } else { svcs.get(svc.selected() as usize - 1).cloned().unwrap_or_default() };
    let rule = fwd::NewRich { action: sel(&action, &acts).into(), family: sel(&fam, &fams).into(), source: source.text().trim().into(), service: svc_name, port: port.text().trim().into(), proto: sel(&proto, &protos).into(), limit: limit.text().trim().into() };
    match fwd::build_rich(&rule) {
        Ok(r) => {
            if fwd_edit(ctx, "add-rich", zone, &r).await {
                redo();
            }
        }
        Err(e) => info(ctx, "Règle invalide", &e).await,
    }
}
