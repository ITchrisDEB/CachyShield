//! Pages simples, une par module (comme CleanMyMac) : une phrase claire, de grandes cartes avec un chiffre,
//! des boutons « Analyser » / « Corriger », et des listes en langage courant. Les tableaux techniques
//! restent disponibles dans la page « Avancé ».

use super::auto::update_cve_data;
use super::dialogs::{pending_updates_blocking, system_update};
use super::global_page::GlobalPage;
use super::actions::{self, clickable, show_advice};
use super::tool_page::{Progress, ToolPage};
use crate::advice::{self, Advice, Direct};
use super::{Ctx, plain_label, when};
use crate::live::{self, Expo, Snapshot, key_of};
use crate::risk::{self, RiskLevel};
use crate::util::abs_prog;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use libadwaita as adw;
use adw::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

type Pages = Rc<HashMap<&'static str, Rc<ToolPage>>>;

pub struct Modules {
    pub protection: gtk::Widget,
    pub failles: gtk::Widget,
    pub maj: gtk::Widget,
    pub reseau: gtk::Widget,
    pub config: gtk::Widget,
    pub clean: gtk::Widget,
}

// ─────────────────────────────── composants ────────────────────────────────

struct Card {
    click: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>>,
    root: gtk::Box,
    value: gtk::Label,
    text: gtk::Label,
    btns: gtk::Box,
}

impl Card {
    fn new(tile_css: &str, icon: &str, name: &str) -> Card {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.add_css_class("tile");
        root.add_css_class(tile_css);
        root.set_hexpand(true);
        root.set_valign(gtk::Align::Fill);
        root.set_height_request(190);
        let top = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let n = gtk::Label::new(Some(crate::i18n::tr(name).as_str()));
        n.add_css_class("tile-name");
        n.set_xalign(0.0);
        // un titre plus long dans une autre langue passe à la ligne au lieu d'élargir la fenêtre
        n.set_wrap(true);
        n.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        n.set_max_width_chars(26);
        n.set_width_chars(8);
        n.set_hexpand(true);
        let img = gtk::Image::from_icon_name(icon);
        img.set_pixel_size(36);
        img.set_opacity(0.85);
        top.append(&n);
        top.append(&img);
        let value = plain_label("—");
        value.set_wrap_mode(gtk::pango::WrapMode::WordChar);
        value.add_css_class("tile-value");
        let text = plain_label("");
        text.add_css_class("soft");
        text.set_yalign(0.0);
        let btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        btns.set_margin_top(6);
        root.append(&top);
        root.append(&value);
        root.append(&text);
        root.append(&btns);
        let click: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(std::cell::RefCell::new(None));
        let g = gtk::GestureClick::new();
        let c2 = click.clone();
        g.connect_released(move |_, _, _, _| {
            let f = c2.borrow().clone();
            if let Some(f) = f {
                f();
            }
        });
        root.add_controller(g);
        root.add_css_class("tile-click");
        root.set_cursor_from_name(Some("pointer"));
        Card { click, root, value, text, btns }
    }

    fn set(&self, value: &str, text: &str) {
        self.value.set_text(&crate::i18n::tr(value));
        self.text.set_text(&crate::i18n::tr(text));
    }

    fn set_click(&self, f: Rc<dyn Fn()>) {
        *self.click.borrow_mut() = Some(f);
    }

    fn button(&self, label: &str, f: impl Fn() + 'static) -> gtk::Button {
        let b = gtk::Button::with_label(&crate::i18n::tr(label));
        b.add_css_class("glass-btn");
        let f: Rc<dyn Fn()> = Rc::new(f);
        if self.click.borrow().is_none() {
            self.set_click(f.clone());
        }
        b.connect_clicked(move |_| f());
        self.btns.append(&b);
        b
    }
}

fn sev_word(key: &str) -> (&'static str, &'static str) {
    match key {
        "critical" => ("Critique", "sev-critical"),
        "high" => ("Grave", "sev-high"),
        "medium" => ("Moyenne", "sev-medium"),
        "low" => ("Faible", "sev-low"),
        _ => ("À examiner", "sev-unknown"),
    }
}

fn badge(text: &str, css: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(crate::i18n::tr(text).as_str()));
    l.set_use_markup(false);
    l.add_css_class("sev-pill");
    l.add_css_class(css);
    l.set_valign(gtk::Align::Center);
    l
}

fn row(title: &str, subtitle: &str, tag: Option<(&str, &str)>) -> gtk::Box {
    let r = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    r.add_css_class("glass-row");
    let left = gtk::Box::new(gtk::Orientation::Vertical, 2);
    left.set_hexpand(true);
    let t = plain_label(title);
    t.add_css_class("row-title");
    left.append(&t);
    if !subtitle.is_empty() {
        let s = plain_label(subtitle);
        s.add_css_class("soft");
        left.append(&s);
    }
    r.append(&left);
    if let Some((txt, css)) = tag {
        r.append(&badge(txt, css));
    }
    r
}

fn section(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(crate::i18n::tr(text).as_str()));
    l.add_css_class("section-title");
    l.set_xalign(0.0);
    l
}

fn clear(b: &gtk::Box) {
    while let Some(c) = b.first_child() {
        b.remove(&c);
    }
}

struct Shell {
    root: gtk::Box,
    headline: gtk::Label,
    sub: gtk::Label,
    cards: gtk::Box,
    list: gtk::Box,
    banner: Rc<Banner>,
    sw: gtk::ScrolledWindow,
}

/// Fait défiler la page jusqu'à la liste (ou tout en bas).
#[allow(deprecated)]
fn scroll_to(sw: &gtk::ScrolledWindow, target: Option<&gtk::Box>) {
    let adj = sw.vadjustment();
    let y = match target {
        Some(t) => (t.allocation().y() as f64 - 10.0).max(0.0),
        None => adj.upper(),
    };
    adj.set_value(y.min(adj.upper() - adj.page_size()).max(0.0));
}

fn shell(theme: &str) -> Shell {
    let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
    root.add_css_class("themed");
    root.add_css_class(theme);
    let inner = gtk::Box::new(gtk::Orientation::Vertical, 12);
    inner.set_margin_top(26);
    inner.set_margin_bottom(22);
    inner.set_margin_start(30);
    inner.set_margin_end(30);
    let headline = gtk::Label::new(None);
    headline.add_css_class("smart-title");
    headline.set_wrap(true);
    headline.set_justify(gtk::Justification::Center);
    let sub = gtk::Label::new(None);
    sub.add_css_class("smart-sub");
    sub.add_css_class("soft");
    sub.set_wrap(true);
    sub.set_justify(gtk::Justification::Center);
    let cards = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    cards.set_homogeneous(true);
    cards.set_valign(gtk::Align::Start);
    cards.set_margin_top(8);
    let list = gtk::Box::new(gtk::Orientation::Vertical, 8);
    list.set_margin_top(6);
    headline.set_text(&crate::i18n::tr("Vérification en cours…"));
    inner.append(&headline);
    let banner = Banner::new();
    inner.append(&sub);
    inner.append(&banner.root);
    inner.append(&cards);
    inner.append(&list);
    let sw = gtk::ScrolledWindow::builder().child(&inner).vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).build();
    root.append(&sw);
    Shell { root, headline, sub, cards, list, banner, sw }
}

fn set_list(list: &gtk::Box, items: Vec<gtk::Widget>, empty: &str) {
    if items.is_empty() {
        let l = plain_label(empty);
        l.add_css_class("soft");
        list.append(&l);
    }
    for i in items {
        list.append(&i);
    }
}

/// Lance une analyse sans quitter la page, puis rafraîchit l'affichage.
fn analyse(pages: &Pages, key: &'static str, card: &Rc<Card>, then: Rc<dyn Fn()>) {
    let (p, c) = (pages[key].clone(), card.clone());
    c.value.set_text(&crate::i18n::tr("Analyse en cours…"));
    set_busy(&c, true);
    glib::spawn_future_local(async move {
        p.run_await().await;
        set_busy(&c, false);
        then();
    });
}

// ───────────────────────────────── modules ─────────────────────────────────

pub fn build(ctx: Rc<Ctx>, pages: Pages, global: Rc<GlobalPage>) -> Modules {
    Modules { protection: protection(&ctx, &pages), failles: failles(&ctx, &pages, &global), maj: maj(&ctx, &global), reseau: reseau(&ctx), config: config(&ctx, &pages), clean: clean(&ctx) }
}

fn wire_refresh(root: &gtk::Box, refresh: Rc<dyn Fn()>) {
    let r = refresh.clone();
    root.connect_map(move |_| r());
}

fn protection(ctx: &Rc<Ctx>, pages: &Pages) -> gtk::Widget {
    let s = shell("mod-protection");
    s.banner.attach(&pages["rkhunter"], "Recherche de rootkits");
    let rk = Rc::new(Card::new("tile-protection", "security-high-symbolic", "ROOTKITS ET LOGICIELS ESPIONS"));
    let ssh = Rc::new(Card::new("tile-protection", "network-server-symbolic", "ACCÈS À DISTANCE"));
    s.cards.append(&rk.root);
    s.cards.append(&ssh.root);
    {
        let c = ctx.clone();
        ssh.set_click(Rc::new(move || super::sshpanel::show(&c, Rc::new(|| {}))));
    }
    let (headline, sub, list) = (s.headline.clone(), s.sub.clone(), s.list.clone());
    let ctx2 = ctx.clone();
    // le rafraîchissement doit pouvoir se rappeler lui-même après une action (ignorer, corriger…)
    let me: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(std::cell::RefCell::new(None));
    let refresh: Rc<dyn Fn()> = Rc::new({
        let (rk, ssh, me2) = (rk.clone(), ssh.clone(), me.clone());
        move || {
            clear(&list);
            let st = ctx2.state.borrow();
            match st.tools.get("rkhunter") {
                None => {
                    headline.set_text(&crate::i18n::tr("Votre protection n'a pas encore été vérifiée"));
                    sub.set_text(&crate::i18n::tr("L'analyse cherche les logiciels espions cachés et les fichiers système modifiés. Votre mot de passe sera demandé."));
                    rk.set("Non analysé", "rkhunter compare vos fichiers système à une référence et cherche des rootkits connus.");
                    set_list(&list, vec![], "Lancez l'analyse pour voir les résultats ici.");
                }
                Some(saved) => {
                    let r = saved.result.counts.get("rootkits").copied().unwrap_or(0);
                    let alerts: Vec<(String, String)> = saved.rows.iter().map(|c| (c.get(1).cloned().unwrap_or_default(), c.get(2).cloned().unwrap_or_default())).collect();
                    let when_txt = when(saved.result.time).replace("analysé le ", "");
                    headline.set_text(&crate::i18n::tr("Vérification des alertes avec pacman…"));
                    sub.set_text(&crate::i18n::tr("Chaque fichier signalé est comparé à l'original du paquet officiel."));
                    // vérification en arrière-plan : le fichier est-il identique à celui du paquet officiel ?
                    let paths: Vec<String> = alerts.iter().filter_map(|(t, _)| crate::verify::path_in(t)).collect();
                    let (tx, rx) = async_channel::bounded::<HashMap<String, crate::verify::Verdict>>(1);
                    std::thread::spawn(move || {
                        let _ = tx.send_blocking(crate::verify::verify_all(&paths));
                    });
                    let (headline, sub, list, rk, ctx3, me3) = (headline.clone(), sub.clone(), list.clone(), rk.clone(), ctx2.clone(), me2.clone());
                    glib::spawn_future_local(async move {
                        let Ok(verdicts) = rx.recv().await else { return };
                        clear(&list);
                        let again: Rc<dyn Fn()> = Rc::new(move || {
                            if let Some(f) = me3.borrow().as_ref() {
                                f();
                            }
                        });
                        let ignored = ctx3.state.borrow().ignored.clone();
                        let (mut serious, mut benign, mut masked) = (0usize, 0usize, 0usize);
                        let mut benign_items: Vec<gtk::Widget> = Vec::new();
                        let mut items: Vec<gtk::Widget> = Vec::new();
                        for (text, note) in &alerts {
                            if ignored.contains(text) {
                                masked += 1;
                                continue;
                            }
                            let v = alert_row(text, note, &verdicts);
                            if v.serious { serious += 1 } else { benign += 1 }
                            // « C'est normal » : l'alerte n'est plus signalée (le système n'est pas modifié) ; réversible
                            let (c, key, ag) = (ctx3.clone(), text.clone(), again.clone());
                            let ignore: Rc<dyn Fn()> = Rc::new(move || {
                                {
                                    let mut st = c.state.borrow_mut();
                                    if !st.ignored.contains(&key) {
                                        st.ignored.push(key.clone());
                                    }
                                }
                                c.save();
                                ag();
                            });
                            let (c2, title, intro, adv, ag2) = (ctx3.clone(), v.title.clone(), v.intro.clone(), v.advice.clone(), again.clone());
                            let open: Rc<dyn Fn()> = Rc::new(move || show_advice(&c2, &title, &intro, adv.clone(), vec![(Direct::IgnoreAlert, ignore.clone())], ag2.clone()));
                            let w = clickable(v.row, "Cliquez pour voir ce qui est possible et la recommandation", open);
                            if v.serious { items.push(w.upcast()) } else { benign_items.push(w.upcast()) }
                        }
                        if masked > 0 {
                            let (c, ag) = (ctx3.clone(), again.clone());
                            let b = gtk::Button::with_label(&format!("Réafficher les {masked} alerte(s) marquée(s) normales"));
                            b.add_css_class("glass-btn");
                            b.set_halign(gtk::Align::Start);
                            b.connect_clicked(move |_| {
                                c.state.borrow_mut().ignored.clear();
                                c.save();
                                ag();
                            });
                            items.push(b.upcast());
                        }
                        if r > 0 {
                            headline.set_text(&crate::i18n::tr("Une menace possible a été détectée"));
                        } else if serious > 0 {
                            headline.set_text(&format!("{serious} point(s) à examiner"));
                        } else {
                            headline.set_text(&crate::i18n::tr("Aucune menace détectée"));
                        }
                        sub.set_text(&if benign > 0 && serious == 0 { format!("{benign} alerte(s) de rkhunter examinée(s) : ce sont des faux positifs, vérifiés ci-dessous. Dernière vérification : {when_txt}") } else { format!("Dernière vérification : {when_txt}") });
                        rk.set(&if r > 0 { format!("{r} menace(s)") } else if serious > 0 { format!("{serious} à examiner") } else { "Aucune menace".into() }, &format!("{benign} alerte(s) sans danger, vérifiée(s) avec la base des paquets."));
                        set_list(&list, items, "Aucune alerte. Votre système est sain.");
                        if !benign_items.is_empty() {
                            let ex = gtk::Expander::new(Some(&format!("{} ({})", crate::i18n::tr("Alertes vérifiées, sans danger : aucune action nécessaire"), benign_items.len())));
                            let inner = gtk::Box::new(gtk::Orientation::Vertical, 8);
                            inner.set_margin_top(8);
                            for w in benign_items {
                                inner.append(&w);
                            }
                            ex.set_child(Some(&inner));
                            list.append(&ex);
                        }
                    });
                }
            }
            drop(st);
            let active = abs_prog("systemctl").and_then(|p| std::process::Command::new(p).args(["is-active", "sshd"]).output().ok()).map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false);
            ssh.set(if active { "SSH est actif" } else { "SSH est désactivé" }, if active { "SSH permet de se connecter à cet ordinateur à distance. Si vous ne l'utilisez pas, mieux vaut le désactiver. Cliquez ici pour régler SSH." } else { "Personne ne peut se connecter à distance par SSH. C'est le plus sûr si vous n'en avez pas besoin. Cliquez ici pour régler SSH." });
        }
    });
    *me.borrow_mut() = Some(refresh.clone());
    let (p, r) = (pages.clone(), refresh.clone());
    let rk2 = rk.clone();
    rk.button("Analyser", move || analyse(&p, "rkhunter", &rk2, r.clone()));
    wire_refresh(&s.root, refresh);
    s.root.upcast()
}

fn failles(ctx: &Rc<Ctx>, pages: &Pages, global: &Rc<GlobalPage>) -> gtk::Widget {
    let s = shell("mod-failles");
    s.banner.attach(&pages["arch-audit"], "Analyse de vos paquets");
    s.banner.attach(&pages["osv-scanner"], "Analyse de vos projets");
    s.banner.attach(&pages["trivy"], "Analyse des bibliothèques");
    let sys = Rc::new(Card::new("tile-failles", "dialog-warning-symbolic", "VOTRE SYSTÈME"));
    let prj = Rc::new(Card::new("tile-failles", "folder-symbolic", "VOS PROJETS"));
    let atk = Rc::new(Card::new("tile-failles", "security-low-symbolic", "ATTAQUES RÉELLES"));
    for c in [&sys, &prj, &atk] {
        s.cards.append(&c.root);
    }
    let (headline, sub, list) = (s.headline.clone(), s.sub.clone(), s.list.clone());
    let (ctx2, global2) = (ctx.clone(), global.clone());
    let me: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(std::cell::RefCell::new(None));
    // durée et fraîcheur de la dernière vérification (pour que l'utilisateur voie que l'analyse a vraiment été refaite)
    let last_run: Rc<std::cell::RefCell<String>> = Rc::new(std::cell::RefCell::new(String::new()));
    let refresh: Rc<dyn Fn()> = Rc::new({
        let (sys, prj, atk, me2, last2) = (sys.clone(), prj.clone(), atk.clone(), me.clone(), last_run.clone());
        move || {
            clear(&list);
            let st = ctx2.state.borrow();
            let (arch_done, osv_done) = (st.tools.contains_key("arch-audit"), st.tools.contains_key("osv-scanner") && !st.settings.project_dirs.is_empty());
            let arch: Vec<Vec<String>> = st.tools.get("arch-audit").map(|s| s.rows.clone()).unwrap_or_default();
            let osv_rows: Vec<Vec<String>> = if st.settings.project_dirs.is_empty() { Vec::new() } else { st.tools.get("osv-scanner").map(|s| s.rows.clone()).unwrap_or_default() };
            let trivy_done = st.tools.contains_key("trivy");
            let trivy_rows: Vec<Vec<String>> = st.tools.get("trivy").map(|s| s.rows.clone()).unwrap_or_default();
            drop(st);
            // projets : regroupés par logiciel et version
            let mut proj: BTreeMap<(String, String), (usize, usize, String)> = BTreeMap::new();
            let mut meta: BTreeMap<(String, String), (String, Vec<String>)> = BTreeMap::new();
            let mut seen_ids: HashSet<(String, String, String)> = HashSet::new();
            for r in &osv_rows {
                let m = meta.entry((r[2].clone(), r[3].clone())).or_insert((r[0].clone(), Vec::new()));
                if m.1.len() < 3 && !m.1.contains(&r[6]) {
                    m.1.push(r[6].clone());
                }
                let e = proj.entry((r[2].clone(), r[3].clone())).or_insert((0, 0, String::new()));
                if seen_ids.insert((r[2].clone(), r[3].clone(), r[5].clone())) {
                    e.0 += 1;
                    if matches!(r[1].as_str(), "critical" | "high") {
                        e.1 += 1;
                    }
                }
                if r[4] != "aucun" && (e.2.is_empty() || crate::depfix::cmp(&r[4], &e.2) == std::cmp::Ordering::Greater) {
                    e.2 = r[4].clone();
                }
            }
            let kev = global2.kev_groups();
            let recent_from: String = crate::global::iso_utc(crate::util::now_unix() - 365 * 86_400).chars().take(10).collect();
            sys.set(&if !arch_done { "Non analysé".to_string() } else if arch.is_empty() { "Aucune faille".to_string() } else { "Calcul en cours…".to_string() }, "Logiciels installés qui ont une faille connue, d'après l'équipe sécurité d'Arch Linux.");
            prj.set(&if !osv_done { "Non analysé".to_string() } else if proj.is_empty() { "Aucune faille".to_string() } else { format!("{} dépendance(s)", proj.len()) }, "Bibliothèques utilisées par vos projets (Python, npm, Rust…) qui ont une faille connue.");
            {
                let n = ctx2.state.borrow().settings.project_dirs.len();
                prj.text.set_text(&if n == 0 { crate::i18n::tr("Aucun dossier de projets : cliquez sur « Dossiers… » pour en ajouter.") } else { format!("{}\n{} {n}", crate::i18n::tr("Bibliothèques utilisées par vos projets (Python, npm, Rust…) qui ont une faille connue."), crate::i18n::tr("Dossiers analysés :")) });
            }
            let kev_ready = global2.inventory_ready() || !global2.kev_loaded();
            if !kev_ready {
                let me4 = me2.clone();
                glib::timeout_add_seconds_local_once(2, move || {
                    if let Some(f) = me4.borrow().as_ref() {
                        f();
                    }
                });
            }
            let urgent_n = kev.iter().filter(|(n, _, last)| last.as_str() >= recent_from.as_str() && !global2.likely_fixed(n, last)).count();
            atk.set(&if !kev_ready { "Calcul en cours…".to_string() } else if urgent_n == 0 { "Aucune urgence".to_string() } else { format!("{urgent_n} logiciel(s)") }, if kev_ready && urgent_n == 0 && !kev.is_empty() { "Aucun de vos logiciels n'est concerné par une faille exploitée récente : ceux de la liste CISA sont déjà corrigés chez vous (paquet plus récent que la faille)." } else { "Failles utilisées par de vrais pirates en ce moment (liste officielle CISA). À traiter en premier." });
            if arch.is_empty() && proj.is_empty() && kev.is_empty() {
                headline.set_text(&crate::i18n::tr("Aucune faille connue"));
                sub.set_text(&crate::i18n::tr("Lancez une analyse pour vérifier à nouveau."));
            } else {
                headline.set_text(&crate::i18n::tr("Des failles connues touchent vos logiciels"));
                sub.set_text(&crate::i18n::tr("Commencez par la liste « Attaques réelles » : ce sont les plus urgentes."));
            }
            let (ctx3, global3, list2, me3, sys3, headline2, sub2) = (ctx2.clone(), global2.clone(), list.clone(), me2.clone(), sys.clone(), headline.clone(), sub.clone());
            let (proj_n, urgent_n2) = (proj.len(), urgent_n);
            let arch_done_flag = arch_done;
            let (arch2, proj2, meta2, kev2) = (arch.clone(), proj.clone(), meta.clone(), kev.clone());
            let (trivy2, tdone) = (trivy_rows.clone(), trivy_done);
            let last_txt = last2.borrow().clone();
            glib::spawn_future_local(async move {
                let ups = actions::pending(&ctx3).await;
                let again: Rc<dyn Fn()> = Rc::new(move || {
                    if let Some(f) = me3.borrow().as_ref() {
                        f();
                    }
                });
                let tip = "Cliquez pour voir ce que l'application peut faire et la recommandation de la source";
                let old_kev: Vec<gtk::Widget> = Vec::new();
                let mut stale_w: Vec<gtk::Widget> = Vec::new();
                let mut items: Vec<gtk::Widget> = Vec::new();
                if !kev2.is_empty() {
                    items.push(section("ATTAQUES RÉELLES — À TRAITER EN PREMIER").upcast());
                    for (name, n, last) in kev2.iter().take(20) {
                        let fixed = global3.likely_fixed(name, last);
                        let recent = *last >= recent_from && !fixed;
                        let hint = if fixed { "votre paquet est plus récent que la faille : probablement déjà corrigé" } else if recent { "mettez ce logiciel à jour" } else { "ancienne faille : probablement déjà corrigée, vérifiez que le logiciel est à jour" };
                        let r = row(name, &format!("{n} faille(s) exploitée(s) par des pirates · la plus récente signalée le {last} · {hint}"), Some(if recent { ("Urgent", "sev-critical") } else if fixed { ("Probablement corrigé", "sev-ok") } else { ("À vérifier", "sev-medium") }));
                        let adv = advice::for_kev(name, &global3.kev_entries(name), &ups);
                        let (c, ag, nm) = (ctx3.clone(), again.clone(), name.clone());
                        let w = clickable(r, tip, Rc::new(move || show_advice(&c, &nm, "Logiciel ciblé par des attaques réelles.", adv.clone(), vec![], ag.clone())));
                        if recent {
                            items.push(w.upcast());
                        }
                    }
                }
                // Entrées du tracker d'Arch qui visent une version PLUS ANCIENNE que celle installée : probablement obsolètes.
                let only: HashSet<String> = arch2.iter().map(|r| r[0].clone()).collect();
                let installed = global3.installed_map();
                let json = crate::util::load_private("avg.json", 16 << 20);
                let (tx, rx) = async_channel::bounded(1);
                std::thread::spawn(move || {
                    let res = json.map(|j| crate::tracker::obsolete_packages(&crate::tracker::parse(&j), &installed, &only, &crate::tracker::vercmp)).unwrap_or_default();
                    let _ = tx.send_blocking(res);
                });
                let obsolete: HashMap<String, Vec<crate::tracker::Obsolete>> = rx.recv().await.unwrap_or_default();
                let (real, stale): (Vec<&Vec<String>>, Vec<&Vec<String>>) = arch2.iter().partition(|r| !obsolete.contains_key(&r[0]));
                if arch_done_flag {
                    sys3.set(&if real.is_empty() { "Aucune faille".to_string() } else { format!("{} logiciel(s)", real.len()) }, if real.is_empty() { "Aucun de vos paquets n'a de faille connue non corrigée." } else { "Logiciels installés qui ont une faille connue, d'après l'équipe sécurité d'Arch Linux." });
                }
                let libs = lib_groups(&trivy2);
                let sys_items: Vec<crate::depfix::Item> = {
                    let (txi, rxi) = async_channel::bounded(1);
                    let rows = trivy2.clone();
                    std::thread::spawn(move || {
                        let paths: Vec<String> = rows.iter().map(|x| crate::depfix::row_path(x)).filter(|p| !p.is_empty()).collect::<HashSet<_>>().into_iter().collect();
                        let owners = crate::depfix::pacman_owners(&paths);
                        let _ = txi.send_blocking(crate::depfix::plan_system(&rows, &owners));
                    });
                    rxi.recv().await.unwrap_or_default()
                };
                if arch_done_flag || tdone {
                    let n_pk = global3.installed_map().len();
                    let t = |s: &str| crate::i18n::tr(s);
                    let mut lines = vec![if real.is_empty() { t("Aucun de vos paquets n'a de faille connue non corrigée.") } else { t("Logiciels installés qui ont une faille connue, d'après l'équipe sécurité d'Arch Linux.") }];
                    if n_pk > 0 {
                        lines.push(format!("{n_pk} {}", t("paquets vérifiés")));
                    }
                    lines.push(if tdone { format!("{} {}", libs.len(), t("bibliothèque(s) de programmes installés avec une faille")) } else { t("Bibliothèques des programmes (Python, Node, Rust…) : pas encore analysées") });
                    if !last_txt.is_empty() {
                        lines.push(last_txt.clone());
                    }
                    let value = if !arch_done_flag { t("Non analysé") } else if !real.is_empty() { format!("{} logiciel(s)", real.len()) } else if !libs.is_empty() { format!("{} bibliothèque(s)", libs.len()) } else { t("Aucune faille") };
                    sys3.value.set_text(&value);
                    sys3.text.set_text(&lines.join("\n"));
                }
                if arch_done_flag {
                    let sys_real = real.len();
                    let (h, s) = if sys_real + urgent_n2 == 0 && proj_n == 0 { ("Votre système est sain", "Aucune faille connue ne touche vos logiciels. Lancez une analyse pour vérifier à nouveau.") } else if sys_real + urgent_n2 == 0 { ("Votre système est sain", "Seules les bibliothèques de vos projets ont des failles connues (voir « Vos projets » plus bas).") } else { ("Des failles connues touchent vos logiciels", "Commencez par la liste « Attaques réelles » : ce sont les plus urgentes.") };
                    headline2.set_text(&crate::i18n::tr(h));
                    sub2.set_text(&crate::i18n::tr(s));
                }
                let arch2: Vec<Vec<String>> = real.into_iter().cloned().collect();
                let stale_rows: Vec<Vec<String>> = stale.into_iter().cloned().collect();
                if !arch2.is_empty() {
                    items.push(section("VOTRE SYSTÈME").upcast());
                    for r in arch2.iter().take(40) {
                        let (word, css) = sev_word(&r[1]);
                        let fix = if r[3] == "aucun" { "pas encore de correctif publié".to_string() } else { format!("correctif disponible : {}", r[3]) };
                        let line = row(&r[0], &format!("{} faille(s) · {} · {fix}", r[4], r[2]), Some((word, css)));
                        let adv = advice::for_system_package(&r[0], &r[3], &r[5], &ups);
                        let (c, ag, nm) = (ctx3.clone(), again.clone(), r[0].clone());
                        items.push(clickable(line, tip, Rc::new(move || show_advice(&c, &nm, "Logiciel installé avec une faille connue.", adv.clone(), vec![], ag.clone()))).upcast());
                    }
                }
                if !libs.is_empty() {
                    items.push(section("BIBLIOTHÈQUES DES PROGRAMMES INSTALLÉS").upcast());
                    // un seul bloc par PROGRAMME (déduit de l'emplacement) : le détail de chaque bibliothèque s'ouvre au clic
                    let mut progs: Vec<(String, Vec<&LibGroup>)> = Vec::new();
                    for l in libs.iter() {
                        match progs.iter_mut().find(|(p, _)| *p == l.program) {
                            Some((_, v)) => v.push(l),
                            None => progs.push((l.program.clone(), vec![l])),
                        }
                    }
                    progs.sort_by_key(|(p, v)| (std::cmp::Reverse(v.iter().map(|l| l.grave).sum::<usize>()), std::cmp::Reverse(v.iter().map(|l| l.n).sum::<usize>()), p.clone()));
                    for (prog, entries) in progs.iter().take(25) {
                        let (n_all, g_all): (usize, usize) = (entries.iter().map(|l| l.n).sum(), entries.iter().map(|l| l.grave).sum());
                        let title = if entries.len() == 1 { format!("{prog} — {} {}", entries[0].name, entries[0].ver) } else { prog.clone() };
                        let sub = format!("{} bibliothèque(s) · {n_all} faille(s) dont {g_all} grave(s)", entries.len());
                        let line = row(&title, &sub, Some(if g_all > 0 { ("Grave", "sev-high") } else { ("Moyenne", "sev-medium") }));
                        let mut adv = Advice {
                            source: "Trivy (Aqua Security) — bibliothèques trouvées dans les programmes installés".into(),
                            recommendation: vec![format!("{prog} : {} bibliothèque(s) avec une faille connue, {n_all} faille(s) au total ({g_all} grave(s)).", entries.len())],
                            ..Default::default()
                        };
                        let mut handlers: Vec<actions::Handler> = Vec::new();
                        let mut notes: Vec<String> = Vec::new();
                        let mut owners_pk: Vec<String> = Vec::new();
                        for l in entries.iter() {
                            let fixtxt = if l.fix.is_empty() { "pas de correctif connu".to_string() } else { format!("mettre à jour vers {}", l.fix) };
                            adv.recommendation.push(format!("• {} {} : {} faille(s) dont {} grave(s) · {fixtxt} · {}", l.name, l.ver, l.n, l.grave, l.kind));
                            for it in sys_items.iter().filter(|i| i.name == l.name && i.version == l.ver) {
                                match it.kind {
                                    crate::depfix::Kind::Manual => {
                                        if !it.pkg.is_empty() && ups.iter().any(|u| u.name == it.pkg) {
                                            let d = Direct::SystemUpdate { packages: vec![it.pkg.clone()] };
                                            if !adv.direct.contains(&d) {
                                                adv.direct.push(d);
                                            }
                                        }
                                        if !it.command.is_empty() {
                                            let d = Direct::CopyCommand { command: it.command.clone() };
                                            if !adv.direct.contains(&d) {
                                                adv.direct.push(d);
                                            }
                                        }
                                        if !notes.contains(&it.note) {
                                            notes.push(it.note.clone());
                                        }
                                        if !it.pkg.is_empty() && !owners_pk.contains(&it.pkg) {
                                            owners_pk.push(it.pkg.clone());
                                        }
                                    }
                                    _ => {
                                        let d = Direct::LibFix { name: it.name.clone(), fixed: it.fixed.clone(), place: it.place.clone() };
                                        if !adv.direct.contains(&d) {
                                            adv.direct.push(d.clone());
                                            let (c, ag, itc) = (ctx3.clone(), again.clone(), it.clone());
                                            handlers.push((d, Rc::new(move || { let ag = ag.clone(); super::dialogs::project_fix(&c, "Corriger les bibliothèques du système", vec![itc.clone()], Box::new(move || ag())) })));
                                        }
                                    }
                                }
                            }
                        }
                        adv.recommendation.extend(notes.iter().cloned());
                        if adv.direct.is_empty() {
                            adv.no_direct = Some(notes.first().cloned().unwrap_or_else(|| "Ces bibliothèques sont livrées avec un logiciel installé : elles se corrigent en mettant ce logiciel à jour. Si aucune mise à jour n'existe encore, il n'y a rien à faire pour l'instant.".to_string()));
                        }
                        let (c, nm) = (ctx3.clone(), prog.clone());
                        items.push(clickable(line, tip, Rc::new(move || {
                            let (c, nm, adv, handlers, pks) = (c.clone(), nm.clone(), adv.clone(), handlers.clone(), owners_pk.clone());
                            glib::spawn_future_local(async move {
                                let mut adv = adv;
                                if !pks.is_empty() {
                                    let (txp, rxp) = async_channel::bounded(1);
                                    let p2 = pks.clone();
                                    std::thread::spawn(move || {
                                        let _ = txp.send_blocking(crate::pkginfo::lookup(&p2));
                                    });
                                    let infos = rxp.recv().await.unwrap_or_default();
                                    let mut extra: Vec<String> = pks.iter().filter_map(|p| infos.get(p).map(|i| crate::pkginfo::describe(p, i))).collect();
                                    extra.append(&mut adv.recommendation);
                                    adv.recommendation = extra;
                                }
                                show_advice(&c, &nm, "Bibliothèques d'un programme installé avec des failles connues.", adv, handlers, Rc::new(|| {}));
                            });
                        })).upcast());
                    }
                }
                if !stale_rows.is_empty() {
                    for r in stale_rows.iter().take(40) {
                        let o = obsolete.get(&r[0]).cloned().unwrap_or_default();
                        let first = o.first().cloned().unwrap_or(crate::tracker::Obsolete { avg: String::new(), affected: String::new(), installed: String::new() });
                        let line = row(&r[0], &format!("Le tracker vise la version {} ; vous avez la {} : probablement déjà corrigé", first.affected, first.installed), Some(("Obsolète", "sev-unknown")));
                        let adv = Advice {
                            source: "Arch Security Tracker + comparaison de versions (vercmp de pacman)".into(),
                            no_direct: Some("Il n'y a rien à corriger : votre version est plus récente que celle visée par ces entrées.".into()),
                            recommendation: vec![
                                format!("{} entrée(s) du tracker pour « {} » : {}.", o.len(), r[0], o.iter().map(|x| format!("{} (version visée {})", x.avg, x.affected)).collect::<Vec<_>>().join(", ")),
                                format!("Votre version installée est {}, plus récente que chacune des versions visées.", first.installed),
                                "Le tracker garde ces entrées « Vulnerable » sans jamais noter de correctif, d'où l'alerte d'arch-audit. Ce n'est pas une certitude absolue (le tracker ne dit pas quelle version corrige), mais c'est très probablement un faux positif.".into(),
                            ],
                            ..Default::default()
                        };
                        let (c, nm) = (ctx3.clone(), r[0].clone());
                        stale_w.push(clickable(line, tip, Rc::new(move || show_advice(&c, &nm, "Entrée obsolète du tracker.", adv.clone(), vec![], Rc::new(|| {})))).upcast());
                    }
                }
                if !proj2.is_empty() {
                    items.push(section("VOS PROJETS").upcast());
                    let mut v: Vec<_> = proj2.iter().collect();
                    v.sort_by(|a, b| b.1.1.cmp(&a.1.1).then(b.1.0.cmp(&a.1.0)));
                    for ((name, ver), (n, grave, fixed)) in v.into_iter().take(25) {
                        let fix = if fixed.is_empty() { "pas de correctif connu".to_string() } else { format!("mettre à jour vers {fixed}") };
                        let where_ = meta2.get(&(name.clone(), ver.clone())).map(|(_, fs)| { let mut d: Vec<String> = fs.iter().filter_map(|f| std::path::Path::new(f).parent()?.file_name().map(|n| n.to_string_lossy().into_owned())).collect(); d.dedup(); d.join(", ") }).unwrap_or_default();
                        let line = row(&format!("{name} {ver}"), &format!("{n} faille(s) dont {grave} grave(s) · {fix}{}", if where_.is_empty() { String::new() } else { format!(" · {} {where_}", crate::i18n::tr("dans")) }), Some(if *grave > 0 { ("Grave", "sev-high") } else { ("Moyenne", "sev-medium") }));
                        let (eco, files) = meta2.get(&(name.clone(), ver.clone())).cloned().unwrap_or_default();
                        let adv = advice::for_dependency(&eco, name, ver, if fixed.is_empty() { "aucun" } else { fixed }, &files);
                        let (c, ag, nm) = (ctx3.clone(), again.clone(), format!("{name} {ver}"));
                        items.push(clickable(line, tip, Rc::new(move || show_advice(&c, &nm, "Bibliothèque d'un de vos projets avec une faille connue.", adv.clone(), vec![], ag.clone()))).upcast());
                    }
                }
                // ce qui est déjà corrigé (anciennes entrées du tracker, paquets plus récents que la faille) n'est pas affiché du tout
                let _ = (&old_kev, &stale_w);
                let folds: Vec<gtk::Widget> = Vec::new();
                clear(&list2);
                let empty = items.is_empty();
                set_list(&list2, items, if folds.is_empty() { "Aucune faille connue dans les dernières analyses." } else { "Rien d'urgent à corriger." });
                let _ = empty;
                for w in folds {
                    list2.append(&w);
                }
            });
        }
    });
    *me.borrow_mut() = Some(refresh.clone());
    let (p, r, c) = (pages.clone(), refresh.clone(), sys.clone());
    sys.button("Analyser", move || {
        let (pa, pt, c, r) = (p["arch-audit"].clone(), p["trivy"].clone(), c.clone(), r.clone());
        let last = last_run.clone();
        c.value.set_text(&crate::i18n::tr("Analyse en cours…"));
        c.text.set_text(&crate::i18n::tr("Vérification des paquets, puis des bibliothèques de vos programmes installés (Python, Node, Rust…). Cela peut prendre quelques minutes."));
        set_busy(&c, true);
        glib::spawn_future_local(async move {
            let t0 = std::time::Instant::now();
            pa.run_await().await;
            let t_pk = t0.elapsed().as_secs_f32();
            r();
            // le dossier personnel reste hors de ce périmètre : vos projets ont leur propre analyse
            let cur = pt.panel.values().s("skipdirs").to_string();
            if let Some(h) = crate::util::home_dir().map(|p| p.to_string_lossy().into_owned()) {
                if !h.is_empty() && !h.contains(',') && !cur.split(',').any(|x| x.trim() == h) {
                    pt.panel.set_text("skipdirs", &if cur.is_empty() { h } else { format!("{cur},{h}") });
                }
            }
            pt.panel.set_text("target", "/");
            let t1 = std::time::Instant::now();
            pt.run_await().await;
            let t_lib = t1.elapsed().as_secs_f32();
            let at = glib::DateTime::now_local().ok().and_then(|d| d.format("%H:%M").ok()).map(|s| s.to_string()).unwrap_or_default();
            let t = |s: &str| crate::i18n::tr(s);
            *last.borrow_mut() = format!("{} {at} · {} {t_pk:.1} s ({}) · {} {t_lib:.0} s", t("Vérifié à"), t("paquets"), t("données du tracker Arch téléchargées à l'instant"), t("bibliothèques"));
            set_busy(&c, false);
            r();
        });
    });
    let (ctx3, r) = (ctx.clone(), refresh.clone());
    sys.button("Corriger", move || {
        let (ctx, r) = (ctx3.clone(), r.clone());
        let rows: Vec<Vec<String>> = ctx.state.borrow().tools.get("trivy").map(|s| s.rows.clone()).unwrap_or_default();
        glib::spawn_future_local(async move {
            let ups = actions::pending(&ctx).await;
            let paths: Vec<String> = rows.iter().map(|x| crate::depfix::row_path(x)).filter(|p| !p.is_empty()).collect::<HashSet<_>>().into_iter().collect();
            let (tx, rx) = async_channel::bounded(1);
            std::thread::spawn(move || {
                let owners = crate::depfix::pacman_owners(&paths);
                let _ = tx.send_blocking(crate::depfix::plan_system(&rows, &owners));
            });
            let items = rx.recv().await.unwrap_or_default();
            let r2 = r.clone();
            let libs_title = "Corriger les bibliothèques du système";
            if !ups.is_empty() {
                // d'abord les mises à jour du système ; ensuite, s'il y en a, les bibliothèques
                let ctx2 = ctx.clone();
                let after: Box<dyn FnOnce()> = if items.is_empty() { Box::new(move || r2()) } else { Box::new(move || super::dialogs::project_fix(&ctx2, libs_title, items, Box::new(move || r2()))) };
                super::dialogs::system_update(&ctx, after);
            } else if !items.is_empty() {
                super::dialogs::project_fix(&ctx, libs_title, items, Box::new(move || r2()));
            } else {
                super::dialogs::system_update(&ctx, Box::new(move || r2()));
            }
        });
    });
    let (p, r, c) = (pages.clone(), refresh.clone(), prj.clone());
    {
        let ctx7 = ctx.clone();
        prj.button("Analyser", move || {
            if ctx7.state.borrow().settings.project_dirs.is_empty() {
                let r4 = r.clone();
                super::wizard::show_folders_dialog(&ctx7, Rc::new(move || r4()));
            } else {
                analyse(&p, "osv-scanner", &c, r.clone());
            }
        });
    }
    {
        let (ctx8, r) = (ctx.clone(), refresh.clone());
        prj.button("Corriger", move || {
            let rows: Vec<Vec<String>> = if ctx8.state.borrow().settings.project_dirs.is_empty() { Vec::new() } else { ctx8.state.borrow().tools.get("osv-scanner").map(|s| s.rows.clone()).unwrap_or_default() };
            let items = crate::depfix::plan(&rows, None);
            let r = r.clone();
            if items.is_empty() {
                let d = adw::AlertDialog::new(Some(&crate::i18n::tr("Rien à corriger")), Some(&crate::i18n::tr("Aucune correction n'est proposée : lancez d'abord « Analyser », ou OSV ne connaît pas de version corrective pour ces bibliothèques.")));
                d.add_response("close", &crate::i18n::tr("Fermer"));
                let w = ctx8.window();
                glib::spawn_future_local(async move {
                    let _ = d.choose_future(w.as_ref()).await;
                });
            } else {
                super::dialogs::project_fix(&ctx8, "Corriger vos projets", items, Box::new(move || r()));
            }
        });
    }
    {
        let (ctx5, pg, r2) = (ctx.clone(), pages["osv-scanner"].clone(), refresh.clone());
        prj.button("Dossiers…", move || {
            let r3 = r2.clone();
            super::wizard::show_folders_dialog(&ctx5, Rc::new(move || r3()));
        });
        let _ = &pg;
    }
    {
        let (ctx9, g, r) = (ctx.clone(), global.clone(), refresh.clone());
        atk.button("Corriger", move || {
            let recent_from: String = crate::global::iso_utc(crate::util::now_unix() - 365 * 86_400).chars().take(10).collect();
            let names: Vec<String> = g.kev_groups().into_iter().filter(|(n, _, last)| last.as_str() >= recent_from.as_str() && !g.likely_fixed(n, last)).map(|(n, _, _)| n).collect();
            let r = r.clone();
            if names.is_empty() {
                return;
            }
            super::dialogs::fix_attacks(&ctx9, names, Box::new(move || r()));
        });
    }
    let (g, r, c) = (global.clone(), refresh.clone(), atk.clone());
    atk.button("Actualiser la liste", move || {
        c.value.set_text(&crate::i18n::tr("Mise à jour…"));
        let (g, r) = (g.clone(), r.clone());
        glib::spawn_future_local(async move {
            g.update_kev_async().await;
            r();
        });
    });
    wire_refresh(&s.root, refresh);
    s.root.upcast()
}

fn maj(ctx: &Rc<Ctx>, global: &Rc<GlobalPage>) -> gtk::Widget {
    let s = shell("mod-maj");
    let sys = Rc::new(Card::new("tile-maj", "software-update-available-symbolic", "MISES À JOUR DU SYSTÈME"));
    let db = Rc::new(Card::new("tile-maj", "emblem-synchronizing-symbolic", "BASES DE FAILLES"));
    s.cards.append(&sys.root);
    s.cards.append(&db.root);
    let (headline, sub, list) = (s.headline.clone(), s.sub.clone(), s.list.clone());
    let ctx2 = ctx.clone();
    let me: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(std::cell::RefCell::new(None));
    let refresh: Rc<dyn Fn()> = Rc::new({
        let (sys, db, me2) = (sys.clone(), db.clone(), me.clone());
        move || {
            // bases de failles
            let st = ctx2.state.borrow();
            let age = |k: &str| st.db.get(k).filter(|s| s.ok).map(|s| (crate::util::now_unix() - s.time) / 3600);
            let d = |k: &str| st.db.get(k).filter(|s| s.ok).map(|s| when(s.time).replace("analysé le ", "")).unwrap_or_else(|| "jamais".into());
            let fresh = age("kev").is_some_and(|h| h < 48) && age("trivy").is_some_and(|h| h < 48);
            db.set(if fresh { "À jour" } else { "À mettre à jour" }, &format!("Liste des attaques réelles (CISA) : {}\nBase des failles (Trivy) : {}\nMise à jour automatique : {}", d("kev"), d("trivy"), if st.settings.auto_update { "activée" } else { "désactivée" }));
            drop(st);
            // mises à jour du système (en arrière-plan)
            let (tx, rx) = async_channel::bounded::<String>(1);
            std::thread::spawn(move || {
                let _ = tx.send_blocking(pending_updates_blocking());
            });
            let (sys, headline, sub, list, ctx3, me3) = (sys.clone(), headline.clone(), sub.clone(), list.clone(), ctx2.clone(), me2.clone());
            glib::spawn_future_local(async move {
                let Ok(out) = rx.recv().await else { return };
                let ups = risk::parse_updates(&out);
                *ctx3.pending.borrow_mut() = Some((crate::util::now_unix(), ups.clone()));
                let again: Rc<dyn Fn()> = Rc::new(move || {
                    if let Some(f) = me3.borrow().as_ref() {
                        f();
                    }
                });
                let risks = risk::assess(&ups);
                let aur = actions::pending_aur().await;
                let helper = crate::ui::dialogs::aur_helper();
                clear(&list);
                if ups.is_empty() && !aur.is_empty() && helper.is_some() {
                    headline.set_text(&format!("{} mise(s) à jour AUR disponible(s)", aur.len()));
                    sub.set_text("Les paquets AUR ne sont pas vérifiés par Arch : vous relirez chaque PKGBUILD avant l'installation.");
                    sys.set(&format!("{} mise(s) à jour AUR", aur.len()), "Dépôts officiels à jour. « Corriger » télécharge les recettes AUR, vous les faites relire, puis les installe.");
                } else if ups.is_empty() {
                    headline.set_text(&crate::i18n::tr("Votre système est à jour"));
                    sub.set_text(&crate::i18n::tr("Aucune mise à jour n'est en attente."));
                    sys.set("À jour", "Tous vos paquets sont à la dernière version.");
                } else {
                    let high = risks.iter().filter(|r| r.level == RiskLevel::High).count();
                    headline.set_text(&format!("{} mise(s) à jour disponible(s)", ups.len()));
                    sub.set_text(if high > 0 { "Certaines peuvent bloquer le système si elles se passent mal : vous serez prévenu avant de les installer." } else { "Aucun risque particulier détecté." });
                    sys.set(&format!("{} mise(s) à jour", ups.len()), &if high > 0 { format!("⚠ {high} point(s) à risque élevé : un instantané de secours est créé avant.") } else { "Prêtes à installer.".to_string() });
                    let mut risky: HashMap<&str, RiskLevel> = HashMap::new();
                    let mut msgs: HashMap<&str, &str> = HashMap::new();
                    for r in &risks {
                        for p in &r.packages {
                            risky.insert(p.as_str(), r.level);
                            msgs.insert(p.as_str(), r.message);
                        }
                    }
                    let mut sorted: Vec<&risk::Update> = ups.iter().collect();
                    sorted.sort_by_key(|u| !risky.contains_key(u.name.as_str()));
                    let items = sorted
                        .into_iter()
                        .take(80)
                        .map(|u| {
                            let tag = risky.get(u.name.as_str()).map(|l| if *l == RiskLevel::High { ("Risque élevé", "sev-critical") } else { ("À surveiller", "sev-medium") });
                            let line = row(&u.name, &format!("{} → {}", u.old, u.new), tag);
                            let adv = advice::for_update(u, msgs.get(u.name.as_str()).copied());
                            let (c, ag, nm) = (ctx3.clone(), again.clone(), u.name.clone());
                            clickable(line, "Cliquez pour voir le détail et installer", Rc::new(move || show_advice(&c, &nm, "Mise à jour disponible.", adv.clone(), vec![], ag.clone()))).upcast()
                        })
                        .collect();
                    set_list(&list, items, "");
                    for r in &risks {
                        let _ = r;
                    }
                }
                // AUR (paru / yay) : détecté en lecture seule, JAMAIS installé automatiquement (relecture des PKGBUILD obligatoire)
                match (helper, aur.is_empty()) {
                    (Some(h), false) => {
                        list.append(&section(&format!("PAQUETS AUR — À RELIRE AVANT D'INSTALLER ({h})")));
                        let cmd = format!("{h} -Sua");
                        for u in aur.iter().take(40) {
                            let line = row(&u.name, &format!("{} → {}", u.old, u.new), Some(("AUR — à relire", "sev-medium")));
                            let adv = Advice {
                                source: "AUR (Arch User Repository)".into(),
                                direct: vec![Direct::AurUpdate { helper: h.to_string(), packages: vec![u.name.clone()], terminal: false }, Direct::AurUpdate { helper: h.to_string(), packages: vec![u.name.clone()], terminal: true }, Direct::CopyCommand { command: cmd.clone() }],
                                recommendation: vec![
                                    format!("{} : {} → {}", u.name, u.old, u.new),
                                    "Les paquets AUR ne sont pas vérifiés par Arch : n'importe qui peut les modifier, et des paquets AUR ont été piégés en 2026 (scripts de build malveillants).".into(),
                                    format!("« Mettre à jour dans un terminal » ouvre votre terminal : {h} y affiche les différences du PKGBUILD pour que vous les releviez avant d'accepter, et le mot de passe y est saisi (l'application ne le voit jamais)."),
                                    "L'application ne contourne jamais cette relecture : jamais d'installation silencieuse (pas de --noconfirm ni --skipreview).".into(),
                                ],
                                ..Default::default()
                            };
                            let (c, nm) = (ctx3.clone(), u.name.clone());
                            list.append(&clickable(line, "Cliquez pour voir comment l'installer en sécurité", Rc::new(move || show_advice(&c, &nm, "Mise à jour AUR disponible.", adv.clone(), vec![], Rc::new(|| {})))));
                        }
                    }
                    (Some(h), true) => list.append(&plain_label(&format!("AUR ({h}) : aucune mise à jour en attente."))),
                    (None, _) => list.append(&plain_label("AUR : aucun assistant (paru, yay) détecté : vos paquets AUR ne sont pas surveillés.")),
                }
            });
        }
    });
    *me.borrow_mut() = Some(refresh.clone());
    let (c3, r) = (ctx.clone(), refresh.clone());
    sys.button("Corriger", move || {
        let r = r.clone();
        system_update(&c3, Box::new(move || r()));
    });
    let (c4, g, r, dbc) = (ctx.clone(), global.clone(), refresh.clone(), db.clone());
    db.button("Mettre à jour maintenant", move || {
        dbc.value.set_text(&crate::i18n::tr("Mise à jour…"));
        let (c, g, r) = (c4.clone(), g.clone(), r.clone());
        glib::spawn_future_local(async move {
            update_cve_data(&c, &g, 0).await;
            r();
        });
    });
    let sw = gtk::Switch::new();
    sw.set_active(ctx.state.borrow().settings.auto_update);
    sw.set_valign(gtk::Align::Center);
    let c5 = ctx.clone();
    sw.connect_state_set(move |_, on| {
        c5.state.borrow_mut().settings.auto_update = on;
        c5.save();
        glib::Propagation::Proceed
    });
    let lbl = gtk::Label::new(Some(crate::i18n::tr("Automatique").as_str()));
    lbl.add_css_class("soft");
    db.btns.append(&lbl);
    db.btns.append(&sw);
    wire_refresh(&s.root, refresh);
    s.root.upcast()
}

fn reseau(ctx: &Rc<Ctx>) -> gtk::Widget {
    let s = shell("mod-reseau");
    let svc = Rc::new(Card::new("tile-reseau", "network-server-symbolic", "SERVICES OUVERTS AU RÉSEAU"));
    let fw = Rc::new(Card::new("tile-reseau", "security-medium-symbolic", "PARE-FEU"));
    fw.btns.set_orientation(gtk::Orientation::Vertical);
    fw.btns.set_halign(gtk::Align::Start);
    let net = Rc::new(Card::new("tile-reseau", "network-wired-symbolic", "CONNEXIONS VERS INTERNET"));
    for c in [&svc, &fw, &net] {
        s.cards.append(&c.root);
    }
    {
        let (sw, l) = (s.sw.clone(), s.list.clone());
        svc.set_click(Rc::new(move || scroll_to(&sw, Some(&l))));
        let (sw, l) = (s.sw.clone(), s.list.clone());
        net.set_click(Rc::new(move || { let _ = &l; scroll_to(&sw, None) }));
    }
    let (headline, sub, list) = (s.headline.clone(), s.sub.clone(), s.list.clone());
    let ctx2 = ctx.clone();
    let refresh: Rc<dyn Fn()> = {
        let (svc, fw, net) = (svc.clone(), fw.clone(), net.clone());
        let me: Rc<std::cell::RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(std::cell::RefCell::new(None));
        let me2 = me.clone();
        let f: Rc<dyn Fn()> = Rc::new(move || {
            let (tx, rx) = async_channel::bounded::<Snapshot>(1);
            std::thread::spawn(move || {
                let _ = tx.send_blocking(live::snapshot());
            });
            let (svc, fw, net, headline, sub, list, ctx2, me3) = (svc.clone(), fw.clone(), net.clone(), headline.clone(), sub.clone(), list.clone(), ctx2.clone(), me2.clone());
            glib::spawn_future_local(async move {
                let Ok(snap) = rx.recv().await else { return };
                let allowed: HashSet<String> = ctx2.state.borrow().allowed.clone().unwrap_or_default().into_iter().collect();
                let (wanted, to_check) = live::exposure(&snap, &allowed);
                // services regroupés par programme
                let mut services: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();
                for l in snap.listeners.iter().filter(|l| l.expo == Expo::All) {
                    let key = key_of(&l.proc, &l.port);
                    let e = services.entry(key.clone()).or_insert((vec![], key));
                    let p = format!("{} ({})", l.port, l.proto);
                    if !e.0.contains(&p) {
                        e.0.push(p);
                    }
                }
                let mut svc_info: BTreeMap<String, (Vec<(String, u16)>, Vec<u32>)> = BTreeMap::new();
                for l in snap.listeners.iter().filter(|l| l.expo == Expo::All) {
                    let e = svc_info.entry(key_of(&l.proc, &l.port)).or_default();
                    if let Ok(p) = l.port.parse::<u16>() {
                        if !e.0.contains(&(l.proto.clone(), p)) {
                            e.0.push((l.proto.clone(), p));
                        }
                    }
                    if l.pid > 1 && !e.1.contains(&l.pid) {
                        e.1.push(l.pid);
                    }
                }
                let by_conn_pids: BTreeMap<String, Vec<u32>> = {
                    let mut m: BTreeMap<String, Vec<u32>> = BTreeMap::new();
                    for c in snap.conns.iter().filter(|c| c.public) {
                        if let Ok(p) = c.pid.parse::<u32>() {
                            let e = m.entry(c.proc.clone()).or_default();
                            if !e.contains(&p) {
                                e.push(p);
                            }
                        }
                    }
                    m
                };
                let mut by_app: BTreeMap<String, (usize, HashSet<String>)> = BTreeMap::new();
                let mut public = 0;
                for c in snap.conns.iter().filter(|c| c.public) {
                    public += 1;
                    let e = by_app.entry(c.proc.clone()).or_default();
                    e.0 += 1;
                    e.1.insert(c.remote.clone());
                }
                headline.set_text(if to_check == 0 { "Aucun service suspect" } else { "Des services sont ouverts sans que vous l'ayez confirmé" });
                sub.set_text(if to_check == 0 { "Tous les services accessibles depuis votre réseau sont ceux que vous avez choisis." } else { "Vérifiez la liste ci-dessous : cliquez « Autoriser » si vous les reconnaissez." });
                svc.set(&if to_check == 0 { format!("{wanted} autorisé(s)") } else { format!("{to_check} à vérifier") }, "Programmes qui acceptent des connexions venant d'autres appareils de votre réseau.");
                fw.set(if snap.firewall.is_some() { "Actif" } else { "Inactif" }, if snap.firewall.is_some() { "Les connexions entrantes non autorisées sont bloquées." } else { "Rien ne bloque les connexions entrantes. Sur votre réseau maison c'est acceptable ; sur un Wi-Fi public, activez un pare-feu." });
                while let Some(c) = fw.btns.first_child() {
                    fw.btns.remove(&c);
                }
                {
                    {
                        let (ctx_e, me_e) = (ctx2.clone(), me3.clone());
                        let edit = gtk::Button::with_label(&crate::i18n::tr("Modifier les règles"));
                        edit.add_css_class("glass-btn");
                        edit.connect_clicked(move |_| {
                            let me9 = me_e.clone();
                            super::wizard::show_fw_editor(&ctx_e, Rc::new(move || {
                                if let Some(f) = me9.borrow().as_ref() {
                                    f();
                                }
                            }));
                        });
                        fw.btns.append(&edit);
                    }
                    let own = super::dialogs::firewall_on(&ctx2);
                    let native = super::dialogs::native_active();
                    // un service nftables lancé par le système lui-même (hors de l'application) n'est pas géré ici
                    let foreign = !own && native.is_none() && snap.firewall.is_some();
                    let on = own || native.is_some();
                    if let Some(n) = native {
                        fw.set("Actif", &format!("Pare-feu du système ({n}) actif : il bloque les connexions entrantes non autorisées."));
                    } else if own {
                        fw.set("Actif", if super::dialogs::firewall_permanent() { "Pare-feu permanent : il bloque les connexions entrantes non autorisées à chaque démarrage." } else { "Le pare-feu de l'application bloque les connexions entrantes non autorisées (jusqu'au prochain redémarrage)." });
                    } else if foreign {
                        fw.set("Actif", "Un pare-feu nftables configuré sur votre système est actif : il est géré par vous, l'application n'y touche pas.");
                    }
                    if !foreign {
                    let b = gtk::Button::with_label(&crate::i18n::tr(if on { "Désactiver le pare-feu" } else { "Activer le pare-feu" }));
                    b.add_css_class("glass-btn");
                    let (ctx3, me4) = (ctx2.clone(), me3.clone());
                    let ports = {
                        let l: Vec<(String, String, String)> = snap.listeners.iter().filter(|l| l.expo == Expo::All).map(|l| (l.proc.clone(), l.port.clone(), l.proto.clone())).collect();
                        crate::procctl::firewall_args(&l, &allowed, &ctx2.state.borrow().fw_rules, ctx2.state.borrow().settings.fw_log)
                    };
                    b.connect_clicked(move |_| {
                        let me5 = me4.clone();
                        let then: Box<dyn FnOnce()> = Box::new(move || {
                            if let Some(f) = me5.borrow().as_ref() {
                                f();
                            }
                        });
                        if on {
                            super::dialogs::disable_firewall(&ctx3, then);
                        } else {
                            super::dialogs::enable_firewall(&ctx3, ports.clone(), then);
                        }
                    });
                    {
                        let b2 = b.clone();
                        fw.set_click(Rc::new(move || b2.emit_clicked()));
                    }
                    fw.btns.append(&b);
                    }
                    if on {
                        let upd = gtk::Button::with_label(&crate::i18n::tr("Mettre à jour les ports ouverts"));
                        upd.add_css_class("glass-btn");
                        let (ctx3, me4) = (ctx2.clone(), me3.clone());
                        let ports2 = {
                            let l: Vec<(String, String, String)> = snap.listeners.iter().filter(|l| l.expo == Expo::All).map(|l| (l.proc.clone(), l.port.clone(), l.proto.clone())).collect();
                            crate::procctl::firewall_args(&l, &allowed, &ctx2.state.borrow().fw_rules, ctx2.state.borrow().settings.fw_log)
                        };
                        upd.connect_clicked(move |_| {
                            let me5 = me4.clone();
                            super::dialogs::enable_firewall(&ctx3, ports2.clone(), Box::new(move || {
                                if let Some(f) = me5.borrow().as_ref() {
                                    f();
                                }
                            }));
                        });
                        fw.btns.append(&upd);
                    }
                }
                net.set(&public.to_string(), "Connexions ouvertes vers Internet en ce moment (navigateur, mises à jour, etc.).");
                clear(&list);
                list.append(&section("SERVICES ACCESSIBLES DEPUIS VOTRE RÉSEAU"));
                if to_check > 0 {
                    let all = gtk::Button::with_label(&crate::i18n::tr("Tout autoriser"));
                    all.add_css_class("glass-btn");
                    all.set_halign(gtk::Align::Start);
                    let (ctx6, me6, keys) = (ctx2.clone(), me3.clone(), services.keys().cloned().collect::<Vec<_>>());
                    all.connect_clicked(move |_| {
                        {
                            let mut st = ctx6.state.borrow_mut();
                            let l = st.allowed.get_or_insert_with(Vec::new);
                            for k in &keys {
                                if !l.contains(k) {
                                    l.push(k.clone());
                                }
                            }
                            l.sort();
                        }
                        ctx6.save();
                        if let Some(f) = me6.borrow().as_ref() {
                            f();
                        }
                    });
                    list.append(&all);
                }
                for (key, (ports, _)) in &services {
                    let ok = allowed.contains(key);
                    let name = key.strip_prefix("port:").map(|p| port_name(p)).unwrap_or_else(|| key.clone());
                    let r = row(&name, &format!("Ports : {}", ports.join(", ")), Some(if ok { ("Autorisé", "sev-ok") } else { ("À vérifier", "sev-medium") }));
                    if !ok {
                        let b = gtk::Button::with_label(&crate::i18n::tr("Autoriser"));
                        b.add_css_class("glass-btn");
                        b.set_valign(gtk::Align::Center);
                        let (ctx3, key, me4) = (ctx2.clone(), key.clone(), me3.clone());
                        b.connect_clicked(move |_| {
                            {
                                let mut st = ctx3.state.borrow_mut();
                                let l = st.allowed.get_or_insert_with(Vec::new);
                                if !l.contains(&key) {
                                    l.push(key.clone());
                                    l.sort();
                                }
                            }
                            ctx3.save();
                            if let Some(f) = me4.borrow().as_ref() {
                                f();
                            }
                        });
                        r.append(&b);
                    } else {
                        let b = gtk::Button::with_label(&crate::i18n::tr("Ne plus autoriser"));
                        b.add_css_class("glass-btn");
                        b.set_valign(gtk::Align::Center);
                        let (ctx3, key, me4) = (ctx2.clone(), key.clone(), me3.clone());
                        b.connect_clicked(move |_| {
                            ctx3.state.borrow_mut().allowed.get_or_insert_with(Vec::new).retain(|k| k != &key);
                            ctx3.save();
                            if let Some(f) = me4.borrow().as_ref() {
                                f();
                            }
                        });
                        r.append(&b);
                    }
                    let (ports_v, pids_v) = svc_info.get(key).cloned().unwrap_or_default();
                    let procs: Vec<crate::procctl::ProcInfo> = pids_v.iter().filter_map(|p| crate::procctl::read_proc(*p)).collect();
                    let blocked: Vec<(String, u16)> = ctx2.state.borrow().blocks.iter().filter(|b| b.kind == "port").map(|b| (b.proto.clone(), b.port)).collect();
                    let adv = advice::for_service(&name, &ports_v, &procs, &blocked, ok);
                    let (ctx4, key2, me5, name2) = (ctx2.clone(), key.clone(), me3.clone(), name.clone());
                    let mark: Rc<dyn Fn()> = {
                        let (ctx5, key3, me6) = (ctx2.clone(), key.clone(), me3.clone());
                        Rc::new(move || {
                            {
                                let mut st = ctx5.state.borrow_mut();
                                let l = st.allowed.get_or_insert_with(Vec::new);
                                if !l.contains(&key3) {
                                    l.push(key3.clone());
                                    l.sort();
                                }
                            }
                            ctx5.save();
                            if let Some(f) = me6.borrow().as_ref() {
                                f();
                            }
                        })
                    };
                    let _ = key2;
                    let r = clickable(r, "Cliquez pour voir les actions possibles (arrêter, bloquer)", Rc::new(move || {
                        let me7 = me5.clone();
                        show_advice(&ctx4, "Service accessible depuis le réseau", &name2, adv.clone(), vec![(Direct::MarkWanted, mark.clone())], Rc::new(move || {
                            if let Some(f) = me7.borrow().as_ref() {
                                f();
                            }
                        }));
                    }));
                    list.append(&r);
                }
                if services.is_empty() {
                    list.append(&plain_label("Aucun service n'écoute sur toutes les interfaces."));
                }
                if crate::procctl::fw_backend() != crate::procctl::FwBackend::Own {
                    list.append(&section("RÈGLES DU PARE-FEU"));
                    let b = crate::procctl::fw_backend();
                    let help = plain_label(&format!("{} {} : {}", crate::i18n::tr("Pare-feu détecté :"), b.id(), crate::i18n::tr("ses règles réelles (zones, services, ports, règles détaillées) se lisent et se modifient dans l'éditeur, même pare-feu désactivé.")));
                    help.add_css_class("soft");
                    list.append(&help);
                    let open = gtk::Button::with_label(&crate::i18n::tr("Ouvrir l'éditeur du pare-feu…"));
                    open.add_css_class("glass-btn");
                    open.set_halign(gtk::Align::Start);
                    let (ctx_e, me_e) = (ctx2.clone(), me3.clone());
                    open.connect_clicked(move |_| {
                        let me9 = me_e.clone();
                        super::wizard::show_fw_editor(&ctx_e, Rc::new(move || {
                            if let Some(f) = me9.borrow().as_ref() {
                                f();
                            }
                        }));
                    });
                    list.append(&open);
                } else {
                list.append(&section("RÈGLES DU PARE-FEU"));
                let help = plain_label("Les services marqués « autorisés » sont autorisés automatiquement. Ajoutez vos propres règles : autoriser, refuser ou limiter un port, pour tout le monde ou une seule adresse. Vous pouvez les modifier à tout moment, même pare-feu désactivé : elles sont appliquées à l'activation.");
                help.add_css_class("soft");
                list.append(&help);
                let rules = ctx2.state.borrow().fw_rules.clone();
                for (i, r) in rules.iter().enumerate() {
                    let (word, css) = match r.action.as_str() { "deny" => ("Refuser", "sev-critical"), "limit" => ("Limiter", "sev-medium"), _ => ("Autoriser", "sev-ok") };
                    let from = if r.from.is_empty() { "depuis n'importe où".to_string() } else { format!("depuis {}", r.from) };
                    let line = row(&format!("Port {}/{}", r.port, r.proto), &from, Some((word, css)));
                    let b = gtk::Button::with_label(&crate::i18n::tr("Supprimer"));
                    b.add_css_class("glass-btn");
                    b.set_valign(gtk::Align::Center);
                    let (ctx6, me6) = (ctx2.clone(), me3.clone());
                    b.connect_clicked(move |_| {
                        {
                            let mut st = ctx6.state.borrow_mut();
                            if i < st.fw_rules.len() {
                                st.fw_rules.remove(i);
                            }
                        }
                        ctx6.save();
                        if let Some(f) = me6.borrow().as_ref() {
                            f();
                        }
                    });
                    line.append(&b);
                    list.append(&line);
                }
                {
                    let bar = gtk::Box::new(gtk::Orientation::Horizontal, 10);
                    let add = gtk::Button::with_label(&crate::i18n::tr("Ajouter une règle…"));
                    add.add_css_class("glass-btn");
                    let (ctx6, me6) = (ctx2.clone(), me3.clone());
                    add.connect_clicked(move |_| {
                        let me7 = me6.clone();
                        super::dialogs::add_fw_rule(&ctx6, Box::new(move || {
                            if let Some(f) = me7.borrow().as_ref() {
                                f();
                            }
                        }));
                    });
                    bar.append(&add);
                    let sw = gtk::Switch::new();
                    sw.set_valign(gtk::Align::Center);
                    sw.set_active(ctx2.state.borrow().settings.fw_log);
                    let (c7, me8) = (ctx2.clone(), me3.clone());
                    sw.connect_state_set(move |_, on| {
                        c7.state.borrow_mut().settings.fw_log = on;
                        c7.save();
                        let me9 = me8.clone();
                        glib::idle_add_local_once(move || {
                            if let Some(f) = me9.borrow().as_ref() {
                                f();
                            }
                        });
                        glib::Propagation::Proceed
                    });
                    bar.append(&sw);
                    let ll = plain_label("Journaliser les connexions refusées");
                    ll.add_css_class("soft");
                    bar.append(&ll);
                    list.append(&bar);
                }
                }
                list.append(&section("CONNEXIONS VERS INTERNET, PAR PROGRAMME"));
                for (app, (n, hosts)) in &by_app {
                    let line = row(app, &format!("{n} connexion(s) vers {} serveur(s)", hosts.len()), None);
                    let procs: Vec<crate::procctl::ProcInfo> = by_conn_pids.get(app).map(|v| v.iter().filter_map(|p| crate::procctl::read_proc(*p)).collect()).unwrap_or_default();
                    let mut remotes: Vec<String> = hosts.iter().cloned().collect();
                    remotes.sort();
                    let adv = advice::for_connections(app, &procs, &remotes);
                    let (ctx4, me5, app2) = (ctx2.clone(), me3.clone(), app.clone());
                    list.append(&clickable(line, "Cliquez pour voir les actions possibles (arrêter, bloquer)", Rc::new(move || {
                        let me7 = me5.clone();
                        show_advice(&ctx4, "Connexions vers Internet", &app2, adv.clone(), vec![], Rc::new(move || {
                            if let Some(f) = me7.borrow().as_ref() {
                                f();
                            }
                        }));
                    })));
                }
                if by_app.is_empty() {
                    list.append(&plain_label("Aucune connexion vers Internet en ce moment."));
                }
                let blocks: Vec<crate::util::BlockRec> = ctx2.state.borrow().blocks.iter().filter(|b| b.kind != "firewall").cloned().collect();
                if !blocks.is_empty() {
                    list.append(&section("BLOCAGES ACTIFS"));
                    for b in &blocks {
                        let (title, sub) = if b.kind == "port" { (format!("Port {}/{}", b.port, b.proto), "Refusé pour tout ce qui vient du réseau".to_string()) } else { (format!("Serveur {}", b.ip), "Connexions sortantes refusées".to_string()) };
                        let r = row(&title, &sub, None);
                        if b.kind == "port" {
                            let btn = gtk::Button::with_label(&crate::i18n::tr("Débloquer"));
                            btn.add_css_class("glass-btn");
                            btn.set_valign(gtk::Align::Center);
                            let (ctx6, me6, proto, port) = (ctx2.clone(), me3.clone(), b.proto.clone(), b.port);
                            btn.connect_clicked(move |_| {
                                let me7 = me6.clone();
                                super::dialogs::unblock_port(&ctx6, proto.clone(), port, Box::new(move || {
                                    if let Some(f) = me7.borrow().as_ref() {
                                        f();
                                    }
                                }));
                            });
                            r.append(&btn);
                        }
                        list.append(&r);
                    }
                    let all = gtk::Button::with_label(&crate::i18n::tr("Tout débloquer"));
                    all.add_css_class("glass-btn");
                    all.set_halign(gtk::Align::Start);
                    let (ctx6, me6) = (ctx2.clone(), me3.clone());
                    all.connect_clicked(move |_| {
                        let me7 = me6.clone();
                        super::dialogs::unblock_all(&ctx6, Box::new(move || {
                            if let Some(f) = me7.borrow().as_ref() {
                                f();
                            }
                        }));
                    });
                    list.append(&all);
                }
            });
        });
        *me.borrow_mut() = Some(f.clone());
        f
    };
    wire_refresh(&s.root, refresh.clone());
    let r = refresh.clone();
    glib::timeout_add_seconds_local(10, move || {
        r();
        glib::ControlFlow::Continue
    });
    s.root.upcast()
}

fn config(ctx: &Rc<Ctx>, pages: &Pages) -> gtk::Widget {
    let s = shell("mod-config");
    s.banner.attach(&pages["lynis"], "Analyse de la configuration");
    let score = Rc::new(Card::new("tile-config", "preferences-system-symbolic", "SCORE DE SÉCURITÉ"));
    s.cards.append(&score.root);
    let hard = Rc::new(Card::new("tile-config", "emblem-system-symbolic", "DURCISSEMENT DU SYSTÈME"));
    s.cards.append(&hard.root);
    let (headline, sub, list) = (s.headline.clone(), s.sub.clone(), s.list.clone());
    let ctx2 = ctx.clone();
    let refresh: Rc<dyn Fn()> = Rc::new({
        let (score, hard) = (score.clone(), hard.clone());
        move || {
            clear(&list);
            {
                let p = crate::harden::pending();
                if let Some(b) = hard.btns.first_child().and_downcast::<gtk::Button>() {
                    b.set_label(&crate::i18n::tr(if crate::harden::applied() { "Annuler le durcissement" } else { "Appliquer" }));
                }
                if crate::harden::applied() {
                    hard.set("Appliqué", "Réglages du noyau et du réseau durcis (fichier sysctl.d). Vous pouvez les annuler à tout moment.");
                } else if p.is_empty() {
                    hard.set("Rien à durcir", "Les réglages du noyau et du réseau proposés sont déjà à la valeur recommandée.");
                } else {
                    hard.set(&format!("{} réglage(s) à appliquer", p.len()), "Réglages sûrs du noyau et du réseau (redirections ICMP, adresses du noyau…), appliqués par le mécanisme natif de Linux, sans effet sur l'usage normal.");
                }
            }
            let st = ctx2.state.borrow();
            match st.tools.get("lynis") {
                None => {
                    headline.set_text(&crate::i18n::tr("La configuration n'a pas encore été vérifiée"));
                    sub.set_text(&crate::i18n::tr("L'analyse examine SSH, les mots de passe, le noyau, les permissions… Votre mot de passe sera demandé."));
                    score.set("Non analysé", "Lynis note votre configuration sur 100 et propose des améliorations.");
                    set_list(&list, vec![], "Lancez l'analyse pour voir les conseils ici.");
                }
                Some(saved) => {
                    let sc = saved.result.score;
                    headline.set_text(&match sc {
                        Some(s) if s >= 80 => "Votre configuration est solide".to_string(),
                        Some(s) if s >= 60 => "Votre configuration est correcte, avec des points à améliorer".to_string(),
                        Some(_) => "Votre configuration mérite d'être renforcée".to_string(),
                        None => "Analyse terminée".to_string(),
                    });
                    sub.set_text(&format!("Dernière vérification : {}", when(saved.result.time).replace("analysé le ", "")));
                    score.set(&sc.map(|s| format!("{s} / 100")).unwrap_or_else(|| "—".into()), "Plus le score est haut, mieux votre système est protégé. Les conseils sont en anglais : ils viennent de l'outil Lynis.");
                    let mut items: Vec<gtk::Widget> = Vec::new();
                    for c in saved.rows.iter().take(45) {
                        let alert = c.first().map(String::as_str) == Some("Alerte");
                        let detail = c.get(4).cloned().unwrap_or_default().replace("text:", "").replace("arch-audit has output ", "");
                        let (id, text) = (c.get(2).cloned().unwrap_or_default(), c.get(3).cloned().unwrap_or_default());
                        let line = row(&text, &detail, Some(if alert { ("Alerte", "sev-critical") } else { ("Conseil", "sev-low") }));
                        let adv = advice::for_lynis(&id, &text, &detail);
                        let (ctx3, heading) = (ctx2.clone(), if alert { "Alerte de configuration" } else { "Conseil de durcissement" });
                        items.push(clickable(line, "Cliquez pour voir la recommandation de Lynis", Rc::new(move || show_advice(&ctx3, heading, &id, adv.clone(), vec![], Rc::new(|| {})))).upcast());
                    }
                    set_list(&list, items, "Aucun conseil.");
                }
            }
        }
    });
    let (p, r, c) = (pages.clone(), refresh.clone(), score.clone());
    score.button("Analyser", move || analyse(&p, "lynis", &c, r.clone()));
    {
        let (c1, r1) = (ctx.clone(), refresh.clone());
        hard.button(if crate::harden::applied() { "Annuler le durcissement" } else { "Appliquer" }, move || {
            let r2 = r1.clone();
            let then: Box<dyn FnOnce()> = Box::new(move || r2());
            if crate::harden::applied() {
                super::dialogs::revert_hardening(&c1, then);
            } else {
                super::dialogs::apply_hardening(&c1, then);
            }
        });
    }
    wire_refresh(&s.root, refresh);
    s.root.upcast()
}

/// Nom lisible d'un service système connu, d'après son numéro de port.
fn port_name(port: &str) -> String {
    let known = match port {
        "22" => "Accès à distance SSH",
        "53" => "Résolution de noms (DNS)",
        "67" => "Attribution d'adresses réseau (DHCP)",
        "631" => "Impression (CUPS)",
        "1900" => "Découverte d'appareils (UPnP)",
        "3389" => "Bureau à distance",
        "5353" => "Découverte d'appareils sur le réseau (mDNS)",
        "5355" => "Résolution de noms locale (LLMNR)",
        "5432" => "Base de données PostgreSQL",
        _ => "",
    };
    if known.is_empty() { format!("Service système (port {port})") } else { format!("{known} — port {port}") }
}

// ─────────────────────────── bandeau de progression ────────────────────────

/// Bandeau visible pendant une analyse : animation, étape, dernière ligne de sortie, durée, bouton Arrêter.
/// Pour une analyse administrateur, il indique clairement qu'elle attend le mot de passe.
struct Banner {
    root: gtk::Box,
    title: gtk::Label,
    detail: gtk::Label,
    elapsed: gtk::Label,
    spinner: gtk::Spinner,
    stop: gtk::Button,
    started: std::cell::Cell<Option<std::time::Instant>>,
    page: std::cell::RefCell<Option<std::rc::Weak<ToolPage>>>,
}

impl Banner {
    fn new() -> Rc<Banner> {
        let root = gtk::Box::new(gtk::Orientation::Horizontal, 14);
        root.add_css_class("glass-row");
        root.set_visible(false);
        let spinner = gtk::Spinner::new();
        spinner.set_size_request(28, 28);
        let col = gtk::Box::new(gtk::Orientation::Vertical, 2);
        col.set_hexpand(true);
        let title = plain_label("Analyse en cours…");
        title.add_css_class("row-title");
        let detail = plain_label("");
        detail.add_css_class("soft");
        detail.set_ellipsize(gtk::pango::EllipsizeMode::End);
        detail.set_wrap(false);
        col.append(&title);
        col.append(&detail);
        let elapsed = gtk::Label::new(Some(crate::i18n::tr("0:00").as_str()));
        elapsed.add_css_class("soft");
        let stop = gtk::Button::with_label(&crate::i18n::tr("Arrêter"));
        stop.add_css_class("glass-btn");
        stop.set_valign(gtk::Align::Center);
        root.append(&spinner);
        root.append(&col);
        root.append(&elapsed);
        root.append(&stop);
        let b = Rc::new(Banner { root, title, detail, elapsed, spinner, stop, started: std::cell::Cell::new(None), page: std::cell::RefCell::new(None) });
        let b2 = b.clone();
        b.stop.connect_clicked(move |_| {
            if let Some(p) = b2.page.borrow().as_ref().and_then(|w| w.upgrade()) {
                p.stop();
            }
        });
        let b3 = b.clone();
        glib::timeout_add_seconds_local(1, move || {
            if let Some(t) = b3.started.get() {
                let s = t.elapsed().as_secs();
                b3.elapsed.set_text(&format!("{}:{:02}", s / 60, s % 60));
            }
            glib::ControlFlow::Continue
        });
        b
    }

    /// Relie le bandeau à une analyse : il s'affiche dès qu'elle démarre, y compris lancée depuis « Soin intelligent ».
    fn attach(self: &Rc<Self>, page: &Rc<ToolPage>, label: &'static str) {
        let (me, weak) = (self.clone(), Rc::downgrade(page));
        page.on_progress(move |ev| match ev {
            Progress::Start { elevated } => {
                me.root.set_visible(true);
                me.spinner.start();
                me.title.set_text(&format!("{label} en cours…"));
                me.detail.set_text(if *elevated { "En attente de votre mot de passe administrateur (fenêtre d'authentification de KDE)…" } else { "Démarrage…" });
                me.stop.set_visible(!*elevated);
                me.started.set(Some(std::time::Instant::now()));
                *me.page.borrow_mut() = Some(weak.clone());
            }
            Progress::Line(l) => {
                if me.started.get().is_some() {
                    me.detail.set_text(l);
                }
            }
            Progress::End => {
                me.spinner.stop();
                me.root.set_visible(false);
                me.started.set(None);
            }
        });
    }
}

/// Désactive les boutons d'une carte pendant une analyse (évite les doubles lancements).
/// Une bibliothèque (nom, version) trouvée dans un programme installé.
struct LibGroup {
    name: String,
    ver: String,
    n: usize,
    grave: usize,
    fix: String,
    kind: String,
    /// Programme auquel elle appartient (d'après son emplacement).
    program: String,
}

/// Bibliothèques trouvées par Trivy, regroupées par (programme, nom, version). Les plus graves d'abord.
fn lib_groups(rows: &[Vec<String>]) -> Vec<LibGroup> {
    let mut by: BTreeMap<(String, String, String), (HashSet<String>, usize, Vec<String>, String)> = BTreeMap::new();
    for r in rows {
        if r.len() < 7 || r[0] != "Vulnérabilité" {
            continue;
        }
        let program = crate::depfix::program_of(&crate::depfix::row_path(r), &r[2]);
        let e = by.entry((program, r[2].clone(), r[3].clone())).or_insert((HashSet::new(), 0, Vec::new(), r[6].clone()));
        if e.0.insert(r[5].clone()) && matches!(r[1].as_str(), "critical" | "high") {
            e.1 += 1;
        }
        let per: Vec<String> = r[4].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let refs: Vec<&str> = per.iter().map(String::as_str).collect();
        if let Some(f) = crate::depfix::pick_fixed(&r[3], &refs) {
            e.2.push(f);
        }
    }
    let mut v: Vec<_> = by
        .into_iter()
        .map(|((program, n, ver), (ids, grave, fixes, kind))| {
            // pour tout corriger il faut la plus élevée des versions correctives minimales de chaque faille
            let fix = fixes.into_iter().max_by(|a, b| crate::depfix::cmp(a, b)).unwrap_or_default();
            LibGroup { name: n, ver, n: ids.len(), grave, fix, kind, program }
        })
        .collect();
    v.sort_by(|a, b| b.grave.cmp(&a.grave).then(b.n.cmp(&a.n)));
    v
}

fn set_busy(card: &Card, busy: bool) {
    let mut c = card.btns.first_child();
    while let Some(w) = c {
        w.set_sensitive(!busy);
        c = w.next_sibling();
    }
}

/// Une alerte de rkhunter, expliquée en français, avec ce que l'application peut réellement faire.
struct AlertView {
    row: gtk::Box,
    /// « à examiner » ? Un fichier identique à son paquet officiel n'en est jamais un.
    serious: bool,
    advice: Advice,
    title: String,
    intro: String,
}

fn alert_row(text: &str, note: &str, verdicts: &HashMap<String, crate::verify::Verdict>) -> AlertView {
    use crate::verify::Verdict;
    let mut a = Advice { source: "Vérification avec la base des paquets (pacman) et rkhunter".into(), ..Default::default() };
    let safe = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || "._+-/".contains(c));
    if let Some(path) = crate::verify::path_in(text) {
        let (title, sub, tag, serious, intro) = match verdicts.get(&path) {
            Some(Verdict::Official { pkg, version }) => {
                a.direct.push(Direct::IgnoreAlert);
                a.recommendation.push(format!("Fichier officiel du paquet {pkg} {version}, identique à l'original : pacman a comparé son empreinte à celle enregistrée à l'installation."));
                a.recommendation.push(format!("Pourquoi rkhunter le signale : {note}"));
                a.recommendation.push("Conclusion : faux positif, aucune correction nécessaire.".into());
                (format!("Programme système : {path}"), format!("Fichier officiel du paquet {pkg} {version}, identique à l'original (vérifié avec pacman). {note}"), ("Vérifié, sans danger", "sev-ok"), false, "Faux positif vérifié.".to_string())
            }
            Some(Verdict::Marker { what }) => {
                a.direct.push(Direct::IgnoreAlert);
                a.recommendation.push(format!("{what}. Le contenu du fichier a été vérifié : il porte bien la mention de son créateur."));
                a.recommendation.push("Aucun paquet ne le possède car c'est systemd lui-même qui l'écrit à chaque mise à jour. Conclusion : normal.".into());
                (format!("Fichier système : {path}"), format!("{what}. Créé par le système lors des mises à jour : normal."), ("Vérifié, sans danger", "sev-ok"), false, "Faux positif vérifié.".to_string())
            }
            Some(Verdict::Runtime { program }) => {
                a.direct.push(Direct::IgnoreAlert);
                a.recommendation.push(format!("Fichier temporaire de {program}, qui tourne actuellement sur cette machine (propriétaire et processus vérifiés)."));
                a.recommendation.push("Conclusion : normal tant que ce programme est en cours d'exécution.".into());
                (format!("Fichier temporaire : {path}"), format!("Mémoire partagée de {program} : normal."), ("Vérifié, sans danger", "sev-ok"), false, "Faux positif vérifié.".to_string())
            }
            Some(Verdict::Modified { pkg }) => {
                a.no_direct = Some("Un fichier système modifié ne se corrige pas automatiquement sans risque : réinstaller le paquet écraserait aussi une modification que vous auriez faite volontairement.".into());
                a.recommendation.push(format!("Ce fichier est DIFFÉRENT de celui du paquet {pkg}. Si vous ne l'avez pas modifié vous-même, considérez la machine comme potentiellement compromise."));
                if safe(&pkg) {
                    a.direct.push(Direct::CopyCommand { command: format!("sudo pacman -S {pkg}") });
                    a.recommendation.push("Pour restaurer l'original : sauvegardez d'abord le fichier, puis lancez la commande copiée (réinstalle le paquet).".into());
                }
                (format!("Programme système : {path}"), format!("DIFFÉRENT du paquet {pkg} : modifié."), ("Modifié !", "sev-critical"), true, "Fichier modifié : à examiner en priorité.".to_string())
            }
            _ => {
                a.no_direct = Some("L'application ne peut pas décider à votre place si ce fichier est légitime.".into());
                a.recommendation.push("Aucun paquet officiel ne fournit ce fichier et il n'est pas d'un type connu comme normal : c'est inhabituel.".into());
                if safe(&path) {
                    a.direct.push(Direct::CopyCommand { command: format!("ls -la {path}") });
                    a.recommendation.push("Regardez son propriétaire et sa date avec la commande copiée : un fichier récent créé par un programme que vous connaissez est normal.".into());
                }
                a.direct.push(Direct::IgnoreAlert);
                (format!("Fichier : {path}"), "Aucun paquet officiel ne fournit ce fichier : inhabituel, examinez-le.".to_string(), ("Inconnu", "sev-high"), true, "Fichier inconnu des paquets.".to_string())
            }
        };
        return AlertView { row: row(&title, &sub, Some(tag)), serious, advice: a, title, intro };
    }
    let low = text.to_lowercase();
    let (title, tag, serious): (&str, (&str, &str), bool) = if low.contains("prerequisites") {
        a.direct.push(Direct::IgnoreAlert);
        a.recommendation.push(format!("{note}"));
        ("Outils requis par rkhunter", ("Sans gravité", "sev-low"), false)
    } else if low.contains("ssh root access") {
        a.direct.push(if crate::ui::dialogs::ssh_fix_applied() { Direct::SshRevert } else { Direct::SshFix });
        a.direct.push(Direct::IgnoreAlert);
        a.recommendation.push("rkhunter signale que la connexion « root » par SSH n'est pas interdite explicitement (PermitRootLogin absent de la configuration).".into());
        a.recommendation.push("Par défaut OpenSSH n'accepte root que par clé (« prohibit-password »). Si vous n'avez pas besoin de root en SSH, la recommandation est « PermitRootLogin no ».".into());
        a.recommendation.push("La correction crée un fichier séparé, vérifié avant et après, avec instantané de secours : elle se supprime d'un clic.".into());
        ("Connexion SSH en administrateur (root) non interdite explicitement", ("Réglage conseillé", "sev-low"), false)
    } else if low.contains("ssh protocol v1") {
        a.direct.push(Direct::IgnoreAlert);
        a.recommendation.push("Faux positif fréquent : OpenSSH moderne ne gère plus du tout le protocole 1.".into());
        ("Ancien protocole SSH 1", ("Faux positif connu", "sev-ok"), false)
    } else {
        a.no_direct = Some("Cette alerte ne désigne pas un fichier précis : l'application ne peut pas la vérifier automatiquement.".into());
        a.recommendation.push(note.to_string());
        a.direct.push(Direct::IgnoreAlert);
        (if low.contains("hidden files") { "Fichiers cachés hors des emplacements habituels" } else if low.contains("/dev for suspicious") { "Fichiers inhabituels dans /dev" } else { text }, ("À vérifier", "sev-medium"), true)
    };
    let intro = if serious { "À examiner." } else { "Sans gravité." }.to_string();
    AlertView { row: row(title, note, Some(tag)), serious, advice: a, title: title.to_string(), intro }
}

// ─────────────────────────────── nettoyage ───────────────────────────────

struct CleanRow {
    item: crate::clean::Item,
    check: gtk::CheckButton,
    size: gtk::Label,
    bytes: std::cell::Cell<u64>,
}

fn clean(ctx: &Rc<Ctx>) -> gtk::Widget {
    use crate::clean::{self, Group};
    let s = shell("mod-clean");
    let total = Rc::new(Card::new("tile-clean", "user-trash-symbolic", "ESPACE À LIBÉRER"));
    s.cards.append(&total.root);
    s.headline.set_text(&crate::i18n::tr("Libérez de l'espace et protégez votre vie privée"));
    s.sub.set_text(&crate::i18n::tr("Analysez pour voir ce qui peut être nettoyé, cochez ce que vous voulez, puis appuyez sur Nettoyer. Rien n'est supprimé sans votre confirmation."));
    total.set("—", "Appuyez sur Analyser pour calculer l'espace récupérable.");
    let Some(home) = crate::util::home_dir() else {
        s.list.append(&plain_label("Dossier personnel introuvable : le nettoyage est indisponible."));
        return s.root.upcast();
    };
    let rows: Rc<std::cell::RefCell<Vec<Rc<CleanRow>>>> = Rc::new(std::cell::RefCell::new(Vec::new()));
    let update_total: Rc<dyn Fn()> = {
        let (rows, total) = (rows.clone(), total.clone());
        Rc::new(move || {
            let (mut b, mut n) = (0u64, 0usize);
            for r in rows.borrow().iter().filter(|r| r.check.is_active() && r.item.admin_script.is_none()) {
                b += r.bytes.get();
                n += 1;
            }
            total.set(&clean::human(b), &if n == 0 { crate::i18n::tr("Cochez ce que vous voulez nettoyer.") } else { format!("{} {n}", crate::i18n::tr("Éléments sélectionnés :")) });
        })
    };
    let analyse: Rc<dyn Fn()> = {
        let (rows, list, home, ut, total) = (rows.clone(), s.list.clone(), home.clone(), update_total.clone(), total.clone());
        Rc::new(move || {
            clear(&list);
            rows.borrow_mut().clear();
            let items = clean::items(&home);
            let mut last: Option<Group> = None;
            for it in items {
                if last != Some(it.group) {
                    list.append(&section(match it.group { Group::Systeme => "SYSTÈME ET APPLICATIONS", Group::Navigateur => "NAVIGATEURS", Group::Administrateur => "ADMINISTRATEUR (mot de passe demandé)" }));
                    last = Some(it.group);
                }
                let line = row(&it.title, it.desc, None);
                let check = gtk::CheckButton::new();
                check.set_valign(gtk::Align::Center);
                let size = plain_label(if it.admin_script.is_some() { "—" } else { "Analyse…" });
                size.add_css_class("row-title");
                size.set_wrap(false);
                size.set_xalign(1.0);
                size.set_valign(gtk::Align::Center);
                let ut2 = ut.clone();
                check.connect_toggled(move |_| ut2());
                line.prepend(&check);
                line.append(&size);
                list.append(&line);
                rows.borrow_mut().push(Rc::new(CleanRow { item: it, check, size, bytes: std::cell::Cell::new(0) }));
            }
            total.set("…", "Analyse en cours…");
            let (tx, rx) = async_channel::unbounded::<(usize, u64, u64)>();
            let (h2, items2): (std::path::PathBuf, Vec<clean::Item>) = (home.clone(), rows.borrow().iter().map(|r| r.item.clone()).collect());
            std::thread::spawn(move || {
                for (i, it) in items2.iter().enumerate() {
                    let (b, f) = if it.admin_script.is_some() { (0, 0) } else { clean::size_of(&h2, it) };
                    if tx.send_blocking((i, b, f)).is_err() {
                        return;
                    }
                }
            });
            let (rows2, ut3) = (rows.clone(), ut.clone());
            glib::spawn_future_local(async move {
                while let Ok((i, b, f)) = rx.recv().await {
                    let r = rows2.borrow().get(i).cloned();
                    if let Some(r) = r {
                        r.bytes.set(b);
                        if r.item.admin_script.is_none() {
                            r.size.set_text(&if b == 0 { crate::i18n::tr("Rien à nettoyer") } else { format!("{} ({f} {})", clean::human(b), crate::i18n::tr("fichiers")) });
                            // seuls les CACHES (qui se recréent) sont cochés d'office ; corbeille, cookies, historique et tâches administrateur : à cocher volontairement
                            let regenerable = matches!(r.item.id.as_str(), "thumbs" | "pkgcache" | "gpucache") || r.item.id.ends_with("-cache");
                            r.check.set_active(b > 0 && regenerable);
                            r.check.set_sensitive(b > 0);
                        }
                    }
                }
                ut3();
            });
        })
    };
    let clean_btn_action: Rc<dyn Fn()> = {
        let (rows, ctx, home, an) = (rows.clone(), ctx.clone(), home.clone(), analyse.clone());
        Rc::new(move || {
            let (rows, ctx, home, an) = (rows.clone(), ctx.clone(), home.clone(), an.clone());
            glib::spawn_future_local(async move {
                let parent = ctx.window();
                let selected: Vec<Rc<CleanRow>> = rows.borrow().iter().filter(|r| r.check.is_active() && (r.bytes.get() > 0 || r.item.admin_script.is_some())).cloned().collect();
                let info = |h: &str, b: &str| {
                    let d = adw::AlertDialog::new(Some(&crate::i18n::tr(h)), Some(&crate::i18n::tr(b)));
                    d.add_response("close", &crate::i18n::tr("Fermer"));
                    d
                };
                if selected.is_empty() {
                    let _ = info("Rien à nettoyer", "Analysez d'abord, puis cochez ce que vous voulez nettoyer.").choose_future(parent.as_ref()).await;
                    return;
                }
                // les navigateurs doivent être fermés (sinon leurs bases de données sont verrouillées ou corrompues)
                let mut open: Vec<String> = selected.iter().filter(|r| r.item.browser_proc.is_some_and(clean::process_running)).map(|r| r.item.title.split(" : ").next().unwrap_or("").to_string()).collect();
                open.sort();
                open.dedup();
                if !open.is_empty() {
                    let _ = info("Fermez d'abord le navigateur", &format!("{} {}\n\n{}", crate::i18n::tr("Ces navigateurs sont ouverts :"), open.join(", "), crate::i18n::tr("Fermez-les complètement, puis recommencez : leurs données ne peuvent pas être nettoyées pendant qu'ils tournent."))).choose_future(parent.as_ref()).await;
                    return;
                }
                let bytes: u64 = selected.iter().map(|r| r.bytes.get()).sum();
                let list = selected.iter().map(|r| if r.item.admin_script.is_some() { format!("• {}", r.item.title) } else { format!("• {} — {}", r.item.title, clean::human(r.bytes.get())) }).collect::<Vec<_>>().join("\n");
                let mut body = format!("{}\n{list}\n\n{} {}\n\n{}", crate::i18n::tr("Ce qui va être supprimé :"), crate::i18n::tr("Espace libéré :"), clean::human(bytes), crate::i18n::tr("Cette opération est définitive : les fichiers ne vont pas à la corbeille."));
                if selected.iter().any(|r| r.item.id.ends_with("-cookies")) {
                    body.push_str(&format!("\n\n{}", crate::i18n::tr("Les cookies supprimés vous déconnectent de la plupart des sites.")));
                }
                let d = adw::AlertDialog::new(Some(&crate::i18n::tr("Nettoyer maintenant ?")), Some(&body));
                d.add_response("cancel", &crate::i18n::tr("Annuler"));
                d.add_response("go", &crate::i18n::tr("Nettoyer"));
                d.set_response_appearance("go", adw::ResponseAppearance::Destructive);
                d.set_default_response(Some("cancel"));
                d.set_close_response("cancel");
                if d.choose_future(parent.as_ref()).await != "go" {
                    return;
                }
                // suppression directe (sans droits administrateur), en arrière-plan
                let direct: Vec<clean::Item> = selected.iter().filter(|r| r.item.admin_script.is_none()).map(|r| r.item.clone()).collect();
                let admin: Vec<&'static str> = selected.iter().filter_map(|r| r.item.admin_script).collect();
                let (tx, rx) = async_channel::bounded::<(u64, Vec<String>)>(1);
                let h2 = home.clone();
                std::thread::spawn(move || {
                    let (mut freed, mut errs) = (0u64, Vec::new());
                    for it in &direct {
                        let (f, e) = clean::delete(&h2, it);
                        freed += f;
                        errs.extend(e);
                    }
                    let _ = tx.send_blocking((freed, errs));
                });
                let (freed, errs) = rx.recv().await.unwrap_or_default();
                // tâches administrateur : un seul mot de passe pour les deux
                if !admin.is_empty() {
                    let script: &'static str = if admin.len() > 1 { clean::ADMIN_BOTH } else { admin[0] };
                    let (tx2, rx2) = async_channel::bounded::<()>(1);
                    super::dialogs::run_command(parent.clone(), "Nettoyage administrateur", super::dialogs::admin_script_plan(script), None, move |_dlg, _code, _| {
                        let _ = tx2.try_send(());
                    });
                    let _ = rx2.recv().await;
                }
                let mut msg = format!("{} {}", crate::i18n::tr("Espace libéré :"), clean::human(freed));
                if !errs.is_empty() {
                    msg.push_str(&format!("\n\n{} {}\n{}", errs.len(), crate::i18n::tr("élément(s) n'ont pas pu être supprimés (en cours d'utilisation ?) :"), errs.iter().take(5).cloned().collect::<Vec<_>>().join("\n")));
                }
                let _ = info("Nettoyage terminé", &msg).choose_future(parent.as_ref()).await;
                an();
            });
        })
    };
    let (a2, c2) = (analyse.clone(), clean_btn_action.clone());
    total.button("Analyser", move || a2());
    total.button("Nettoyer", move || c2());
    s.root.upcast()
}
