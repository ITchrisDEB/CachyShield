//! Surveillance en direct : ports, connexions, pare-feu, tentatives de connexion.
//! Les services qui écoutent volontairement sur 0.0.0.0 sont marqués « autorisés » et n'alertent pas.

use super::dashboard::StatCard;
use super::results::Results;
use super::{Ctx, plain_label};
use crate::live::{self, AUTH_SCRIPT, Expo, Snapshot, key_of};
use crate::runner::{self, Msg};
use crate::tools::Plan;
use crate::util::SH;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

#[derive(Clone, Copy, Default)]
pub struct Summary {
    pub to_check: usize,
    pub wanted: usize,
    pub public: usize,
}

pub struct LivePage {
    pub root: gtk::Box,
    ctx: Rc<Ctx>,
    listen: Rc<Results>,
    conns: Rc<Results>,
    auth: Rc<Results>,
    events: gtk::ListBox,
    stat_fw: StatCard,
    stat_listen: StatCard,
    stat_pub: StatCard,
    auto: gtk::CheckButton,
    only_pub: gtk::CheckButton,
    interval: gtk::SpinButton,
    days: gtk::SpinButton,
    auth_btn: gtk::Button,
    auth_info: gtk::Label,
    known_listen: RefCell<HashSet<(String, String)>>,
    known_remote: RefCell<HashSet<(String, String, String)>>,
    first: Cell<bool>,
    busy: Cell<bool>,
    ticks: Cell<u32>,
    on_update: RefCell<Option<Box<dyn Fn(Option<&str>, Summary)>>>,
}

fn status_sev(s: &str) -> (String, &'static str, u8) {
    match s {
        "À vérifier" => (s.into(), "sev-medium", 0),
        "Autorisé" => (s.into(), "sev-ok", 2),
        _ => (s.into(), "", 5),
    }
}

fn type_sev(s: &str) -> (String, &'static str, u8) {
    match s {
        "Internet" => (s.into(), "sev-low", 0),
        _ => (s.into(), "", 5),
    }
}

impl LivePage {
    pub fn new(ctx: Rc<Ctx>) -> Rc<LivePage> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
        root.set_margin_top(20);
        root.set_margin_bottom(16);
        root.set_margin_start(24);
        root.set_margin_end(24);
        let title = gtk::Label::new(Some(crate::i18n::tr("Surveillance en direct").as_str()));
        title.add_css_class("title-2");
        title.set_xalign(0.0);
        let desc = plain_label("Ports ouverts, connexions réseau et tentatives d'intrusion. Actualisation automatique, sans droits root. Les services que vous avez marqués comme autorisés ne déclenchent pas d'alerte.");
        desc.add_css_class("dim-label");
        root.append(&title);
        root.append(&desc);

        let stats = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        stats.set_homogeneous(true);
        let (stat_fw, stat_listen, stat_pub) = (StatCard::new("Pare-feu"), StatCard::new("Ports exposés au réseau"), StatCard::new("Connexions vers Internet"));
        for s in [&stat_fw, &stat_listen, &stat_pub] {
            stats.append(&s.root);
        }
        root.append(&stats);

        let ctl = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let auto = gtk::CheckButton::with_label(&crate::i18n::tr("Actualiser automatiquement"));
        auto.set_active(true);
        let interval = gtk::SpinButton::with_range(1.0, 60.0, 1.0);
        interval.set_value(4.0);
        let only_pub = gtk::CheckButton::with_label(&crate::i18n::tr("Connexions publiques seulement"));
        let refresh = gtk::Button::with_label(&crate::i18n::tr("Actualiser"));
        refresh.set_hexpand(true);
        refresh.set_halign(gtk::Align::End);
        for w in [auto.upcast_ref::<gtk::Widget>(), gtk::Label::new(Some(crate::i18n::tr("toutes les (sec.)").as_str())).upcast_ref(), interval.upcast_ref(), only_pub.upcast_ref(), refresh.upcast_ref()] {
            ctl.append(w);
        }
        root.append(&ctl);

        let listen = Results::new(&["Proto", "Adresse", "Port", "Processus", "Exposition", "Statut"], &[70, 190, 80, 200, 200, 110], Some((5, status_sev as _)));
        let conns = Results::new(&["Processus", "PID", "Local", "Distant", "Port", "Type"], &[160, 70, 200, 220, 80, 120], Some((5, type_sev as _)));
        let auth = Results::new(&["IP source", "Échecs", "Dernière tentative", "Source"], &[200, 80, 220, 160], None);
        let events = gtk::ListBox::new();
        events.set_selection_mode(gtk::SelectionMode::None);

        let listen_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let toggle = gtk::Button::with_label(&crate::i18n::tr("Autoriser / ne plus autoriser"));
        toggle.set_tooltip_text(Some("Sélectionnez un port écoutant sur toutes les interfaces. Il est identifié par son processus (ou son numéro de port s'il est inconnu)."));
        toggle.set_halign(gtk::Align::Start);
        listen_box.append(&listen.widget);
        listen_box.append(&toggle);

        let auth_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        let arow = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let days = gtk::SpinButton::with_range(1.0, 365.0, 1.0);
        days.set_value(30.0);
        let auth_btn = gtk::Button::with_label(&crate::i18n::tr("Analyser les tentatives de connexion (admin)"));
        auth_btn.add_css_class("suggested-action");
        arow.append(&gtk::Label::new(Some(crate::i18n::tr("Période (jours) :").as_str())));
        arow.append(&days);
        arow.append(&auth_btn);
        let auth_info = plain_label("Lit le journal SSH et lastb. Nécessite les droits administrateur.");
        auth_info.add_css_class("dim-label");
        auth_box.append(&arow);
        auth_box.append(&auth_info);
        auth_box.append(&auth.widget);

        let tabs = gtk::Notebook::new();
        tabs.append_page(&listen_box, Some(&gtk::Label::new(Some(crate::i18n::tr("Ports en écoute").as_str()))));
        tabs.append_page(&conns.widget, Some(&gtk::Label::new(Some(crate::i18n::tr("Connexions actives").as_str()))));
        tabs.append_page(&auth_box, Some(&gtk::Label::new(Some(crate::i18n::tr("Tentatives de connexion").as_str()))));
        tabs.append_page(&gtk::ScrolledWindow::builder().child(&events).build(), Some(&gtk::Label::new(Some(crate::i18n::tr("Événements").as_str()))));
        tabs.set_vexpand(true);
        root.append(&tabs);

        let page = Rc::new(LivePage {
            root,
            ctx,
            listen,
            conns,
            auth,
            events,
            stat_fw,
            stat_listen,
            stat_pub,
            auto,
            only_pub,
            interval,
            days,
            auth_btn,
            auth_info,
            known_listen: RefCell::new(HashSet::new()),
            known_remote: RefCell::new(HashSet::new()),
            first: Cell::new(true),
            busy: Cell::new(false),
            ticks: Cell::new(0),
            on_update: RefCell::new(None),
        });

        let p = page.clone();
        refresh.connect_clicked(move |_| p.refresh());
        let p = page.clone();
        toggle.connect_clicked(move |_| p.toggle_selected());
        let p = page.clone();
        page.auth_btn.connect_clicked(move |_| p.run_auth());
        let p = page.clone();
        glib::timeout_add_seconds_local(1, move || {
            let t = p.ticks.get() + 1;
            if t >= p.interval.value() as u32 && p.auto.is_active() {
                p.ticks.set(0);
                p.refresh();
            } else {
                p.ticks.set(t);
            }
            glib::ControlFlow::Continue
        });
        page.refresh();
        page
    }

    pub fn on_update(&self, f: impl Fn(Option<&str>, Summary) + 'static) {
        *self.on_update.borrow_mut() = Some(Box::new(f));
    }

    fn log(&self, msg: &str, warn: bool) {
        let t = glib::DateTime::now_local().ok().and_then(|d| d.format("%H:%M:%S").ok()).map(|s| s.to_string()).unwrap_or_default();
        let l = plain_label(&format!("{t}  {msg}"));
        l.set_margin_start(8);
        l.set_margin_top(3);
        l.set_margin_bottom(3);
        if warn {
            l.add_css_class("warning");
        }
        self.events.prepend(&l);
        while let Some(r) = self.events.row_at_index(300) {
            self.events.remove(&r);
        }
    }

    fn refresh(self: &Rc<Self>) {
        if self.busy.replace(true) {
            return;
        }
        let (tx, rx) = async_channel::bounded::<Snapshot>(1);
        std::thread::spawn(move || {
            let _ = tx.send_blocking(live::snapshot());
        });
        let me = self.clone();
        glib::spawn_future_local(async move {
            if let Ok(snap) = rx.recv().await {
                me.apply(snap);
            }
            me.busy.set(false);
        });
    }

    fn allowed(&self) -> HashSet<String> {
        self.ctx.state.borrow().allowed.clone().unwrap_or_default().into_iter().collect()
    }

    fn apply(&self, snap: Snapshot) {
        // Premier lancement : rien n'est validé d'office (un service déjà actif pourrait être une porte dérobée) ; vous confirmez ce que vous reconnaissez.
        if self.ctx.state.borrow().allowed.is_none() && !snap.listeners.is_empty() {
            self.ctx.state.borrow_mut().allowed = Some(Vec::new());
            self.ctx.save();
            self.log("Premier lancement : confirmez les services que vous reconnaissez avec « Autoriser ».", false);
        }
        let allowed = self.allowed();

        let (mut to_check, mut wanted) = (0usize, 0usize);
        let mut current: HashSet<(String, String)> = HashSet::new();
        let mut rows = Vec::new();
        for l in &snap.listeners {
            let (expo, status) = match &l.expo {
                Expo::All => ("Toutes les interfaces".to_string(), if allowed.contains(&key_of(&l.proc, &l.port)) { "Autorisé" } else { "À vérifier" }),
                Expo::Local => ("Local seulement".into(), "—"),
                Expo::Net(h) => (format!("Réseau ({h})"), "—"),
            };
            if l.proto == "tcp" && status == "Autorisé" {
                wanted += 1;
            }
            if l.proto == "tcp" && status == "À vérifier" {
                to_check += 1;
                current.insert((l.port.clone(), l.proc.clone()));
            }
            rows.push(vec![l.proto.clone(), l.host.clone(), l.port.clone(), l.proc.clone(), expo, status.to_string()]);
        }
        self.listen.set_rows(&rows);
        if !self.first.get() {
            for (port, proc) in current.difference(&self.known_listen.borrow()) {
                self.log(&format!("Nouveau port exposé non autorisé : {port} ({proc})"), true);
                self.ctx.notify("nouveau-port", "Nouveau port ouvert", &format!("Le port {port} ({proc}) écoute sur toutes les interfaces et n'est pas marqué comme autorisé."));
            }
        }
        *self.known_listen.borrow_mut() = current;

        let only_pub = self.only_pub.is_active();
        let mut public = 0;
        let mut crows = Vec::new();
        for c in &snap.conns {
            public += c.public as usize;
            let key = (c.proc.clone(), c.remote.clone(), c.port.clone());
            if c.public && !self.first.get() && !self.known_remote.borrow().contains(&key) {
                self.log(&format!("Nouvelle connexion : {} → {}:{}", c.proc, c.remote, c.port), false);
            }
            self.known_remote.borrow_mut().insert(key);
            if c.public || !only_pub {
                crows.push(vec![c.proc.clone(), c.pid.clone(), c.local.clone(), c.remote.clone(), c.port.clone(), if c.public { "Internet" } else { "Réseau local" }.into()]);
            }
        }
        self.conns.set_rows(&crows);

        match &snap.firewall {
            Some(f) => self.stat_fw.set(&format!("Actif ({f})"), Some("stat-ok")),
            None => self.stat_fw.set("Inactif", Some("stat-warn")),
        }
        let mut t = format!("{to_check} à vérifier");
        if wanted > 0 {
            t += &format!(" · {wanted} autorisés");
        }
        self.stat_listen.set(&t, Some(if to_check > 0 { "stat-warn" } else { "stat-ok" }));
        self.stat_pub.set(&public.to_string(), None);
        if self.first.replace(false) {
            self.log("Surveillance démarrée", false);
        }
        if let Some(cb) = self.on_update.borrow().as_ref() {
            cb(snap.firewall.as_deref(), Summary { to_check, wanted, public });
        }
    }

    fn toggle_selected(&self) {
        let Some(row) = self.listen.selected() else { return };
        if row.get(4).map(String::as_str) != Some("Toutes les interfaces") {
            return;
        }
        let key = key_of(&row[3], &row[2]);
        {
            let mut st = self.ctx.state.borrow_mut();
            let list = st.allowed.get_or_insert_with(Vec::new);
            if let Some(i) = list.iter().position(|k| *k == key) {
                list.remove(i);
            } else {
                list.push(key.clone());
                list.sort();
            }
        }
        self.ctx.save();
        self.log(&format!("« {key} » : statut « autorisé » modifié"), false);
        // actualisation immédiate avec le dernier état connu
        let snap = live::snapshot();
        self.apply(snap);
    }

    fn run_auth(self: &Rc<Self>) {
        let days = self.days.value().clamp(1.0, 365.0) as u32;
        let plan = Plan { argv: vec![SH.into(), "-c".into(), AUTH_SCRIPT.into(), "sh".into(), days.to_string()], elevated: true, out_flag: None, out_pos: 0 };
        let Ok(run) = runner::spawn(&plan, &[], None) else {
            self.auth_info.set_text(&crate::i18n::tr("Impossible de lancer l'analyse."));
            return;
        };
        self.auth_btn.set_sensitive(false);
        self.auth_info.set_text(&crate::i18n::tr("Analyse en cours…"));
        let me = self.clone();
        glib::spawn_future_local(async move {
            while let Ok(msg) = run.rx.recv().await {
                if let Msg::Done { code, text, .. } = msg {
                    me.auth_btn.set_sensitive(true);
                    if code != 0 && text.trim().is_empty() {
                        me.auth_info.set_text(&crate::i18n::tr("Droits administrateur refusés ou analyse annulée."));
                    } else {
                        let rep = live::parse_auth(&text);
                        let mut rows: Vec<(String, (u32, String, &str))> = rep.fails.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                        rows.sort_by(|a, b| b.1.0.cmp(&a.1.0));
                        let table: Vec<Vec<String>> = rows.iter().map(|(ip, v)| vec![ip.clone(), v.0.to_string(), v.1.clone(), v.2.to_string()]).collect();
                        me.auth.set_rows(&table);
                        let total: u32 = rep.fails.values().map(|v| v.0).sum();
                        me.auth_info.set_text(&format!("{total} tentative(s) échouée(s) depuis {} IP — {} connexion(s) SSH réussie(s) sur {days} jour(s).", rep.fails.len(), rep.accepted));
                        me.log(&format!("Analyse des connexions : {total} échec(s), {} IP", rep.fails.len()), total > 0);
                        if total > 0 {
                            me.ctx.notify("tentatives-ssh", "Tentatives de connexion détectées", &format!("{total} tentative(s) échouée(s) depuis {} IP — {} connexion(s) SSH réussie(s) sur {days} jour(s).", rep.fails.len(), rep.accepted));
                        }
                    }
                    break;
                }
            }
        });
    }
}
