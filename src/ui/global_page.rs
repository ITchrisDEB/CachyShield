//! Failles de tous les systèmes et éditeurs : catalogue CISA KEV et base NVD (NIST).

use super::results::{Results, tool_sev};
use super::{Ctx, open_https, plain_label, when};
use crate::global::{self, Kev, Pkg};
use crate::runner::{self, Msg};
use crate::util::{self, Stamp};
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

const MAX_KEV_CACHE: u64 = 16 * 1024 * 1024;

pub struct GlobalPage {
    pub root: gtk::Box,
    ctx: Rc<Ctx>,
    kev: RefCell<Option<Kev>>,
    inv: RefCell<Vec<Pkg>>,
    /// Date de construction (secondes Unix) de chaque paquet installé : sert à estimer si une faille est déjà corrigée.
    builds: RefCell<std::collections::HashMap<String, i64>>,
    /// Tracker de sécurité d'Arch indexé par CVE : donne, pour chaque faille et chaque paquet, la version qui corrige.
    idx: RefCell<std::rc::Rc<crate::tracker::CveIndex>>,
    /// Correspondances catalogue CISA / logiciels installés : le calcul est lourd (millions de comparaisons), il n'est refait que si les données changent.
    cache: RefCell<Option<Vec<global::Matched>>>,
    kev_table: Rc<Results>,
    nvd_table: Rc<Results>,
    kev_info: gtk::Label,
    nvd_info: gtk::Label,
    only_mine: gtk::CheckButton,
    update_btn: gtk::Button,
    query: gtk::Entry,
    search_btn: gtk::Button,
    recent_btn: gtk::Button,
    on_kev: RefCell<Option<Box<dyn Fn(Option<(usize, usize)>)>>>,
}

fn mine_sev(s: &str) -> (String, &'static str, u8) {
    if s.is_empty() { (String::new(), "", 9) } else { (s.into(), "sev-high", 0) }
}

/// Télécharge une adresse autorisée et renvoie le contenu (erreurs traduites en français).
pub async fn fetch(url: &str) -> Result<String, String> {
    let plan = global::fetch_plan(url)?;
    let run = runner::spawn(&plan, &[], None)?;
    let mut errs = String::new();
    while let Ok(msg) = run.rx.recv().await {
        match msg {
            Msg::Line(l) => {
                errs.push_str(&l);
                errs.push('\n');
            }
            Msg::Done { code: 0, blob, .. } => return blob.filter(|b| !b.trim().is_empty()).ok_or_else(|| "réponse vide".to_string()),
            Msg::Done { .. } => {
                let e = errs.trim();
                return Err(if e.contains("403") || e.contains("429") {
                    "Le serveur limite le débit (NVD : 5 requêtes par 30 s sans clé). Réessayez dans une minute.".into()
                } else if e.contains("resolve") || e.contains("connect") {
                    "Pas de connexion à Internet ou serveur injoignable.".into()
                } else {
                    format!("Téléchargement impossible : {e}")
                });
            }
        }
    }
    Err("téléchargement interrompu".into())
}

impl GlobalPage {
    pub fn new(ctx: Rc<Ctx>) -> Rc<GlobalPage> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 10);
        root.set_margin_top(20);
        root.set_margin_bottom(16);
        root.set_margin_start(24);
        root.set_margin_end(24);
        let title = gtk::Label::new(Some(crate::i18n::tr("Failles mondiales — tous systèmes et éditeurs").as_str()));
        title.add_css_class("title-2");
        title.set_xalign(0.0);
        let desc = plain_label("Windows, macOS, Linux, routeurs, navigateurs, serveurs… Deux sources officielles : le catalogue CISA KEV (failles activement exploitées dans la nature) et la base NVD du NIST (catalogue mondial de référence). La correspondance avec vos logiciels se fait par nom, sans comparer la version : à vérifier.");
        desc.add_css_class("dim-label");
        root.append(&title);
        root.append(&desc);

        let kev_table = Results::new(&["CVE", "Éditeur", "Produit", "Faille", "Ajoutée le", "Échéance", "Rançongiciel", "Sur votre machine"], &[140, 150, 180, 360, 100, 100, 100, 250], Some((7, mine_sev as _)));
        let nvd_table = Results::new(&["CVE", "Publiée", "Score", "Gravité", "Description"], &[140, 100, 70, 100, 700], Some((3, tool_sev as _)));

        // onglet CISA KEV
        let kev_info = plain_label("Catalogue non téléchargé.");
        let update_btn = gtk::Button::with_label(&crate::i18n::tr("Mettre à jour le catalogue CISA KEV"));
        update_btn.add_css_class("suggested-action");
        let only_mine = gtk::CheckButton::with_label(&crate::i18n::tr("Seulement celles qui concernent possiblement ma machine"));
        let top = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        kev_info.set_hexpand(true);
        top.append(&kev_info);
        top.append(&update_btn);
        let kev_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        kev_box.append(&top);
        kev_box.append(&only_mine);
        kev_box.append(&kev_table.widget);

        // onglet NVD
        let query = gtk::Entry::new();
        query.set_placeholder_text(Some("CVE-2021-44228, ou un mot-clé : chrome, log4j, openssl…"));
        query.set_hexpand(true);
        let search_btn = gtk::Button::with_label(&crate::i18n::tr("Rechercher dans NVD"));
        search_btn.add_css_class("suggested-action");
        let recent_btn = gtk::Button::with_label(&crate::i18n::tr("Critiques des 7 derniers jours"));
        let qrow = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        qrow.append(&query);
        qrow.append(&search_btn);
        qrow.append(&recent_btn);
        let nvd_info = plain_label("La base NVD contient plus de 400 000 CVE. Recherche à la demande (limite : 5 requêtes / 30 s sans clé API).");
        nvd_info.add_css_class("dim-label");
        let nvd_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
        nvd_box.append(&qrow);
        nvd_box.append(&nvd_info);
        nvd_box.append(&nvd_table.widget);

        let tabs = gtk::Notebook::new();
        tabs.append_page(&kev_box, Some(&gtk::Label::new(Some(crate::i18n::tr("Exploitées activement (CISA KEV)").as_str()))));
        tabs.append_page(&nvd_box, Some(&gtk::Label::new(Some(crate::i18n::tr("Recherche dans NVD").as_str()))));
        tabs.set_vexpand(true);
        root.append(&tabs);

        let page = Rc::new(GlobalPage { root, ctx, kev: RefCell::new(None), inv: RefCell::new(vec![]), builds: RefCell::new(Default::default()), idx: RefCell::new(Default::default()), cache: RefCell::new(None), kev_table, nvd_table, kev_info, nvd_info, only_mine, update_btn, query, search_btn, recent_btn, on_kev: RefCell::new(None) });

        // catalogue en cache
        if let Some(k) = util::load_private("kev.json", MAX_KEV_CACHE).and_then(|t| global::parse_kev(&t).ok()) {
            *page.kev.borrow_mut() = Some(k);
        }
        let p = page.clone();
        page.update_btn.connect_clicked(move |_| p.update_kev());
        let p = page.clone();
        page.only_mine.connect_toggled(move |_| p.refresh_kev());
        let p = page.clone();
        page.search_btn.connect_clicked(move |_| p.search());
        let p = page.clone();
        page.query.connect_activate(move |_| p.search());
        let p = page.clone();
        page.recent_btn.connect_clicked(move |_| {
            let url = global::nvd_recent_url(util::now_unix(), 7);
            p.run_nvd(Ok(url), "critiques des 7 derniers jours");
        });
        for t in [&page.kev_table, &page.nvd_table] {
            let t2 = t.clone();
            t.view.connect_activate(move |_, pos| {
                if let Some(cve) = t2.row_at(pos).and_then(|r| r.first().cloned()).filter(|c| global::is_cve(c)) {
                    open_https(&format!("https://nvd.nist.gov/vuln/detail/{cve}"));
                }
            });
        }

        // inventaire de la machine (en arrière-plan)
        let (tx, rx) = async_channel::bounded::<(Vec<Pkg>, std::collections::HashMap<String, i64>, Vec<crate::tracker::Avg>)>(1);
        std::thread::spawn(move || {
            let avgs = util::load_private("avg.json", 16 << 20).map(|j| crate::tracker::parse(&j)).unwrap_or_default();
            let _ = tx.send_blocking((global::inventory(), global::build_dates(), avgs));
        });
        let p = page.clone();
        glib::spawn_future_local(async move {
            if let Ok((inv, builds, avgs)) = rx.recv().await {
                *p.inv.borrow_mut() = inv;
                *p.builds.borrow_mut() = builds;
                *p.idx.borrow_mut() = std::rc::Rc::new(crate::tracker::CveIndex::new(avgs));
                *p.cache.borrow_mut() = None;
                p.refresh_kev();
            }
        });
        page.refresh_kev();
        page
    }

    pub fn on_kev(&self, f: impl Fn(Option<(usize, usize)>) + 'static) {
        *self.on_kev.borrow_mut() = Some(Box::new(f));
        self.notify();
    }

    fn notify(&self) {
        let n = self.kev.borrow().as_ref().map(|k| {
            let m = self.matched(k);
            let soft: std::collections::HashSet<&str> = m.iter().map(|x| x.pkg.name.as_str()).collect();
            (m.len(), soft.len())
        });
        if let Some(cb) = self.on_kev.borrow().as_ref() {
            cb(n);
        }
    }

    pub fn refresh_kev(&self) {
        let kev = self.kev.borrow();
        let Some(k) = kev.as_ref() else { return };
        let m = self.matched(k);
        let map: HashMap<&str, &global::Matched> = m.iter().map(|x| (x.kev.cve.as_str(), x)).collect();
        let only = self.only_mine.is_active();
        let mut rows: Vec<Vec<String>> = k
            .vulnerabilities
            .iter()
            .filter(|v| !only || map.contains_key(v.cve.as_str()))
            .map(|v| {
                vec![v.cve.clone(), v.vendor.clone(), v.product.clone(), v.name.clone(), v.added.clone(), v.due.clone(), if v.ransomware == "Known" { "Oui".into() } else { "—".into() }, map.get(v.cve.as_str()).map(|x| format!("Possible : {} {}", x.pkg.name, x.pkg.version)).unwrap_or_default()]
            })
            .collect();
        rows.sort_by(|a, b| b[4].cmp(&a[4]));
        self.kev_table.set_rows(&rows);
        let stamp = self.ctx.state.borrow().db.get("kev").map(|s| when(s.time)).unwrap_or_default();
        self.kev_info.set_text(&format!("CISA KEV : {} failles activement exploitées — catalogue {} (publié le {}) — {} concernent possiblement vos logiciels. {stamp}", k.vulnerabilities.len(), k.version, k.released.chars().take(10).collect::<String>(), m.len()));
        drop(kev);
        self.notify();
    }

    pub fn update_kev(self: &Rc<Self>) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            me.update_kev_async().await;
        });
    }

    /// Télécharge le catalogue CISA et le valide ; renvoie true si le catalogue a été mis à jour.
    pub async fn update_kev_async(self: &Rc<Self>) -> bool {
        self.update_btn.set_sensitive(false);
        self.kev_info.set_text(&crate::i18n::tr("Téléchargement du catalogue CISA KEV…"));
        let res = match fetch(global::KEV_URL).await {
            Ok(text) => global::parse_kev(&text).map(|k| (k, text)),
            Err(e) => Err(e),
        };
        let ok = res.is_ok();
        match res {
            Ok((k, text)) => {
                if let Err(e) = util::save_private("kev.json", text.as_bytes()) {
                    eprintln!("cache KEV impossible : {e}");
                }
                *self.kev.borrow_mut() = Some(k);
                *self.cache.borrow_mut() = None;
            }
            // un téléchargement invalide ne remplace JAMAIS le catalogue précédent
            Err(e) => self.kev_info.set_text(&format!("Mise à jour refusée : {e}. Le catalogue précédent est conservé.")),
        }
        self.ctx.state.borrow_mut().db.insert("kev".into(), Stamp { time: util::now_unix(), ok });
        self.ctx.save();
        if ok {
            self.refresh_kev();
            self.announce_new_matches();
        }
        self.update_btn.set_sensitive(true);
        ok
    }

    /// Notifie uniquement les failles exploitées qui concernent vos logiciels ET qu'on ne vous avait pas encore signalées.
    fn announce_new_matches(&self) {
        let (cves, names): (Vec<String>, Vec<String>) = {
            let kev = self.kev.borrow();
            let Some(k) = kev.as_ref() else { return };
            self.matched(k).into_iter().map(|m| (m.kev.cve, m.pkg.name)).unzip()
        };
        let first = self.ctx.state.borrow().kev_seen.is_empty();
        let new: Vec<usize> = {
            let seen = &self.ctx.state.borrow().kev_seen;
            (0..cves.len()).filter(|i| !seen.contains(&cves[*i])).collect()
        };
        self.ctx.state.borrow_mut().kev_seen = cves.clone();
        self.ctx.save();
        if first || new.is_empty() {
            return;
        }
        let mut soft: Vec<&str> = new.iter().map(|i| names[*i].as_str()).collect();
        soft.sort();
        soft.dedup();
        self.ctx.notify("nouvelles-kev", "Nouvelles failles activement exploitées", &format!("{} nouvelle(s) faille(s) concernent possiblement : {}", new.len(), soft.iter().take(5).copied().collect::<Vec<_>>().join(", ")));
    }

    pub fn kev_loaded(&self) -> bool {
        self.kev.borrow().is_some()
    }

    /// (failles, logiciels concernés) d'après le catalogue CISA, ou None si le catalogue n'est pas chargé.
    pub fn kev_summary(&self) -> Option<(usize, usize)> {
        let kev = self.kev.borrow();
        let k = kev.as_ref()?;
        let m = self.matched(k);
        let soft: std::collections::HashSet<&str> = m.iter().map(|x| x.pkg.name.as_str()).collect();
        Some((m.len(), soft.len()))
    }

    fn search(self: &Rc<Self>) {
        let q = self.query.text().to_string();
        let url = global::nvd_search_url(&q, 50);
        self.run_nvd(url, &format!("« {} »", q.trim()));
    }

    fn run_nvd(self: &Rc<Self>, url: Result<String, String>, label: &str) {
        let url = match url {
            Ok(u) => u,
            Err(e) => {
                self.nvd_info.set_text(&e);
                return;
            }
        };
        for b in [&self.search_btn, &self.recent_btn] {
            b.set_sensitive(false);
        }
        self.nvd_info.set_text(&crate::i18n::tr("Interrogation de NVD…"));
        let me = self.clone();
        let label = label.to_string();
        glib::spawn_future_local(async move {
            match fetch(&url).await.and_then(|t| global::parse_nvd(&t)) {
                Ok(page) => {
                    let rows: Vec<Vec<String>> = page.rows.iter().map(|r| vec![r.id.clone(), r.published.clone(), r.score.clone(), r.severity.clone(), r.description.clone()]).collect();
                    me.nvd_info.set_text(&format!("{label} : {} résultat(s) au total dans NVD, {} affiché(s). Double-clic : ouvrir la fiche officielle.", page.total, rows.len()));
                    me.nvd_table.set_rows(&rows);
                }
                Err(e) => me.nvd_info.set_text(&e),
            }
            // respect de la limite de débit de NVD
            glib::timeout_add_seconds_local_once(7, move || {
                for b in [&me.search_btn, &me.recent_btn] {
                    b.set_sensitive(true);
                }
            });
        });
    }
}

impl GlobalPage {
    /// Logiciels de la machine ciblés par des attaques réelles : (logiciel, nombre de failles, dernière ajoutée le).
    pub fn kev_groups(&self) -> Vec<(String, usize, String)> {
        let kev = self.kev.borrow();
        let Some(k) = kev.as_ref() else { return vec![] };
        let mut by: std::collections::BTreeMap<String, (usize, String)> = std::collections::BTreeMap::new();
        for m in self.matched(k) {
            let e = by.entry(m.pkg.name.clone()).or_insert((0, String::new()));
            e.0 += 1;
            if m.kev.added > e.1 {
                e.1 = m.kev.added.clone();
            }
        }
        let mut v: Vec<(String, usize, String)> = by.into_iter().map(|(n, (c, d))| (n, c, d)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

impl GlobalPage {
    /// Failles CISA rattachées à un logiciel de la machine, la plus récente d'abord.
    pub fn kev_entries(&self, pkg: &str) -> Vec<crate::global::KevVuln> {
        let kev = self.kev.borrow();
        let Some(k) = kev.as_ref() else { return vec![] };
        let mut v: Vec<crate::global::KevVuln> = self.matched(k).into_iter().filter(|m| m.pkg.name == pkg).map(|m| m.kev).collect();
        v.sort_by(|a, b| b.added.cmp(&a.added));
        v
    }
}

impl GlobalPage {
    /// L'inventaire des logiciels installés est-il chargé ? (sinon la correspondance avec le catalogue CISA n'est pas calculable)
    pub fn inventory_ready(&self) -> bool {
        !self.inv.borrow().is_empty()
    }
}

impl GlobalPage {
    /// Correspondances (mises en cache) entre le catalogue chargé et les logiciels installés.
    fn matched(&self, k: &Kev) -> Vec<global::Matched> {
        if let Some(c) = self.cache.borrow().as_ref() {
            return c.clone();
        }
        // delta réel : on ne garde que les failles que la version INSTALLÉE n'a pas encore corrigées
        let m: Vec<global::Matched> = global::matches(k, &self.inv.borrow()).into_iter().filter(|x| self.is_open(x)).collect();
        *self.cache.borrow_mut() = Some(m.clone());
        m
    }
}

impl GlobalPage {
    /// Versions installées (nom -> version), pour comparer aux versions affectées du tracker d'Arch.
    /// Le paquet installé a-t-il été construit APRÈS la dernière faille CISA qui le concerne ? Alors il contient très probablement déjà le correctif (estimation, pas une preuve).
    pub fn likely_fixed(&self, name: &str, last_added: &str) -> bool {
        match (self.builds.borrow().get(name), global::parse_iso_day(last_added)) {
            (Some(built), Some(added)) => *built > added,
            _ => false,
        }
    }

    /// Cette faille touche-t-elle encore la version installée ?
    /// 1) tracker d'Arch : version installée comparée à la version qui corrige (fiable) ;
    /// 2) sinon, estimation : paquet construit après la date de la faille.
    fn is_open(&self, m: &global::Matched) -> bool {
        use crate::tracker::Verdict;
        match self.idx.borrow().verdict(&m.kev.cve, &m.pkg.name, &m.pkg.version) {
            Verdict::Fixed => false,
            Verdict::Vulnerable => true,
            Verdict::Unknown => !self.likely_fixed(&m.pkg.name, &m.kev.added),
        }
    }

    pub fn installed_map(&self) -> std::collections::HashMap<String, String> {
        self.inv.borrow().iter().map(|p| (p.name.clone(), p.version.clone())).collect()
    }
}
