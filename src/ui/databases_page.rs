//! Bases de données de failles : d'où viennent les données de chaque outil, et leur mise à jour.

use super::dialogs::{Step, pending_updates_blocking, run_steps, system_update};
use super::{Ctx, plain_label, when};
use crate::risk;
use crate::tools::Plan;
use crate::util::abs_prog;
use gtk4 as gtk;
use gtk::{glib, prelude::*};
use serde_json::Value;
use std::rc::Rc;

pub struct DatabasesPage {
    pub root: gtk::ScrolledWindow,
    ctx: Rc<Ctx>,
    status: Vec<(&'static str, gtk::Label)>,
    extra_trivy: gtk::Label,
    extra_system: gtk::Label,
}

pub fn step(key: &'static str) -> Result<Step, String> {
    let prog = |n: &str| abs_prog(n).map(|p| p.to_string_lossy().into_owned()).ok_or_else(|| format!("{n} est introuvable"));
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mk = |label: &str, argv: Vec<String>, elevated: bool, ok: &'static [i32]| Step { key, label: label.into(), plan: Plan { argv, elevated, out_flag: None, out_pos: 0 }, ok_codes: ok };
    if key == "nvd" {
        return Ok(Step { key, label: "NVD : vérifier que le catalogue répond (NIST)".into(), plan: crate::global::fetch_plan(&crate::global::nvd_total_url())?, ok_codes: &[0] });
    }
    Ok(match key {
        "trivy" => mk("Trivy : télécharger la base de vulnérabilités (Aqua Security)", [vec![prog("trivy")?], s(&["rootfs", "--download-db-only", "--no-progress", "/tmp"])].concat(), false, &[0]),
        "rkhunter" => mk("rkhunter : mettre à jour les signatures (administrateur)", [vec![prog("rkhunter")?], s(&["--update", "--nocolors", "--skip-keypress"])].concat(), true, &[0, 2]),
        "lynis" => mk("Lynis : vérifier la version des règles", [vec![prog("lynis")?], s(&["update", "info"])].concat(), false, &[0]),
        "arch-audit" => mk("arch-audit : vérifier la source (Arch Security Tracker)", [vec![prog("arch-audit")?], s(&["--color", "never", "-q"])].concat(), false, &[0, 1]),
        _ => return Err("source inconnue".into()),
    })
}

fn trivy_info_blocking() -> Option<(String, String)> {
    let out = std::process::Command::new(abs_prog("trivy")?).args(["version", "--format", "json"]).output().ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    let db = v.get("VulnerabilityDB")?;
    Some((db.get("UpdatedAt")?.as_str()?.to_string(), db.get("DownloadedAt").and_then(Value::as_str).unwrap_or("").to_string()))
}

impl DatabasesPage {
    pub fn new(ctx: Rc<Ctx>, update_kev: Rc<dyn Fn()>) -> Rc<DatabasesPage> {
        let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
        for f in [24, 24] {
            let _ = f;
        }
        content.set_margin_top(20);
        content.set_margin_bottom(20);
        content.set_margin_start(24);
        content.set_margin_end(24);
        let title = gtk::Label::new(Some(crate::i18n::tr("Bases de données de failles").as_str()));
        title.add_css_class("title-2");
        title.set_xalign(0.0);
        let desc = plain_label("D'où viennent les données de chaque outil, et comment les garder à jour. Les sources « en direct » sont interrogées à chaque analyse : il n'y a rien à télécharger.");
        desc.add_css_class("dim-label");
        let all_btn = gtk::Button::with_label(&crate::i18n::tr("Tout mettre à jour"));
        all_btn.add_css_class("suggested-action");
        all_btn.set_halign(gtk::Align::Start);
        content.append(&title);
        content.append(&desc);
        content.append(&all_btn);

        let mut status = Vec::new();
        let mut buttons: Vec<(&'static str, gtk::Button)> = Vec::new();
        // (clé, titre, source, mode, bouton)
        let distro = crate::util::distro_name();
        let t_audit = crate::i18n::tr("arch-audit · paquets {distro}").replace("{distro}", &distro);
        let t_system = format!("{} · {}", crate::i18n::tr("Dépôts {distro}").replace("{distro}", &distro), crate::i18n::tr("paquets système"));
        let rows: [(&'static str, &str, &str, &str, Option<&str>); 8] = [
            ("arch-audit", t_audit.as_str(), "Arch Security Tracker — security.archlinux.org (équipe sécurité d'Arch Linux)", "En direct : interrogé à chaque analyse", Some("Vérifier la source")),
            ("trivy", "Trivy · bibliothèques, binaires, systèmes", "Base Trivy (Aqua Security) — miroir officiel mirror.gcr.io/aquasec/trivy-db, ghcr.io en secours. Couvre Debian, Ubuntu, RHEL, Alpine… et les langages (Go, Python, Node, Rust, Java…)", "Base locale : téléchargée automatiquement", Some("Mettre à jour")),
            ("osv-scanner", "OSV-Scanner · dépendances de vos projets", "OSV — osv.dev : PyPI, npm, crates.io, Go, Maven, RubyGems, GitHub Advisory, et d'autres écosystèmes", "En direct (API en ligne) : toujours à jour", None),
            ("rkhunter", "rkhunter · rootkits", "Fichiers de signatures du projet rkhunter, récupérés depuis ses miroirs", "Base locale : mise à jour avec les droits administrateur", Some("Mettre à jour")),
            ("lynis", "Lynis · configuration", "Règles d'audit embarquées par CISOfy dans le paquet Lynis", "Intégrées au paquet : mises à jour par pacman", Some("Vérifier la version")),
            ("kev", "CISA KEV · failles exploitées, tous éditeurs", "Catalogue officiel CISA (agence américaine de cybersécurité) des failles activement exploitées : Windows, Apple, Cisco, Linux, navigateurs…", "Catalogue local : téléchargé automatiquement", Some("Mettre à jour")),
            ("nvd", "NVD · catalogue mondial des CVE", "National Vulnerability Database du NIST — plus de 400 000 CVE", "En direct : recherche à la demande (page Failles mondiales) · le bouton vérifie que NVD répond", Some("Vérifier la source")),
            ("system", t_system.as_str(), "Dépôts officiels (pacman) : ce sont eux qui apportent les correctifs", "À synchroniser via la mise à jour du système", Some("Mettre à jour le système…")),
        ];
        let mut extra_trivy = gtk::Label::new(None);
        let mut extra_system = gtk::Label::new(None);
        for (key, name, source, mode, button) in rows {
            let card = gtk::Box::new(gtk::Orientation::Vertical, 3);
            card.add_css_class("card");
            for m in [14, 14] {
                let _ = m;
            }
            card.set_margin_bottom(0);
            let inner = gtk::Box::new(gtk::Orientation::Vertical, 3);
            inner.set_margin_top(12);
            inner.set_margin_bottom(12);
            inner.set_margin_start(16);
            inner.set_margin_end(16);
            let t = gtk::Label::new(Some(name));
            t.add_css_class("heading");
            t.set_xalign(0.0);
            let src = plain_label(source);
            src.add_css_class("dim-label");
            let m = plain_label(mode);
            let st = plain_label("");
            st.add_css_class("dim-label");
            for w in [t.upcast_ref::<gtk::Widget>(), src.upcast_ref(), m.upcast_ref(), st.upcast_ref()] {
                inner.append(w);
            }
            if key == "trivy" {
                extra_trivy = st.clone();
            }
            if key == "system" {
                extra_system = st.clone();
            }
            if let Some(label) = button {
                let b = gtk::Button::with_label(label);
                b.set_halign(gtk::Align::Start);
                b.set_margin_top(6);
                inner.append(&b);
                buttons.push((key, b));
            }
            card.append(&inner);
            content.append(&card);
            status.push((key, st));
        }
        let root = gtk::ScrolledWindow::builder().child(&content).hscrollbar_policy(gtk::PolicyType::Never).build();
        let page = Rc::new(DatabasesPage { root, ctx, status, extra_trivy, extra_system });
        page.refresh();

        for (key, b) in buttons {
            let (p, upd) = (page.clone(), update_kev.clone());
            b.connect_clicked(move |_| match key {
                "kev" => upd(),
                "system" => system_update(&p.ctx, Box::new(|| {})),
                k => p.run(vec![k]),
            });
        }
        let (p, upd) = (page.clone(), update_kev.clone());
        all_btn.connect_clicked(move |_| {
            upd();
            p.run(vec!["trivy", "rkhunter", "lynis", "arch-audit", "nvd"]);
        });
        page.load_live_info();
        page
    }

    fn run(self: &Rc<Self>, keys: Vec<&'static str>) {
        let mut steps = Vec::new();
        for k in keys {
            match step(k) {
                Ok(s) => steps.push(s),
                Err(e) => {
                    if let Some((_, l)) = self.status.iter().find(|(key, _)| *key == k) {
                        l.set_text(&e);
                    }
                }
            }
        }
        if steps.is_empty() {
            return;
        }
        let me = self.clone();
        run_steps(&self.ctx, "Mise à jour des bases de données", steps, move || {
            me.refresh();
            me.load_live_info();
        });
    }

    pub fn refresh(&self) {
        let st = self.ctx.state.borrow();
        for (key, label) in &self.status {
            let text = match st.db.get(*key) {
                Some(s) if s.ok => format!("✔ Dernière mise à jour réussie : {}", when(s.time).replace("analysé le ", "")),
                Some(s) => format!("✘ Échec de la dernière mise à jour ({})", when(s.time).replace("analysé le ", "")),
                None if matches!(*key, "osv-scanner" | "nvd" | "system") => String::new(),
                None => "Jamais mise à jour depuis cette application.".to_string(),
            };
            if !text.is_empty() {
                label.set_text(&text);
            }
        }
    }

    /// Informations lues sur la machine : fraîcheur de la base Trivy, mises à jour système en attente.
    fn load_live_info(self: &Rc<Self>) {
        let (tx, rx) = async_channel::bounded::<(Option<(String, String)>, usize)>(1);
        std::thread::spawn(move || {
            let n = risk::parse_updates(&pending_updates_blocking()).len();
            let _ = tx.send_blocking((trivy_info_blocking(), n));
        });
        let me = self.clone();
        glib::spawn_future_local(async move {
            let Ok((trivy, pending)) = rx.recv().await else { return };
            if let Some((updated, downloaded)) = trivy {
                let ts = glib::DateTime::from_iso8601(&updated, None).ok();
                let age = ts.as_ref().map(|d| (crate::util::now_unix() - d.to_unix()) / 86_400).unwrap_or(0);
                let date: String = updated.chars().take(16).collect::<String>().replace('T', " ");
                let dl: String = downloaded.chars().take(16).collect::<String>().replace('T', " ");
                me.extra_trivy.set_text(&format!("Base de vulnérabilités du {date} UTC (téléchargée le {dl}) — {age} jour(s){}", if age > 3 { " ⚠ périmée : mettez à jour" } else { "" }));
                if age > 3 {
                    me.extra_trivy.add_css_class("warning");
                }
            } else {
                me.extra_trivy.set_text(&crate::i18n::tr("Aucune base téléchargée : Trivy la téléchargera à la première analyse."));
            }
            me.extra_system.set_text(&if pending == 0 { "Système à jour d'après les dépôts.".to_string() } else { format!("{pending} mise(s) à jour en attente (certaines peuvent être à risque : vérifiées avant l'installation).") });
        });
    }
}
