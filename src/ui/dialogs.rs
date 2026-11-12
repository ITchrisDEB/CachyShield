//! Fenêtres de commande et boutons « Corriger », avec avertissement des risques AVANT toute action.

use super::{Ctx, plain_label};
use crate::risk::{self, Kind, RiskLevel};
use crate::runner::{self, Msg};
use crate::tools::Plan;
use crate::util::abs_prog;
use gtk4 as gtk;
use gtk::{gio, glib, prelude::*};
use libadwaita as adw;
use adw::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

// ─────────────────────────── fenêtre d'exécution ───────────────────────────

pub struct CmdDialog {
    pub win: adw::Window,
    text: gtk::TextView,
    banner: adw::Banner,
    status: gtk::Label,
    spinner: gtk::Spinner,
    close: gtk::Button,
    bar: gtk::ProgressBar,
    finished: Rc<std::cell::Cell<bool>>,
    custom: Rc<std::cell::Cell<bool>>,
}

impl CmdDialog {
    pub fn new(parent: Option<&gtk::Window>, title: &str, command: &str) -> Rc<CmdDialog> {
        let win = adw::Window::builder().title(title).modal(true).default_width(860).default_height(540).build();
        if let Some(p) = parent {
            win.set_transient_for(Some(p));
        }
        win.set_deletable(false);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&adw::HeaderBar::new());
        let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
        for f in [12, 12] {
            let _ = f;
        }
        body.set_margin_start(16);
        body.set_margin_end(16);
        body.set_margin_bottom(14);
        let cmd = plain_label(&format!("$ {command}"));
        cmd.add_css_class("dim-label");
        cmd.add_css_class("mono");
        let banner = adw::Banner::new("");
        banner.set_use_markup(false); // les noms de paquets viennent de sources externes : jamais de balisage
        let text = gtk::TextView::new();
        text.set_editable(false);
        text.set_monospace(true);
        text.set_cursor_visible(false);
        text.set_wrap_mode(gtk::WrapMode::WordChar);
        let sw = gtk::ScrolledWindow::builder().child(&text).vexpand(true).build();
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let spinner = gtk::Spinner::new();
        spinner.start();
        let status = gtk::Label::new(Some(crate::i18n::tr("En cours…").as_str()));
        status.set_hexpand(true);
        status.set_xalign(0.0);
        let close = gtk::Button::with_label(&crate::i18n::tr("Fermer"));
        close.add_css_class("suggested-action");
        close.set_sensitive(false);
        let w2 = win.clone();
        close.connect_clicked(move |_| w2.close());
        row.append(&spinner);
        row.append(&status);
        row.append(&close);
        let bar = gtk::ProgressBar::new();
        bar.set_show_text(true);
        bar.set_visible(false);
        for w in [cmd.upcast_ref::<gtk::Widget>(), banner.upcast_ref(), sw.upcast_ref(), bar.upcast_ref(), row.upcast_ref()] {
            body.append(w);
        }
        view.set_content(Some(&body));
        win.set_content(Some(&view));
        win.present();
        // temps écoulé affiché tant qu'aucune progression précise n'est connue : on voit que ça travaille
        let (finished, custom) = (Rc::new(std::cell::Cell::new(false)), Rc::new(std::cell::Cell::new(false)));
        {
            let (st, f, c, t0) = (status.clone(), finished.clone(), custom.clone(), std::time::Instant::now());
            glib::timeout_add_seconds_local(1, move || {
                if f.get() {
                    return glib::ControlFlow::Break;
                }
                if !c.get() {
                    st.set_text(&format!("{} ({} s)", crate::i18n::tr("En cours…"), t0.elapsed().as_secs()));
                }
                glib::ControlFlow::Continue
            });
        }
        Rc::new(CmdDialog { win, text, banner, status, spinner, close, bar, finished, custom })
    }

    /// Barre d'avancement (0.0–1.0) avec pourcentage et texte d'étape.
    pub fn progress(&self, frac: f64, text: &str) {
        let f = frac.clamp(0.0, 1.0);
        self.custom.set(true);
        self.bar.set_visible(true);
        self.bar.set_fraction(f);
        self.bar.set_text(Some(&format!("{} % — {}", (f * 100.0).floor() as u32, crate::i18n::tr(text))));
        self.status.set_text(&crate::i18n::tr(text));
    }

    pub fn add(&self, line: &str) {
        let buf = self.text.buffer();
        let mut end = buf.end_iter();
        buf.insert(&mut end, &crate::i18n::tr(line));
        buf.insert(&mut end, "\n");
    }

    /// Bouton supplémentaire (à côté de « Fermer ») : ferme la fenêtre puis lance l'action.
    pub fn offer(&self, label: &str, f: Box<dyn Fn()>) {
        let b = gtk::Button::with_label(&crate::i18n::tr(label));
        b.add_css_class("suggested-action");
        let w = self.win.clone();
        b.connect_clicked(move |_| {
            w.close();
            f();
        });
        if let Some(p) = self.close.parent().and_then(|p| p.downcast::<gtk::Box>().ok()) {
            p.insert_child_after(&b, Some(&self.close));
        }
    }

    pub fn notice(&self, text: &str) {
        self.banner.set_title(&crate::i18n::tr(text));
        self.banner.set_revealed(true);
    }

    pub fn finish(&self, status: &str) {
        self.finished.set(true);
        self.spinner.stop();
        if self.bar.is_visible() && status == "Terminé" {
            self.bar.set_fraction(1.0);
            self.bar.set_text(Some("100 %"));
        }
        self.status.set_text(&crate::i18n::tr(status));
        self.win.set_deletable(true);
        self.close.set_sensitive(true);
    }
}

/// Lance une commande dans une fenêtre dédiée.
pub fn run_command(parent: Option<gtk::Window>, title: &str, plan: Plan, cwd: Option<PathBuf>, on_done: impl FnOnce(Rc<CmdDialog>, i32, String) + 'static) {
    run_command_p(parent, title, plan, cwd, None, on_done)
}

/// Suivi d'avancement : reçoit chaque ligne, renvoie éventuellement (fraction, texte d'étape).
pub type Tracker = Box<dyn FnMut(&str) -> Option<(f64, String)>>;

/// État d'avancement de `pacman -Syu` : téléchargements (première moitié) puis installations « (i/N) » (seconde moitié).
pub struct PacProg {
    total: usize,
    dl: usize,
    inst: (usize, usize),
}

impl PacProg {
    pub fn new(total: usize) -> Self {
        PacProg { total: total.max(1), dl: 0, inst: (0, 0) }
    }

    fn is_pkg_token(t: &str) -> bool {
        ["-x86_64", "-any", "-aarch64", "-i686", "-riscv64"].iter().any(|a| t.contains(a))
    }

    pub fn feed(&mut self, line: &str) -> Option<(f64, String)> {
        let l = line.trim();
        if let Some(first) = l.strip_suffix(" downloading...").and_then(|r| r.split_whitespace().next()) {
            if Self::is_pkg_token(first) && self.inst.1 == 0 {
                self.dl = (self.dl + 1).min(self.total);
                return Some((0.5 * self.dl as f64 / self.total as f64, format!("Téléchargement : {} / {}", self.dl, self.total)));
            }
            return None;
        }
        if l.starts_with(":: Processing package changes") || l.contains("checking keys in keyring") || l.contains("checking package integrity") {
            self.dl = self.total;
            return Some((0.5, "Vérification des paquets".into()));
        }
        if let Some(rest) = l.strip_prefix('(') {
            if let Some((counts, what)) = rest.split_once(") ") {
                if ["installing ", "upgrading ", "reinstalling ", "downgrading "].iter().any(|k| what.starts_with(k)) {
                    if let Some((a, b)) = counts.split_once('/') {
                        if let (Ok(i), Ok(m)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                            if m > 0 && i <= m {
                                self.inst = (i, m);
                                return Some((0.5 + 0.5 * i as f64 / m as f64, format!("Installation : {i} / {m}")));
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

pub fn run_command_p(parent: Option<gtk::Window>, title: &str, plan: Plan, cwd: Option<PathBuf>, mut track: Option<Tracker>, on_done: impl FnOnce(Rc<CmdDialog>, i32, String) + 'static) {
    let dlg = CmdDialog::new(parent.as_ref(), title, &runner::preview(&plan));
    let run = match runner::spawn(&plan, SCRIPT_NOISE, cwd) {
        Ok(r) => r,
        Err(e) => {
            dlg.add(&e);
            dlg.finish("Échec du lancement");
            return;
        }
    };
    glib::spawn_future_local(async move {
        while let Ok(msg) = run.rx.recv().await {
            match msg {
                Msg::Line(l) => {
                    if let Some((f, t)) = track.as_mut().and_then(|tr| tr(&l)) {
                        dlg.progress(f, &t);
                    }
                    dlg.add(&l)
                }
                Msg::Done { code, text, .. } => {
                    let status = if code == 0 { "Terminé".to_string() } else { format!("Terminé avec le code {code} (annulé ou en erreur)") };
                    dlg.finish(&status);
                    on_done(dlg.clone(), code, text);
                    break;
                }
            }
        }
    });
}

pub(crate) fn alert(heading: &str, body: &str, responses: &[(&str, &str)]) -> adw::AlertDialog {
    let d = adw::AlertDialog::new(Some(crate::i18n::tr(heading).as_str()), Some(crate::i18n::tr(body).as_str()));
    for (id, label) in responses {
        d.add_response(id, crate::i18n::tr(label).as_str());
    }
    d
}

// ───────────────────────── mise à jour du système ──────────────────────────

/// Mises à jour de l'AUR en attente (lecture seule) : « paru -Qua » ou « yay -Qua ». Vide si aucun assistant AUR n'est installé.
pub fn pending_aur_blocking() -> String {
    let Some(helper) = abs_prog("paru").or_else(|| abs_prog("yay")) else { return String::new() };
    std::process::Command::new(helper).args(["-Qua"]).env("LC_ALL", "C").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Nom de l'assistant AUR détecté (paru ou yay).
pub fn aur_helper() -> Option<&'static str> {
    if abs_prog("paru").is_some() { Some("paru") } else if abs_prog("yay").is_some() { Some("yay") } else { None }
}

pub fn pending_updates_blocking() -> String {
    let (prog, args): (PathBuf, &[&str]) = match abs_prog("checkupdates") {
        Some(p) => (p, &[]),
        None => (abs_prog("pacman").unwrap_or_else(|| PathBuf::from("/usr/bin/pacman")), &["-Qu"]),
    };
    std::process::Command::new(prog).args(args).env("LC_ALL", "C").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Bouton « Corriger : mettre à jour le système » : liste les mises à jour, signale celles qui peuvent
/// bloquer le système, puis demande confirmation avant de lancer `pacman -Syu`.
pub fn system_update(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    // à la fin (succès, refus ou erreur), le compteur de l'icône de la zone de notification est recalculé
    let then: Box<dyn FnOnce()> = {
        let c = ctx.clone();
        Box::new(move || {
            then();
            super::auto::check_updates(&c);
        })
    };
    let parent = ctx.window();
    let ctx2 = ctx.clone();
    let (tx, rx) = async_channel::bounded::<(String, String)>(1);
    std::thread::spawn(move || {
        let _ = tx.send_blocking((pending_updates_blocking(), pending_aur_blocking()));
    });
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let Ok((out, aur_out)) = rx.recv().await else { return };
        let ups = risk::parse_updates(&out);
        let aur = risk::parse_updates(&aur_out);
        let aur_note = match (aur.is_empty(), aur_helper()) {
            (false, Some(_)) => format!("\n\n⚠ {} mise(s) à jour AUR en attente ({}) : traitées juste après, dans une seconde étape. L'AUR demande de relire chaque PKGBUILD (des paquets AUR ont été piégés en 2026) : vous les relirez dans l'application avant toute installation.", aur.len(), aur.iter().take(4).map(|u| u.name.clone()).collect::<Vec<_>>().join(", ")),
            (false, None) => String::new(),
            (true, Some(h)) => format!("\n\nAUR ({h}) : aucune mise à jour en attente."),
            (true, None) => "\n\nAUR : aucun assistant (paru, yay) détecté, vos paquets AUR ne sont pas surveillés.".to_string(),
        };
        if ups.is_empty() && !aur.is_empty() && aur_helper().is_some() {
            let names: Vec<String> = aur.iter().map(|u| u.name.clone()).collect();
            let _ = parent;
            aur_inapp(&ctx2, names, Box::new(move || drop(guard)));
            return;
        }
        if ups.is_empty() {
            let d = alert(
                "Rien à installer pour l'instant",
                &format!("Votre système est à jour : aucune mise à jour n'est en attente dans les dépôts officiels.\n\nIl n'y a rien à corriger maintenant : si des failles restent listées, elles n'ont pas de correctif publié pour votre version (voir leur détail).{aur_note}"),
                &[("ok", "Fermer")],
            );
            d.choose_future(parent.as_ref()).await;
            maintenance_flow(&ctx2, false, Box::new(move || drop(guard)));
            return;
        }
        let risks = risk::assess(&ups);
        let mut body = format!("{} paquet(s) seront mis à jour avec « pacman -Syu » (mise à jour complète, jamais partielle).\n\n", ups.len());
        if risks.is_empty() {
            body += "Aucune mise à jour particulièrement risquée détectée. Un instantané snapper est créé avant et après.";
        } else {
            body += "⚠ RISQUES DÉTECTÉS AVANT MISE À JOUR :\n";
            for r in &risks {
                let tag = if r.level == RiskLevel::High { "RISQUE ÉLEVÉ" } else { "À surveiller" };
                let names: Vec<&str> = r.packages.iter().take(6).map(String::as_str).collect();
                body += &format!("\n• [{tag}] {} ({}{})", r.message, names.join(", "), if r.packages.len() > 6 { "…" } else { "" });
            }
            body += "\n\nsnapper crée des instantanés avant/après : vous pourrez revenir en arrière. Fermez vos travaux en cours.";
        }
        body += &aur_note;
        let list: String = ups.iter().take(80).map(|u| format!("{}  {} → {}", u.name, u.old, u.new)).collect::<Vec<_>>().join("\n");
        let extra = gtk::ScrolledWindow::builder().min_content_height(130).max_content_height(200).build();
        let lbl = plain_label(&list);
        lbl.add_css_class("mono");
        lbl.set_selectable(true);
        extra.set_child(Some(&lbl));

        let d = alert("Mettre à jour le système ?", &body, &[("cancel", "Annuler"), ("go", "Mettre à jour")]);
        d.set_response_appearance("go", if risks.iter().any(|r| r.level == RiskLevel::High) { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested });
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        d.set_extra_child(Some(&extra));
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let Some(pacman) = abs_prog("pacman") else { return };
        let plan = Plan { argv: vec![pacman.to_string_lossy().into_owned(), "-Syu".into(), "--noconfirm".into()], elevated: true, out_flag: None, out_pos: 0 };
        let need_reboot = !risks.is_empty();
        let mut prog = PacProg::new(ups.len());
        let track: Tracker = Box::new(move |l| prog.feed(l));
        let aur_names = aur.iter().map(|u| u.name.clone()).collect::<Vec<_>>();
        run_command_p(parent, "Mise à jour du système", plan, None, Some(track), move |dlg, code, _| {
            if code != 0 {
                drop(guard);
                return;
            }
            {
                dlg.add("\n✔ Mise à jour terminée. Relancez les analyses pour vérifier les failles restantes.");
                if need_reboot {
                    dlg.notice("Redémarrage recommandé : des composants essentiels ont été mis à jour.");
                }
                if !aur_names.is_empty() && aur_helper().is_some() {
                    dlg.add(&format!("\n{} mise(s) à jour AUR en attente : étape suivante, relecture des PKGBUILD (fenêtre suivante).", aur_names.len()));
                    dlg.offer("Mettre à jour l'AUR…", { let (c, n) = (ctx2.clone(), aur_names.clone()); Box::new(move || aur_inapp(&c, n.clone(), Box::new(|| {}))) });
                    let (c, finish): (_, Box<dyn FnOnce()>) = (ctx2.clone(), Box::new(move || drop(guard)));
                    aur_inapp(&ctx2, aur_names, Box::new(move || maintenance_flow(&c, true, finish)));
                    return;
                }
            }
            // entretien comme arch-update : orphelins, cache, services, redémarrage
            maintenance_flow(&ctx2, true, Box::new(move || drop(guard)));
        });
    });
}

// ─────────────────────── correctifs OSV (aperçu sur copie) ─────────────────

fn simple_diff(old: &str, new: &str) -> Vec<String> {
    let mut count: HashMap<&str, i32> = HashMap::new();
    for l in old.lines() {
        *count.entry(l).or_default() += 1;
    }
    let mut out = Vec::new();
    for l in new.lines() {
        match count.get_mut(l) {
            Some(c) if *c > 0 => *c -= 1,
            _ => out.push(format!("+ {l}")),
        }
    }
    let mut removed: Vec<String> = Vec::new();
    for (l, c) in count {
        for _ in 0..c.max(0) {
            removed.push(format!("- {l}"));
        }
    }
    removed.sort();
    removed.extend(out);
    removed
}

/// Bouton « Corriger : proposer les correctifs » : travaille sur une COPIE du projet (jamais sur l'original),
/// et évalue le risque de casse (changements de version majeure).
pub fn osv_fix_preview(ctx: &Rc<Ctx>, start: String, then: Box<dyn FnOnce()>) {
    let parent = ctx.window();
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let dialog = gtk::FileDialog::new();
        dialog.set_title(&crate::i18n::tr("Projet à examiner (package.json + package-lock.json, ou pom.xml)"));
        if !start.is_empty() {
            dialog.set_initial_folder(Some(&gio::File::for_path(&start)));
        }
        let Ok(folder) = dialog.select_folder_future(parent.as_ref()).await else { return };
        let Some(src) = folder.path() else { return };
        let manifest = ["package.json", "pom.xml"].iter().map(|n| src.join(n)).find(|p| p.is_file());
        let lock = Some(src.join("package-lock.json")).filter(|p| p.is_file());
        if manifest.is_none() && lock.is_none() {
            let d = alert("Aucun fichier compatible", "Ce dossier ne contient ni package.json, package-lock.json ni pom.xml.\n\nLa commande « fix » d'OSV-Scanner ne gère pas requirements.txt ni les projets Go ou Rust : pour ceux-là, relevez la version indiquée dans la colonne « Correctif » et mettez-la à jour à la main.", &[("ok", "Fermer")]);
            d.choose_future(parent.as_ref()).await;
            return;
        }
        let level_dd = gtk::DropDown::from_strings(&["patch — le plus prudent", "minor", "major — peut casser le projet"]);
        level_dd.set_selected(1);
        let d = alert("Proposer des correctifs ?", &format!("Projet : {}\n\n• Travaille sur une COPIE temporaire : vos fichiers ne sont pas modifiés.\n• OSV-Scanner peut exécuter le gestionnaire de paquets (scripts npm, registres externes) : ne continuez que si vous faites confiance à ce projet.\n• Une mise à niveau « major » peut casser le projet : testez avant d'appliquer quoi que ce soit.\n\nJusqu'où peut-on changer les versions ?", src.display()), &[("cancel", "Annuler"), ("go", "Proposer")]);
        d.set_extra_child(Some(&level_dd));
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let level = ["patch", "minor", "major"][level_dd.selected().min(2) as usize];
        let Some(osv) = abs_prog("osv-scanner") else { return };
        let Ok(tmp) = runner::private_tmpdir() else { return };
        let mut argv = vec![osv.to_string_lossy().into_owned(), "fix".into()];
        let mut originals: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (flag, f) in [("-M", &manifest), ("-L", &lock)] {
            if let Some(p) = f {
                let name = p.file_name().unwrap_or_default().to_owned();
                if std::fs::copy(p, tmp.join(&name)).is_ok() {
                    argv.extend([flag.into(), name.to_string_lossy().into_owned()]);
                    originals.push((p.clone(), tmp.join(&name)));
                }
            }
        }
        argv.extend(["--upgrade-config".into(), level.into()]);
        let plan = Plan { argv, elevated: false, out_flag: None, out_pos: 0 };
        let tmp2 = tmp.clone();
        run_command(parent, "Correctifs proposés par OSV-Scanner (aperçu)", plan, Some(tmp), move |dlg, _, _| {
            let _guard = guard;
            dlg.add("\n── Modifications qui seraient apportées (aperçu sur copie) ──");
            let mut majors = 0;
            for (orig, copy) in &originals {
                let (o, c) = (std::fs::read_to_string(orig).unwrap_or_default(), std::fs::read_to_string(copy).unwrap_or_default());
                let name = orig.file_name().unwrap_or_default().to_string_lossy().into_owned();
                if name == "package-lock.json" {
                    let ch = risk::lock_changes(&o, &c);
                    let (maj, min, pat) = (ch.iter().filter(|x| x.kind == Kind::Major).count(), ch.iter().filter(|x| x.kind == Kind::Minor).count(), ch.iter().filter(|x| x.kind == Kind::Patch).count());
                    majors = maj;
                    dlg.add(&format!("{name} : {} paquet(s) changé(s) — {maj} majeur(s), {min} mineur(s), {pat} correctif(s)", ch.len()));
                    for x in ch.iter().filter(|x| x.kind == Kind::Major).take(25) {
                        dlg.add(&format!("  ⚠ CHANGEMENT MAJEUR : {} {} → {}  (peut casser le projet)", x.name, x.old, x.new));
                    }
                } else {
                    let diff = simple_diff(&o, &c);
                    dlg.add(&format!("{name} : {} ligne(s) différente(s)", diff.len()));
                    for l in diff.iter().take(60) {
                        dlg.add(&format!("  {l}"));
                    }
                }
            }
            if majors > 0 {
                dlg.notice(&format!("{majors} changement(s) de version majeure : risque de casser le projet. Testez avant d'appliquer."));
            } else {
                dlg.notice("Aucun changement majeur détecté : risque faible, testez quand même avant d'appliquer.");
            }
            dlg.add(&format!("\nVos fichiers dans {} n'ont PAS été modifiés.", originals.first().and_then(|(o, _)| o.parent()).map(|p| p.display().to_string()).unwrap_or_default()));
            let _ = std::fs::remove_dir_all(&tmp2);
        });
    });
}

// ─────────────────── mise à jour des bases (plusieurs étapes) ──────────────

pub struct Step {
    pub key: &'static str,
    pub label: String,
    pub plan: Plan,
    /// Codes de sortie considérés comme un succès.
    pub ok_codes: &'static [i32],
}

/// Exécute plusieurs commandes à la suite dans une seule fenêtre et mémorise le résultat de chacune.
/// Avertissements de `grep`/`egrep` émis par les scripts de rkhunter (sans importance, jamais utiles à l'utilisateur) : masqués dans les fenêtres de commande.
const SCRIPT_NOISE: &[&str] = &["egrep: warning", "grep: warning", "egrep: avertissement", "grep: avertissement"];

pub fn run_steps(ctx: &Rc<Ctx>, title: &str, steps: Vec<Step>, on_done: impl FnOnce() + 'static) {
    let dlg = CmdDialog::new(ctx.window().as_ref(), title, &format!("{} étape(s)", steps.len()));
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        let mut summary: Vec<(String, bool)> = Vec::new();
        let total = steps.len().max(1);
        for (i, s) in steps.into_iter().enumerate() {
            dlg.progress(i as f64 / total as f64, &format!("Étape {} / {} : {}", i + 1, total, s.label));
            dlg.add(&format!("\n▶ {}", s.label));
            let ok = match runner::spawn(&s.plan, SCRIPT_NOISE, None) {
                Err(e) => {
                    dlg.add(&e);
                    false
                }
                Ok(run) => {
                    let mut code = -1;
                    let mut result: Option<String> = None;
                    while let Ok(msg) = run.rx.recv().await {
                        match msg {
                            Msg::Line(l) => dlg.add(&l),
                            Msg::Done { code: c, blob, .. } => {
                                code = c;
                                result = blob;
                                break;
                            }
                        }
                    }
                    // NVD : la réponse (une seule requête) donne le nombre total de CVE du catalogue
                    if s.key == "nvd" && s.ok_codes.contains(&code) {
                        match result.as_deref().map(crate::global::parse_nvd) {
                            Some(Ok(p)) if p.total > 0 => dlg.add(&format!("NVD : {} CVE au total dans le catalogue", p.total)),
                            _ => dlg.add("NVD : réponse reçue, mais illisible"),
                        }
                    }
                    s.ok_codes.contains(&code)
                }
            };
            dlg.add(if ok { "✔ terminé" } else { "✘ échec (voir ci-dessus)" });
            ctx.state.borrow_mut().db.insert(s.key.into(), crate::util::Stamp { time: crate::util::now_unix(), ok });
            summary.push((s.label, ok));
        }
        ctx.save();
        dlg.add("\n── Résumé ──");
        for (l, ok) in &summary {
            dlg.add(&format!("{} {l}", if *ok { "✔" } else { "✘" }));
        }
        let bad = summary.iter().filter(|(_, ok)| !ok).count();
        if bad > 0 {
            dlg.notice(&format!("{bad} mise(s) à jour en échec : les données de ces sources peuvent être périmées."));
        }
        dlg.progress(1.0, "Terminé");
        dlg.finish(if bad == 0 { "Toutes les bases sont à jour" } else { "Terminé avec des échecs" });
        on_done();
    });
}

/// Exécute une action quand il est détruit : permet de prévenir l'appelant à CHAQUE sortie
/// (confirmation refusée, annulation, fin de commande), pour enchaîner plusieurs correctifs.
struct Then(Option<Box<dyn FnOnce()>>);

impl Drop for Then {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Exécute une commande sans fenêtre (mises à jour automatiques des bases) ; renvoie true en cas de succès.
/// Exécute une commande et renvoie (code, sortie) sans ouvrir de fenêtre.
pub async fn run_capture(plan: &Plan) -> (i32, String) {
    let run = match runner::spawn(plan, SCRIPT_NOISE, None) {
        Ok(r) => r,
        Err(e) => return (127, e),
    };
    let mut out = String::new();
    while let Ok(msg) = run.rx.recv().await {
        match msg {
            Msg::Line(l) => {
                out.push_str(&l);
                out.push('\n');
            }
            Msg::Done { code, .. } => return (code, out),
        }
    }
    (-1, out)
}

pub async fn run_silent(plan: &Plan, ok_codes: &[i32]) -> bool {
    let Ok(run) = runner::spawn(plan, &[], None) else { return false };
    while let Ok(msg) = run.rx.recv().await {
        if let Msg::Done { code, .. } = msg {
            return ok_codes.contains(&code);
        }
    }
    false
}

// ───────────────── correction rapide : SSH sans connexion root ─────────────────
// Passe par l'éditeur de réglages SSH (fichier géré unique, script contrôlé, retour arrière automatique).

pub fn ssh_fix_applied() -> bool {
    super::sshpanel::root_login_blocked()
}

pub fn admin_script_plan(script: &'static str) -> Plan {
    Plan { argv: vec![crate::util::SH.into(), "-c".into(), script.into()], elevated: true, out_flag: None, out_pos: 0 }
}

pub fn apply_ssh_fix(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    super::sshpanel::set_root_login_no(ctx, then);
}

pub fn revert_ssh_fix(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    super::sshpanel::unset_root_login(ctx, then);
}

// ───────────────────── couper ou bloquer un programme ─────────────────────

use crate::procctl::{self, Kill};
use crate::util::BlockRec;

fn record_block(ctx: &Rc<Ctx>, rec: BlockRec) {
    {
        let mut st = ctx.state.borrow_mut();
        if !st.blocks.contains(&rec) {
            st.blocks.push(rec);
        }
    }
    ctx.save();
}

fn kill_plan(sig: &'static str, pids: &[u32]) -> Option<Plan> {
    let kill = abs_prog("kill")?;
    let mut argv = vec![kill.to_string_lossy().into_owned(), "-s".into(), sig.into(), "--".into()];
    argv.extend(pids.iter().map(u32::to_string));
    Some(Plan { argv, elevated: false, out_flag: None, out_pos: 0 })
}

/// Processus encore valides et arrêtables : le PID a pu être réattribué ou le programme a pu changer depuis l'analyse.
fn killable(pids: &[u32]) -> Vec<procctl::ProcInfo> {
    let (me, own) = (procctl::current_uid(), std::process::id());
    procctl::pids_valid(pids).into_iter().filter_map(procctl::read_proc).filter(|p| procctl::can_kill(p, me, own) == Kill::Allowed).collect()
}

/// Arrête un programme : confirmation, arrêt propre (SIGTERM), puis proposition de forcer (SIGKILL) s'il résiste.
pub fn stop_process(ctx: &Rc<Ctx>, name: &str, pids: Vec<u32>, then: Box<dyn FnOnce()>) {
    let (parent, name, ctx) = (ctx.window(), name.to_string(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let procs = killable(&pids);
        if procs.is_empty() {
            let d = alert("Rien à arrêter", "Ce programme n'existe plus, ou son arrêt n'est pas autorisé (programme système ou session).", &[("ok", "Fermer")]);
            d.choose_future(parent.as_ref()).await;
            return;
        }
        let ids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        let cmd = procs.first().map(|p| p.cmdline.clone()).unwrap_or_default();
        let body = format!("Programme : {name}\nProcessus n°{}\nCommande : {cmd}\n\nUne demande d'arrêt PROPRE (SIGTERM) lui sera envoyée : il a le temps d'enregistrer et de se fermer.\n• Les données non enregistrées dans ce programme peuvent être perdues.\n• Il ne redémarre pas tout seul, sauf s'il est géré par un service.\n• Votre session et le système ne sont pas touchés.", ids.iter().map(u32::to_string).collect::<Vec<_>>().join(", "));
        let d = alert(&format!("Arrêter « {name} » ?"), &body, &[("cancel", "Annuler"), ("go", "Arrêter le programme")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Destructive);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let Some(plan) = kill_plan("TERM", &ids) else { return };
        let (p2, ids2, name2, ctx2) = (parent.clone(), ids.clone(), name.clone(), ctx.clone());
        run_command(parent, &format!("Arrêt de « {name} »"), plan, None, move |dlg, _code, _| {
            let _g = guard;
            glib::spawn_future_local(async move {
                glib::timeout_future_seconds(2).await;
                let alive: Vec<u32> = ids2.iter().copied().filter(|p| procctl::alive(*p)).collect();
                if alive.is_empty() {
                    dlg.add("\n✔ Le programme s'est arrêté.");
                    dlg.notice("Programme arrêté.");
                    return;
                }
                dlg.notice("Le programme ne s'est pas arrêté de lui-même.");
                let d = alert("Il résiste : forcer l'arrêt ?", "Le programme n'a pas répondu à la demande d'arrêt propre.\n\nForcer l'arrêt (SIGKILL) le coupe immédiatement : les données non enregistrées sont perdues.", &[("cancel", "Laisser tourner"), ("go", "Forcer l'arrêt")]);
                d.set_response_appearance("go", adw::ResponseAppearance::Destructive);
                d.set_default_response(Some("cancel"));
                d.set_close_response("cancel");
                if d.choose_future(p2.as_ref()).await != "go" {
                    return;
                }
                let still = killable(&alive).iter().map(|p| p.pid).collect::<Vec<_>>();
                if let Some(plan) = kill_plan("KILL", &still) {
                    run_command(p2, &format!("Arrêt forcé de « {name2} »"), plan, None, |_, _, _| {});
                }
                let _ = &ctx2;
            });
        });
    });
}

pub(crate) fn admin_args_plan(script: &'static str, args: &[String]) -> Plan {
    let mut argv = vec![crate::util::SH.to_string(), "-c".into(), script.into(), "sh".into()];
    argv.extend(args.iter().cloned());
    Plan { argv, elevated: true, out_flag: None, out_pos: 0 }
}

/// Bloque l'accès à un port depuis le réseau (règle dans une table dédiée, valable jusqu'au redémarrage).
pub fn block_port(ctx: &Rc<Ctx>, proto: String, port: u16, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        if !procctl::valid_proto(&proto) || port == 0 {
            return;
        }
        let body = format!("Ce qui va être fait :\n• ajout d'une règle dans une table de pare-feu DÉDIÉE à l'application : « refuser le port {port}/{proto} pour tout ce qui vient d'un autre appareil »\n\nEffet : le programme continue de tourner et reste utilisable depuis cet ordinateur (l'accès local n'est pas bloqué), mais les autres appareils du réseau ne peuvent plus s'y connecter.\n\nSécurités : vos autres règles de pare-feu ne sont pas touchées · le blocage disparaît au redémarrage · annulable à tout moment depuis la page Réseau.\n\nSi un autre appareil de chez vous utilise ce service (par exemple un second ordinateur), il sera coupé.");
        let d = alert(&format!("Bloquer le port {port}/{proto} depuis le réseau ?"), &body, &[("cancel", "Annuler"), ("go", "Bloquer")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let plan = admin_args_plan(procctl::BLOCK_PORT_SCRIPT, &[proto.clone(), port.to_string()]);
        run_command(parent, &format!("Blocage du port {port}/{proto}"), plan, None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                record_block(&ctx, BlockRec { kind: "port".into(), proto, port, ip: String::new(), time: crate::util::now_unix() });
                dlg.notice("Port bloqué depuis le réseau. Pour l'annuler : page Réseau → « Blocages actifs ».");
            } else {
                dlg.notice("Rien n'a été bloqué (autorisation refusée ou erreur : voir ci-dessus).");
            }
        });
    });
}

pub fn unblock_port(ctx: &Rc<Ctx>, proto: String, port: u16, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        if !procctl::valid_proto(&proto) || port == 0 {
            return;
        }
        let plan = admin_args_plan(procctl::UNBLOCK_PORT_SCRIPT, &[proto.clone(), port.to_string()]);
        run_command(parent, &format!("Déblocage du port {port}/{proto}"), plan, None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                ctx.state.borrow_mut().blocks.retain(|b| !(b.kind == "port" && b.proto == proto && b.port == port));
                ctx.save();
                dlg.notice("Port débloqué.");
            } else {
                dlg.notice("Le déblocage a échoué ou a été annulé.");
            }
        });
    });
}

/// Bloque les connexions sortantes vers des serveurs publics (jamais le réseau local).
pub fn block_hosts(ctx: &Rc<Ctx>, ips: Vec<String>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let ips: Vec<String> = ips.iter().filter_map(|i| procctl::blockable_host(i)).collect();
        if ips.is_empty() {
            return;
        }
        let body = format!("Serveurs concernés ({}) :\n{}\n\nEffet : les connexions de cet ordinateur vers ces adresses sont refusées, pour TOUS les programmes. Un site peut utiliser plusieurs adresses, et une adresse partagée (hébergeur, CDN) peut servir d'autres sites : certains pourraient ne plus s'afficher.\n\nSécurités : seules des adresses publiques sont acceptées (jamais votre réseau local) · vos autres règles ne sont pas touchées · le blocage disparaît au redémarrage · annulable avec « Tout débloquer ».", ips.len(), ips.join("\n"));
        let d = alert("Bloquer ces serveurs ?", &body, &[("cancel", "Annuler"), ("go", "Bloquer")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let plan = admin_args_plan(procctl::BLOCK_HOSTS_SCRIPT, &ips);
        run_command(parent, "Blocage de serveurs", plan, None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                for ip in &ips {
                    record_block(&ctx, BlockRec { kind: "host".into(), proto: String::new(), port: 0, ip: ip.clone(), time: crate::util::now_unix() });
                }
                dlg.notice("Serveurs bloqués. Pour les débloquer : page Réseau → « Blocages actifs ».");
            } else {
                dlg.notice("Rien n'a été bloqué (autorisation refusée ou erreur).");
            }
        });
    });
}

/// Retire tous les blocages posés par l'application.
pub fn unblock_all(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        run_command(parent, "Levée de tous les blocages", admin_args_plan(procctl::UNBLOCK_ALL_SCRIPT, &[]), None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                ctx.state.borrow_mut().blocks.retain(|b| b.kind == "firewall");
                ctx.save();
                dlg.notice("Tous les blocages sont levés.");
            } else {
                dlg.notice("L'opération a échoué ou a été annulée.");
            }
        });
    });
}

// ───────────────────────── pare-feu de l'application ─────────────────────────

/// Heure de démarrage de la machine (les règles nft disparaissent à ce moment-là).
fn boot_unix() -> i64 {
    let up = std::fs::read_to_string("/proc/uptime").ok().and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok()).unwrap_or(0.0);
    crate::util::now_unix() - up as i64
}

/// Le service de démarrage du pare-feu est-il installé ? (fichier lisible par tous, sans droits root)
pub fn firewall_permanent() -> bool {
    std::path::Path::new("/etc/systemd/system/cachy-shield-firewall.service").exists()
}

/// Le pare-feu de l'application est-il actif ? (enregistré dans l'état, oublié après un redémarrage)
pub fn firewall_on(ctx: &Rc<Ctx>) -> bool {
    if firewall_permanent() {
        return true;
    }
    let boot = boot_unix();
    let mut st = ctx.state.borrow_mut();
    let before = st.blocks.len();
    st.blocks.retain(|b| b.time >= boot - 5);
    let changed = before != st.blocks.len();
    let on = st.blocks.iter().any(|b| b.kind == "firewall");
    drop(st);
    if changed {
        ctx.save();
    }
    on
}

/// Pare-feu système actif (ufw ou firewalld), sans droits root.
pub fn native_active() -> Option<&'static str> {
    procctl::active_backend().map(|b| b.id())
}

pub fn enable_firewall(ctx: &Rc<Ctx>, ports: Vec<String>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let blocked = !procctl::kernel_modules_present();
        let backend = procctl::fw_backend();
        let name = procctl::fw_backend_name(backend);
        let kept = if ports.is_empty() { "aucun".to_string() } else { procctl::human_rules(&ports) };
        let native = backend != procctl::FwBackend::Own;
        let how = if native { format!("Pare-feu du système utilisé : {name} (le pare-feu natif de votre installation ; il reste actif à chaque démarrage).") } else { "Pare-feu utilisé : nftables, dans une table dédiée à l'application.".to_string() };
        let tail = if native { format!("Sécurités : vos règles existantes de {name} sont conservées · désactivable à tout moment depuis cette tuile.") } else { "Sécurités : table de pare-feu dédiée, vos autres règles ne sont pas touchées · désactivable à tout moment depuis cette tuile.\n\nDeux choix : « Jusqu'au redémarrage » (rien ne reste après le prochain démarrage, le plus prudent pour essayer) ou « Permanent » (un petit service de démarrage « cachy-shield-firewall » le remet à chaque démarrage ; votre fichier nftables.conf n'est pas modifié).".to_string() };
        let warn = if blocked { "⚠ Activation impossible pour le moment : le noyau en cours d'exécution n'a plus ses modules installés (le noyau a été mis à jour sans redémarrage). Redémarrez l'ordinateur, puis revenez ici. Vous pouvez en attendant consulter ce qui serait appliqué et modifier vos règles (section « Règles du pare-feu » de la page Réseau).\n\n" } else { "" };
        let body = format!("{warn}Ce qui va être fait :\n• les connexions entrantes venant d'autres appareils sont refusées, sauf les réponses à ce que vous ouvrez vous-même, le trafic local et le ping\n• règles appliquées (vos services « autorisés » et vos règles personnalisées) : {kept}\n• {how}\n\nEffet : votre navigateur, les mises à jour et tout ce que VOUS lancez continuent de fonctionner. Un autre appareil ne pourra plus se connecter à un service que vous n'avez pas marqué « Autoriser » (partage de fichiers, SSH, bureau à distance…).\n\n{tail}");
        let responses: Vec<(&str, &str)> = if blocked { vec![("cancel", "Fermer"), ("edit", "Modifier les règles")] } else if native { vec![("cancel", "Annuler"), ("perm", "Activer")] } else { vec![("cancel", "Annuler"), ("temp", "Jusqu'au redémarrage"), ("perm", "Permanent")] };
        let d = alert("Activer le pare-feu ?", &body, &responses);
        d.set_response_appearance(if native { "perm" } else { "temp" }, adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        let mode = d.choose_future(parent.as_ref()).await;
        if mode == "edit" {
            super::wizard::show_fw_editor(&ctx, Rc::new(|| {}));
            return;
        }
        if mode != "temp" && mode != "perm" {
            return;
        }
        let permanent = mode == "perm";
        let plan = match backend {
            procctl::FwBackend::Ufw => admin_args_plan(procctl::UFW_ON_SCRIPT, &ports),
            procctl::FwBackend::Firewalld => admin_args_plan(procctl::FIREWALLD_ON_SCRIPT, &ports),
            procctl::FwBackend::Own => {
                let mut args = vec![mode.to_string()];
                args.extend(ports.iter().cloned());
                admin_args_plan(procctl::FIREWALL_ON_SCRIPT, &args)
            }
        };
        run_command(parent, "Activation du pare-feu", plan, None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                if !native {
                    record_block(&ctx, BlockRec { kind: "firewall".into(), proto: String::new(), port: 0, ip: String::new(), time: crate::util::now_unix() });
                }
                dlg.notice(if native { "Pare-feu activé (il reste actif à chaque démarrage)." } else if permanent { "Pare-feu activé de façon permanente (retiré avec « Désactiver le pare-feu »)." } else { "Pare-feu activé jusqu'au prochain redémarrage." });
            } else {
                dlg.notice("Le pare-feu n'a pas été activé (autorisation refusée ou erreur : voir ci-dessus).");
            }
        });
    });
}

pub fn disable_firewall(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let (script, title): (&'static str, &str) = match native_active() {
            Some("ufw") => (procctl::UFW_OFF_SCRIPT, "Désactivation d'ufw"),
            Some(_) => (procctl::FIREWALLD_OFF_SCRIPT, "Désactivation de firewalld"),
            None => (procctl::FIREWALL_OFF_SCRIPT, "Désactivation du pare-feu"),
        };
        run_command(parent, title, admin_args_plan(script, &[]), None, move |dlg, code, _| {
            let _g = guard;
            if code == 0 {
                ctx.state.borrow_mut().blocks.retain(|b| b.kind != "firewall");
                ctx.save();
                dlg.notice("Pare-feu désactivé.");
            } else {
                dlg.notice("L'opération a échoué ou a été annulée.");
            }
        });
    });
}

// ───────────────────── durcissement du noyau et du réseau (sysctl.d) ─────────────────────

pub fn apply_hardening(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let _ = &ctx;
        let guard = Then(Some(then));
        let pending = crate::harden::pending();
        if pending.is_empty() {
            let d = alert("Rien à durcir", "Tous les réglages du noyau et du réseau proposés sont déjà à la valeur recommandée.", &[("close", "Fermer")]);
            let _ = d.choose_future(parent.as_ref()).await;
            return;
        }
        let list = pending.iter().map(|(i, old)| format!("• {} : {} → {}\n   {}", i.key, old, i.want, crate::i18n::tr(i.why))).collect::<Vec<_>>().join("\n");
        let body = format!("Ce qui va être fait :\n• création du fichier {} (mécanisme natif de Linux : sysctl.d)\n{list}\n\nEffet : ces réglages sont appliqués tout de suite et à chaque démarrage. Ils n'ont aucun effet visible sur l'usage normal d'un poste de bureau.\n\nSécurités : seules des valeurs numériques sûres sont acceptées · les valeurs d'origine sont gardées dans le fichier · annulation à tout moment avec « Annuler le durcissement ».", crate::harden::CONF);
        let d = alert("Appliquer le durcissement du système ?", &body, &[("cancel", "Annuler"), ("go", "Appliquer")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let plan = admin_args_plan(crate::harden::APPLY_SCRIPT, &crate::harden::args(&pending));
        run_command(parent, "Durcissement du système", plan, None, move |dlg, code, _| {
            let _g = guard;
            dlg.notice(if code == 0 { "Durcissement appliqué. Pour l'annuler : « Annuler le durcissement »." } else { "Rien n'a été modifié (autorisation refusée ou erreur : voir ci-dessus)." });
        });
    });
}

pub fn revert_hardening(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, _ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        run_command(parent, "Annulation du durcissement", admin_script_plan(crate::harden::REVERT_SCRIPT), None, move |dlg, code, _| {
            let _g = guard;
            dlg.notice(if code == 0 { "Durcissement annulé." } else { "L'annulation a échoué ou a été refusée." });
        });
    });
}

// ───────────────────── correction directe d'une dépendance npm ─────────────────────

const NPM_FIX_SCRIPT: &str = r#"npm="$1"; name="$2"; fixed="$3"
case "$npm" in /*) ;; *) echo "npm introuvable."; exit 2;; esac
case "$name" in ''|-*|*[!A-Za-z0-9@/._~+-]*) echo "Nom de paquet invalide."; exit 2;; esac
case "$fixed" in ''|-*|*[!0-9A-Za-z.+-]*) echo "Version invalide."; exit 2;; esac
[ -f package.json ] || { echo "package.json introuvable dans ce dossier."; exit 3; }
ts=$(date +%Y%m%d-%H%M%S)
echo "1/3 Sauvegarde de package.json et package-lock.json (suffixe .cs-backup-$ts)…"
cp -p package.json "package.json.cs-backup-$ts" || exit 4
[ -f package-lock.json ] && cp -p package-lock.json "package-lock.json.cs-backup-$ts"
echo "2/3 Mise à jour de $name vers $fixed (sans exécuter de scripts d'installation)…"
if ! "$npm" install "$name@$fixed" --ignore-scripts --no-audit --no-fund; then
  echo "Échec : restauration des fichiers d'origine."
  cp -p "package.json.cs-backup-$ts" package.json
  [ -f "package-lock.json.cs-backup-$ts" ] && cp -p "package-lock.json.cs-backup-$ts" package-lock.json
  exit 5
fi
echo "3/3 Terminé. Pour annuler : copiez les fichiers « .cs-backup-$ts » par-dessus package.json et package-lock.json."
"#;

pub fn npm_fix(ctx: &Rc<Ctx>, dir: String, name: String, fixed: String, then: Box<dyn FnOnce()>) {
    let (parent, _ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let path = std::path::PathBuf::from(&dir);
        let Some(npm) = crate::util::abs_prog("npm") else {
            let d = alert("npm introuvable", "Installez npm (paquet « npm » ou « nodejs-lts ») pour mettre à jour cette dépendance, ou copiez la commande à la main.", &[("close", "Fermer")]);
            let _ = d.choose_future(parent.as_ref()).await;
            return;
        };
        if !path.is_absolute() || !path.join("package.json").is_file() || crate::advice::npm_project_dir(&[path.join("package.json").to_string_lossy().into_owned()]).is_none() {
            return;
        }
        let body = format!("Projet : {dir}\n\nCe qui va être fait :\n• sauvegarde de package.json et package-lock.json (fichiers « .cs-backup-… » à côté)\n• commande : npm install {name}@{fixed} --ignore-scripts\n\nEffet : la dépendance est mise à jour dans CE projet, avec son fichier de verrouillage. Aucun script d'installation n'est exécuté, aucun droit administrateur n'est utilisé.\n\nSécurités : en cas d'échec, les fichiers d'origine sont restaurés automatiquement · une montée de version majeure peut casser le projet : testez-le ensuite.");
        let d = alert(&format!("Mettre à jour {name} vers {fixed} ?"), &body, &[("cancel", "Annuler"), ("go", "Mettre à jour")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let argv = vec![crate::util::SH.to_string(), "-c".into(), NPM_FIX_SCRIPT.into(), "sh".into(), npm.to_string_lossy().into_owned(), name.clone(), fixed.clone()];
        let plan = Plan { argv, elevated: false, out_flag: None, out_pos: 0 };
        run_command(parent, &format!("Mise à jour de {name}"), plan, Some(path), move |dlg, code, _| {
            let _g = guard;
            dlg.notice(if code == 0 { "Dépendance mise à jour. Relancez l'analyse des projets pour vérifier, et testez votre projet." } else { "Rien n'a été modifié (les fichiers d'origine ont été restaurés si nécessaire : voir ci-dessus)." });
        });
    });
}

// ───────────────────── règles de pare-feu personnalisées (éditables sans activer le pare-feu) ─────────────────────

/// Fenêtre d'ajout d'une règle : action, protocole, port, adresse source facultative. Rien n'est appliqué au système ici :
/// la règle est enregistrée et sera appliquée à l'activation (ou via « Mettre à jour les ports ouverts »).
pub fn add_fw_rule(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let d = adw::AlertDialog::new(Some(&crate::i18n::tr("Ajouter une règle de pare-feu")), Some(&crate::i18n::tr("La règle est enregistrée et appliquée quand le pare-feu est activé ou mis à jour. Rien n'est modifié sur le système maintenant.")));
        let grid = gtk::Grid::builder().row_spacing(8).column_spacing(10).margin_top(6).build();
        let t = |s: &str| crate::i18n::tr(s);
        let actions = gtk::DropDown::from_strings(&[&t("Autoriser"), &t("Refuser"), &t("Limiter (anti-abus : 10 connexions/minute)")]);
        let protos = gtk::DropDown::from_strings(&["TCP", "UDP"]);
        let port = gtk::Entry::builder().placeholder_text(t("Port (1 à 65535)")).input_purpose(gtk::InputPurpose::Digits).hexpand(true).build();
        let from = gtk::Entry::builder().placeholder_text(t("Adresse ou réseau source, ex. 192.168.0.0/24 (vide = n'importe où)")).hexpand(true).build();
        for (i, (label, w)) in [("Action", actions.clone().upcast::<gtk::Widget>()), ("Protocole", protos.clone().upcast()), ("Port", port.clone().upcast()), ("Depuis", from.clone().upcast())].into_iter().enumerate() {
            let l = gtk::Label::new(Some(&t(label)));
            l.set_xalign(0.0);
            grid.attach(&l, 0, i as i32, 1, 1);
            grid.attach(&w, 1, i as i32, 1, 1);
        }
        d.set_extra_child(Some(&grid));
        d.add_response("cancel", &t("Annuler"));
        d.add_response("add", &t("Ajouter"));
        d.set_response_appearance("add", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("add"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "add" {
            return;
        }
        let rule = crate::util::FwRule {
            action: ["allow", "deny", "limit"].get(actions.selected() as usize).copied().unwrap_or("allow").into(),
            proto: if protos.selected() == 1 { "udp" } else { "tcp" }.into(),
            port: port.text().trim().parse().unwrap_or(0),
            from: from.text().trim().to_string(),
        };
        if !procctl::rule_valid(&rule) {
            let e = alert("Règle invalide", "Vérifiez le port (1 à 65535) et l'adresse source (IPv4, ou réseau comme 192.168.0.0/24).", &[("close", "Fermer")]);
            let _ = e.choose_future(parent.as_ref()).await;
            return;
        }
        {
            let mut st = ctx.state.borrow_mut();
            if !st.fw_rules.contains(&rule) {
                st.fw_rules.push(rule);
            }
        }
        ctx.save();
        drop(guard);
    });
}

// ───────────────────────────── redémarrage de l'ordinateur ─────────────────────────────

/// Redémarre l'ordinateur APRÈS confirmation (systemd/logind : `systemctl reboot`, droits de la session).
pub fn reboot(ctx: &Rc<Ctx>, then: Box<dyn FnOnce()>) {
    let (parent, _ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let Some(sc) = crate::util::abs_prog("systemctl") else { return };
        let d = alert("Redémarrer l'ordinateur ?", "Tous les programmes seront fermés et l'ordinateur redémarrera tout de suite.\n\nEnregistrez d'abord vos travaux en cours. Un redémarrage applique les mises à jour du noyau et des pilotes.", &[("cancel", "Annuler"), ("go", "Redémarrer")]);
        d.set_response_appearance("go", adw::ResponseAppearance::Destructive);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        let plan = Plan { argv: vec![sc.to_string_lossy().into_owned(), "reboot".into()], elevated: false, out_flag: None, out_pos: 0 };
        run_command(parent, "Redémarrage", plan, None, move |dlg, code, _| {
            let _g = guard;
            if code != 0 {
                dlg.notice("Le redémarrage n'a pas été lancé (refusé ou erreur : voir ci-dessus).");
            }
        });
    });
}

// ───────────────────── correction des dépendances de vos projets ─────────────────────

/// Fenêtre « Corriger vos projets » : liste des corrections, cases à cocher (les sauts de version majeure sont décochés),
/// puis exécution avec sauvegarde et restauration automatique. Rien n'est modifié avant le clic sur « Corriger ».
pub fn project_fix(ctx: &Rc<Ctx>, title: &str, items: Vec<crate::depfix::Item>, then: Box<dyn FnOnce()>) {
    use crate::depfix::Kind as K;
    let t = |s: &str| crate::i18n::tr(s);
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    for m in [content.clone()] {
        m.set_margin_top(14);
        m.set_margin_bottom(16);
        m.set_margin_start(18);
        m.set_margin_end(18);
    }
    let auto: Vec<crate::depfix::Item> = items.iter().filter(|i| i.kind != K::Manual).cloned().collect();
    let manual: Vec<crate::depfix::Item> = items.iter().filter(|i| i.kind == K::Manual).cloned().collect();
    let intro = plain_label(if auto.is_empty() { "Aucune de ces corrections ne peut être faite automatiquement : voici ce qu'il faut changer à la main." } else { "Choisissez les mises à jour à appliquer. Python : seule la ligne épinglée (==) du fichier requirements est modifiée ; vos venv ne sont jamais touchés (installez ensuite vous-même). Chaque fichier est sauvegardé avant (« .cs-backup-… » à côté) et remis en état si une mise à jour échoue. Aucun script d'installation n'est lancé et aucun droit administrateur n'est utilisé. Testez vos projets ensuite." });
    content.append(&intro);

    let checks: Rc<Vec<(gtk::CheckButton, crate::depfix::Item)>> = Rc::new({
        let mut v = Vec::new();
        for it in &auto {
            let cb = gtk::CheckButton::new();
            cb.set_active(!it.major);
            cb.set_valign(gtk::Align::Start);
            let tl = gtk::Label::new(Some(&format!("{} {} → {}", it.name, it.version, it.fixed)));
            tl.set_xalign(0.0);
            tl.add_css_class("heading");
            let mut sub = vec![it.project()];
            sub.push(match it.kind {
                K::Npm => "npm".to_string(),
                K::NpmUpdate => t("npm update (dans les limites du projet)"),
                K::Pip => t("pip (fichier requirements seulement)"),
                _ => "cargo".to_string(),
            });
            if it.grave {
                sub.push(t("grave"));
            }
            if it.major {
                sub.push(t("⚠ saut de version majeure : peut casser le projet"));
            }
            let sl = gtk::Label::new(Some(&sub.join(" · ")));
            sl.set_xalign(0.0);
            sl.add_css_class("dim-label");
            sl.set_wrap(true);
            let col = gtk::Box::new(gtk::Orientation::Vertical, 1);
            col.append(&tl);
            col.append(&sl);
            let row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
            row.append(&cb);
            row.append(&col);
            row.set_margin_top(4);
            row.set_margin_bottom(4);
            v.push((cb, it.clone(), row));
        }
        let list = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let mut out = Vec::new();
        for (cb, it, row) in v {
            list.append(&row);
            out.push((cb, it));
        }
        let sw = gtk::ScrolledWindow::builder().child(&list).min_content_height(if auto.is_empty() { 0 } else { 260 }).vexpand(true).build();
        sw.set_visible(!auto.is_empty());
        content.append(&sw);
        out
    });
    if !manual.is_empty() {
        let h = plain_label("À faire à la main");
        h.add_css_class("heading");
        content.append(&h);
        let b = gtk::Box::new(gtk::Orientation::Vertical, 6);
        for it in manual.iter().take(30) {
            let l = gtk::Label::new(Some(&format!("{} {} → {} ({})\n{}{}", it.name, it.version, it.fixed, it.project(), t(&it.note), if it.command.is_empty() { String::new() } else { format!("\n$ {}", it.command) })));
            l.set_xalign(0.0);
            l.set_wrap(true);
            l.set_selectable(true);
            l.add_css_class("dim-label");
            b.append(&l);
        }
        let sw = gtk::ScrolledWindow::builder().child(&b).min_content_height(if auto.is_empty() { 260 } else { 90 }).max_content_height(200).build();
        content.append(&sw);
    }
    let log = gtk::TextView::builder().editable(false).monospace(true).wrap_mode(gtk::WrapMode::WordChar).build();
    let log_sw = gtk::ScrolledWindow::builder().child(&log).min_content_height(260).vexpand(true).build();
    log_sw.set_visible(false);
    content.append(&log_sw);
    let status = plain_label("");
    status.set_visible(false);
    content.append(&status);

    let go = gtk::Button::with_label(&t("Corriger la sélection"));
    go.add_css_class("suggested-action");
    go.set_visible(!auto.is_empty());
    let close = gtk::Button::with_label(&t("Annuler"));
    let btns = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    btns.set_halign(gtk::Align::End);
    btns.append(&close);
    btns.append(&go);
    content.append(&btns);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&content));
    let d = adw::Dialog::builder().title(t(title)).content_width(680).content_height(560).child(&toolbar).build();
    let then = Rc::new(std::cell::RefCell::new(Some(then)));
    d.connect_closed(move |_| {
        if let Some(f) = then.borrow_mut().take() {
            f();
        }
    });
    let d2 = d.clone();
    close.connect_clicked(move |_| {
        d2.close();
    });
    let (d3, checks2, log2, log_sw2, status2, close2) = (d.clone(), checks.clone(), log.clone(), log_sw.clone(), status.clone(), close.clone());
    let sync = {
        let (go, checks) = (go.clone(), checks.clone());
        Rc::new(move || go.set_sensitive(checks.iter().any(|(c, _)| c.is_active())))
    };
    for (c, _) in checks.iter() {
        let s = sync.clone();
        c.connect_toggled(move |_| s());
    }
    sync();
    go.connect_clicked(move |b| {
        let chosen: Vec<crate::depfix::Item> = checks2.iter().filter(|(c, _)| c.is_active()).map(|(_, i)| i.clone()).collect();
        if chosen.is_empty() {
            return;
        }
        b.set_visible(false);
        close2.set_sensitive(false);
        d3.set_can_close(false);
        for (c, _) in checks2.iter() {
            c.set_sensitive(false);
        }
        log_sw2.set_visible(true);
        status2.set_visible(true);
        status2.set_text(&crate::i18n::tr("Mise à jour en cours…"));
        let (tx, rx) = async_channel::unbounded::<Result<String, (usize, usize)>>();
        std::thread::spawn(move || {
            let txl = tx.clone();
            let r = crate::depfix::apply(&chosen, &mut |l| {
                let _ = txl.send_blocking(Ok(l));
            });
            let _ = tx.send_blocking(Err(r));
        });
        let (log3, status3, close3, d4) = (log2.clone(), status2.clone(), close2.clone(), d3.clone());
        glib::spawn_future_local(async move {
            while let Ok(m) = rx.recv().await {
                match m {
                    Ok(line) => {
                        let buf = log3.buffer();
                        buf.insert(&mut buf.end_iter(), &format!("{}\n", crate::i18n::tr(&line)));
                        let mark = buf.create_mark(None, &buf.end_iter(), false);
                        log3.scroll_mark_onscreen(&mark);
                    }
                    Err((ok, ko)) => {
                        status3.set_text(&(format!("{ok} {} · {ko} {}", crate::i18n::tr("mise(s) à jour réussie(s)"), crate::i18n::tr("échec(s)")) + &if ok > 0 { format!(" · {}", crate::i18n::tr("relancez « Analyser » pour vérifier")) } else { String::new() }));
                        status3.add_css_class(if ko == 0 { "success" } else { "error" });
                        break;
                    }
                }
            }
            close3.set_label(&crate::i18n::tr("Fermer"));
            close3.set_sensitive(true);
            d4.set_can_close(true);
        });
    });
    d.present(ctx.window().as_ref());
}

/// « Corriger » de la carte « Attaques réelles » : ces failles visent des logiciels installés (paquets du système, Flatpak).
/// S'il y a une mise à jour en attente pour l'un d'eux, on ouvre la mise à jour du système (aperçu et confirmation habituels) ;
/// sinon on explique honnêtement qu'il n'y a rien à installer pour l'instant.
pub fn fix_attacks(ctx: &Rc<Ctx>, names: Vec<String>, then: Box<dyn FnOnce()>) {
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        let ups = super::actions::pending(&ctx).await;
        let concerned: Vec<String> = names.iter().filter(|n| ups.iter().any(|u| &u.name == *n)).cloned().collect();
        if !concerned.is_empty() {
            system_update(&ctx, then);
            return;
        }
        let guard = Then(Some(then));
        let list = names.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
        let body = format!("{}\n\n{}", crate::i18n::tr("Aucune mise à jour n'est disponible pour :"), list) + "\n\n" + &crate::i18n::tr("Votre version est la plus récente des dépôts : il n'y a rien à installer pour l'instant. La liste CISA ne précise pas quelle version corrige la faille. Dès que les dépôts {distro} publieront un correctif, il apparaîtra dans « Mises à jour » et ici.").replace("{distro}", &crate::util::distro_name());
        let d = adw::AlertDialog::new(Some(&crate::i18n::tr("Rien à corriger pour l'instant")), Some(&body));
        d.add_response("close", &crate::i18n::tr("Fermer"));
        let _ = d.choose_future(ctx.window().as_ref()).await;
        drop(guard);
    });
}

// ───────────────────── mises à jour AUR (paru / yay) dans un terminal ─────────────────────

/// Script CONSTANT lancé dans le terminal : $1 = assistant AUR (chemin absolu), $2 = message de fin, $3 = invite, puis les paquets.
/// Sans paquet : « -Sua » (toutes les mises à jour AUR) ; sinon « -S -- paquets ». JAMAIS de --noconfirm ni --skipreview :
/// l'assistant montre les modifications du PKGBUILD et c'est l'utilisateur qui accepte, dans le terminal (le mot de passe y est saisi, l'application ne le voit pas).
pub const AUR_TERMINAL_SCRIPT: &str = r#"h="$1"; msg="$2"; press="$3"; shift 3
if [ "$#" -gt 0 ]; then "$h" -S -- "$@"; else "$h" -Sua; fi
rc=$?
printf '\n%s (code %s)\n' "$msg" "$rc"
printf '%s ' "$press"
read -r _
"#;

/// Terminaux connus : (programme, options avant la commande).
const TERMINALS: &[(&str, &[&str])] = &[
    ("konsole", &["-e"]),
    ("gnome-terminal", &["--"]),
    ("xfce4-terminal", &["-x"]),
    ("kitty", &[]),
    ("alacritty", &["-e"]),
    ("foot", &[]),
    ("wezterm", &["start", "--"]),
    ("xterm", &["-e"]),
];

fn aur_pkg_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 100 && !n.starts_with('-') && n.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

/// Ligne de commande complète (terminal + script + arguments), ou une erreur si un nom de paquet est suspect.
pub fn aur_terminal_argv(term: &str, term_flags: &[&str], helper: &str, packages: &[String], done: &str, press: &str) -> Result<Vec<String>, String> {
    if !helper.starts_with('/') || helper.contains('\n') {
        return Err("assistant AUR invalide".into());
    }
    if let Some(bad) = packages.iter().find(|p| !aur_pkg_ok(p)) {
        return Err(format!("nom de paquet invalide : {bad}"));
    }
    let mut v = vec![term.to_string()];
    v.extend(term_flags.iter().map(|s| s.to_string()));
    v.extend([crate::util::SH.to_string(), "-c".into(), AUR_TERMINAL_SCRIPT.into(), "sh".into(), helper.into(), done.into(), press.into()]);
    v.extend(packages.iter().cloned());
    Ok(v)
}

/// Met à jour des paquets AUR (ou tout l'AUR si `packages` est vide) dans un TERMINAL, après confirmation.
/// Le terminal montre les différences de PKGBUILD à relire ; l'utilisateur accepte et saisit son mot de passe là-bas.
pub fn aur_update(ctx: &Rc<Ctx>, helper: String, packages: Vec<String>, then: Box<dyn FnOnce()>) {
    let (parent, _ctx) = (ctx.window(), ctx.clone());
    glib::spawn_future_local(async move {
        let guard = Then(Some(then));
        let Some(hp) = abs_prog(&helper) else { return };
        let what = if packages.is_empty() { format!("{helper} -Sua") } else { format!("{helper} -S {}", packages.join(" ")) };
        let Some((term, flags)) = TERMINALS.iter().find_map(|(t, f)| abs_prog(t).map(|p| (p, *f))) else {
            if let Some(disp) = gtk::gdk::Display::default() {
                disp.clipboard().set_text(&what);
            }
            let d = alert("Aucun terminal trouvé", &format!("Aucun émulateur de terminal connu n'est installé. La commande a été copiée : collez-la dans le terminal de votre choix.\n\n{what}"), &[("close", "Fermer")]);
            let _ = d.choose_future(parent.as_ref()).await;
            return;
        };
        let t = |s: &str| crate::i18n::tr(s);
        let body = format!("{}\n\n{what}\n\n{}", t("Un terminal va s'ouvrir et lancer :"), t("• « {assistant} » affiche les modifications de chaque PKGBUILD : relisez-les avant d'accepter.\n• Le mot de passe est demandé dans ce terminal : l'application ne le voit jamais.\n• Les paquets AUR ne sont pas vérifiés par Arch : des paquets AUR ont été piégés en 2026.").replace("{assistant}", &helper));
        let d = adw::AlertDialog::new(Some(&t("Mettre à jour l'AUR")), Some(&body));
        d.add_response("cancel", &t("Annuler"));
        d.add_response("go", &t("Ouvrir le terminal"));
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }
        match aur_terminal_argv(&term.to_string_lossy(), flags, &hp.to_string_lossy(), &packages, &t("Terminé"), &t("Appuyez sur Entrée pour fermer cette fenêtre…")) {
            Ok(argv) => match std::process::Command::new(&argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
                Ok(mut child) => {
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                }
                Err(e) => {
                    let d = alert("Le terminal n'a pas pu s'ouvrir", &e.to_string(), &[("close", "Fermer")]);
                    let _ = d.choose_future(parent.as_ref()).await;
                }
            },
            Err(e) => {
                let d = alert("Paquet refusé", &e, &[("close", "Fermer")]);
                let _ = d.choose_future(parent.as_ref()).await;
            }
        }
        drop(guard);
    });
}

/// Mise à jour AUR DANS l'application : télécharge les recettes, fait RELIRE chaque PKGBUILD (texte complet + repères automatiques),
/// puis construit et installe exactement ce qui a été relu (makepkg ; les droits administrateur sont demandés par la fenêtre système pkexec).
pub fn aur_inapp(ctx: &Rc<Ctx>, names: Vec<String>, then: Box<dyn FnOnce()>) {
    let parent = ctx.window();
    glib::spawn_future_local(async move {
        let _guard = Then(Some(then));
        let t = |s: &str| crate::i18n::tr(s);
        let mut names: Vec<String> = names.into_iter().filter(|n| crate::aur::valid_name(n)).collect();
        names.dedup();
        if names.is_empty() {
            return;
        }
        if abs_prog("git").is_none() || abs_prog("makepkg").is_none() || abs_prog("env").is_none() {
            let d = alert("Outils manquants", "La mise à jour AUR dans l'application demande « git » et « makepkg » (paquets git et base-devel). Installez-les, ou utilisez « Mettre à jour dans un terminal ».", &[("close", "Fermer")]);
            let _ = d.choose_future(parent.as_ref()).await;
            return;
        }
        let d = alert(
            "Mettre à jour l'AUR ?",
            &format!("{}\n\n{}", names.join(", "), t("Étapes : 1) téléchargement des recettes (PKGBUILD) ; 2) VOUS relisez chacune ; 3) construction et installation de ce que vous avez relu.\n\nLes paquets AUR ne sont pas vérifiés par Arch : relisez attentivement, et ignorez tout paquet dont le script vous inquiète. Une fenêtre système vous demandera votre mot de passe pour l'installation (l'application ne le voit jamais).")),
            &[("cancel", "Annuler"), ("go", "Télécharger et relire")],
        );
        d.set_default_response(Some("cancel"));
        d.set_close_response("cancel");
        d.set_response_appearance("go", adw::ResponseAppearance::Suggested);
        if d.choose_future(parent.as_ref()).await != "go" {
            return;
        }

        // 1) téléchargement des recettes
        let dlg = CmdDialog::new(parent.as_ref(), "Téléchargement des recettes AUR", "git clone --depth 1 https://aur.archlinux.org/…");
        let total = names.len();
        let mut fetched: Vec<crate::aur::Fetched> = Vec::new();
        for (i, n) in names.iter().enumerate() {
            dlg.progress(i as f64 / total as f64, &format!("Téléchargement : {} / {}", i + 1, total));
            dlg.add(&format!("→ {n}"));
            let (tx, rx) = async_channel::bounded(1);
            let nn = n.clone();
            std::thread::spawn(move || {
                let _ = tx.send_blocking(crate::aur::fetch(&nn));
            });
            match rx.recv().await {
                Ok(Ok(f)) => fetched.push(f),
                Ok(Err(e)) => dlg.add(&format!("✘ {e}")),
                Err(_) => {}
            }
        }
        dlg.finish("Terminé");
        dlg.win.close();

        // 2) relecture, paquet par paquet
        let mut approved: Vec<usize> = Vec::new();
        for (i, f) in fetched.iter().enumerate() {
            if let Some(why) = &f.blocked {
                let d = alert(&format!("{} : refusé", f.name), why, &[("close", "Fermer")]);
                let _ = d.choose_future(parent.as_ref()).await;
                continue;
            }
            let mut text = String::new();
            for (n, c) in &f.files {
                text += &format!("──────── {n} ────────\n{c}\n\n");
            }
            if !f.others.is_empty() {
                text += &format!("──────── {} ────────\n{}\n", t("Autres fichiers (non affichés)"), f.others.join("\n"));
            }
            let view = gtk::TextView::new();
            view.set_editable(false);
            view.set_monospace(true);
            view.set_cursor_visible(false);
            view.buffer().set_text(&text);
            let sw = gtk::ScrolledWindow::builder().child(&view).min_content_height(300).min_content_width(640).build();
            let marks = if f.warnings.is_empty() { t("Aucun repère automatique : relisez quand même le texte ci-dessous.") } else { f.warnings.iter().map(|w| format!("• {}", t(w))).collect::<Vec<_>>().join("\n") };
            let head = format!("{} {}  ({} {}/{}, {} {})", f.name, f.version, t("paquet"), i + 1, fetched.len(), t("révision"), f.commit.chars().take(10).collect::<String>());
            let d = adw::AlertDialog::new(Some(&format!("{} {}", t("Relire avant d'installer :"), head)), Some(&format!("{marks}\n\n{}", t("Si un point vous inquiète ou si vous ne comprenez pas le script, choisissez « Ignorer ce paquet »."))));
            d.set_extra_child(Some(&sw));
            d.add_response("skip", &t("Ignorer ce paquet"));
            d.add_response("go", &t("J'ai relu : installer"));
            d.set_default_response(Some("skip"));
            d.set_close_response("skip");
            d.set_response_appearance("go", if f.warnings.iter().any(|w| w.starts_with('⚠')) { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested });
            if d.choose_future(parent.as_ref()).await == "go" {
                approved.push(i);
            }
        }
        if approved.is_empty() {
            for f in &fetched {
                crate::aur::cleanup(f);
            }
            return;
        }

        // 3) construction et installation de ce qui a été relu
        let dlg = CmdDialog::new(parent.as_ref(), "Installation des paquets AUR", "makepkg --syncdeps --install");
        dlg.notice("Une fenêtre système va demander votre mot de passe pour installer chaque paquet.");
        let n = approved.len();
        let mut failed = 0usize;
        for (k, &i) in approved.iter().enumerate() {
            let f = &fetched[i];
            dlg.add(&format!("\n══ {} ({}/{}) ══", f.name, k + 1, n));
            let setup = f.dir.parent().map(|p| p.to_path_buf()).ok_or_else(|| "dossier introuvable".to_string()).and_then(|p| crate::aur::write_makepkg_conf(&p).map_err(|e| e.to_string())).and_then(|c| crate::aur::build_plan(&c));
            let plan = match setup {
                Ok(p) => p,
                Err(e) => {
                    dlg.add(&format!("✘ {e}"));
                    failed += 1;
                    continue;
                }
            };
            let run = match runner::spawn(&plan, SCRIPT_NOISE, Some(f.dir.clone())) {
                Ok(r) => r,
                Err(e) => {
                    dlg.add(&format!("✘ {e}"));
                    failed += 1;
                    continue;
                }
            };
            dlg.progress(k as f64 / n as f64, &format!("Paquet {} / {} : {}", k + 1, n, f.name));
            while let Ok(msg) = run.rx.recv().await {
                match msg {
                    Msg::Line(l) => {
                        if let Some(s) = crate::aur::makepkg_stage(&l) {
                            dlg.progress((k as f64 + s) / n as f64, &format!("Paquet {} / {} : {}", k + 1, n, f.name));
                        }
                        dlg.add(&l);
                    }
                    Msg::Done { code, .. } => {
                        if code == 0 {
                            dlg.add(&format!("✔ {} installé", f.name));
                        } else {
                            failed += 1;
                            dlg.add(&format!("✘ {} : échec (code {code}). Si une dépendance vient aussi de l'AUR, mettez-la à jour d'abord.", f.name));
                        }
                        break;
                    }
                }
            }
        }
        for f in &fetched {
            crate::aur::cleanup(f);
        }
        if failed == 0 {
            dlg.finish("Terminé");
        } else {
            dlg.finish(&format!("Terminé avec {failed} échec(s)"));
        }
    });
}

#[cfg(test)]
mod tests_progress {
    use super::*;

    #[test]
    fn progression_pacman() {
        let mut p = PacProg::new(4);
        assert!(p.feed("core downloading...").is_none(), "les bases de données ne comptent pas");
        let a = p.feed("glibc-2.43-1-x86_64 downloading...").unwrap();
        assert!((a.0 - 0.125).abs() < 1e-9 && a.1.contains("1 / 4"));
        for n in ["a-1-1-x86_64", "b-1-1-any", "c-1-1-x86_64_v4"] {
            p.feed(&format!("{n} downloading..."));
        }
        assert_eq!(p.feed("d-1-1-any downloading..."), Some((0.5, "Téléchargement : 4 / 4".into())), "plafonné au total");
        assert_eq!(p.feed(":: Processing package changes...").unwrap().0, 0.5);
        let b = p.feed("(2/4) upgrading glibc").unwrap();
        assert!((b.0 - 0.75).abs() < 1e-9 && b.1.contains("2 / 4"));
        assert_eq!(p.feed("(4/4) installing foo").unwrap().0, 1.0);
        assert!(p.feed("(1/12) Arming ConditionNeedsUpdate...").is_none(), "les hooks ne comptent pas");
        assert!(p.feed("hello").is_none());
    }
}

#[cfg(test)]
mod tests_aur {
    use super::*;

    #[test]
    fn commande_terminal_sans_confirmation_automatique() {
        let v = aur_terminal_argv("/usr/bin/konsole", &["-e"], "/usr/bin/paru", &["example-bin".into()], "ok", "entrée").unwrap();
        assert_eq!(&v[..2], ["/usr/bin/konsole", "-e"]);
        assert_eq!(v[v.len() - 1], "example-bin");
        assert!(v.contains(&AUR_TERMINAL_SCRIPT.to_string()), "le script est constant, jamais modifié");
        assert!(!AUR_TERMINAL_SCRIPT.contains("noconfirm") && !AUR_TERMINAL_SCRIPT.contains("skipreview"), "la relecture du PKGBUILD n'est jamais court-circuitée");
        // tout l'AUR : aucun paquet passé, le script choisit -Sua
        assert!(aur_terminal_argv("/usr/bin/xterm", &["-e"], "/usr/bin/yay", &[], "ok", "p").is_ok());
    }

    #[test]
    fn noms_de_paquets_hostiles_refuses() {
        for bad in ["-rf", "a b", "a;b", "a\nb", "", "a/../b", "$(x)"] {
            assert!(aur_terminal_argv("/usr/bin/xterm", &["-e"], "/usr/bin/paru", &[bad.to_string()], "ok", "p").is_err(), "{bad:?}");
        }
        assert!(aur_terminal_argv("/usr/bin/xterm", &["-e"], "paru", &[], "ok", "p").is_err(), "chemin absolu obligatoire pour l'assistant");
    }
}

// ───────────────────── entretien après mise à jour (comme arch-update) ─────────────────────
//
// Enchaînement de « Corriger » : mise à jour → paquets orphelins → Flatpak inutilisés → cache de pacman → redémarrage du noyau
// → services à relancer. Chaque étape ne s'affiche que s'il y a quelque chose à faire, détaille ce qui sera fait et demande
// confirmation ; « Passer » la saute. Rien n'est jamais supprimé sans ce clic.

/// Lance une commande dans la fenêtre d'exécution et attend sa fin ; renvoie le code de sortie.
async fn run_wait(parent: Option<gtk::Window>, title: &str, plan: Plan, ok_note: &'static str, ko_note: &'static str) -> i32 {
    let (tx, rx) = async_channel::bounded::<i32>(1);
    run_command(parent, title, plan, None, move |dlg, code, _| {
        dlg.notice(if code == 0 { ok_note } else { ko_note });
        let _ = tx.send_blocking(code);
    });
    rx.recv().await.unwrap_or(-1)
}

/// Question à deux boutons : true si l'utilisateur confirme.
async fn confirm_step(parent: &Option<gtk::Window>, heading: &str, body: &str, skip: &str, go: &str, destructive: bool) -> bool {
    let d = alert(heading, body, &[("skip", skip), ("go", go)]);
    d.set_response_appearance("go", if destructive { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested });
    d.set_default_response(Some("skip"));
    d.set_close_response("skip");
    d.choose_future(parent.as_ref()).await == "go"
}

/// Résultat d'un calcul bloquant lancé hors du fil de l'interface.
async fn off_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = async_channel::bounded::<T>(1);
    std::thread::spawn(move || {
        let _ = tx.send_blocking(f());
    });
    rx.recv().await.ok()
}

fn bullets(items: &[String], max: usize) -> String {
    let shown = items.iter().take(max).map(|p| format!("• {p}")).collect::<Vec<_>>().join("\n");
    if items.len() > max { format!("{shown}\n… (+{})", items.len() - max) } else { shown }
}

async fn orphans_step(parent: &Option<gtk::Window>) {
    let Some(names) = off_thread(crate::maint::orphans).await else { return };
    if names.is_empty() {
        return;
    }
    let n2 = names.clone();
    let all = off_thread(move || crate::maint::removal_preview(&n2)).await.unwrap_or_default();
    let all = if all.is_empty() { names.clone() } else { all };
    let body = format!(
        "Ces paquets ne sont plus utilisés par aucun autre : ils ont été installés comme dépendances et plus rien n'en a besoin.\n\nSeront supprimés ({}) :\n{}\n\nLeurs fichiers de configuration sont supprimés aussi. Vous pourrez toujours les réinstaller avec pacman.",
        all.len(),
        bullets(&all, 25)
    );
    if !confirm_step(parent, "Supprimer les paquets orphelins ?", &body, "Passer", "Supprimer", true).await {
        return;
    }
    run_wait(parent.clone(), "Suppression des paquets orphelins", admin_args_plan(crate::maint::ORPHAN_SCRIPT, &names), "Paquets orphelins supprimés.", "Rien n'a été supprimé (autorisation refusée, paquet devenu utile ou erreur : voir ci-dessus).").await;
}

async fn flatpak_update_step(parent: &Option<gtk::Window>) {
    let Some(pending) = off_thread(crate::maint::flatpak_updates).await else { return };
    if pending.is_empty() {
        return;
    }
    let Some(fp) = abs_prog("flatpak") else { return };
    let body = format!("Des mises à jour sont disponibles pour vos applications Flatpak.\n\nSeront mises à jour ({}) :\n{}", pending.len(), bullets(&pending, 25));
    if !confirm_step(parent, "Mettre à jour les applications Flatpak ?", &body, "Passer", "Mettre à jour", false).await {
        return;
    }
    // Flatpak demande lui-même l'autorisation système au besoin (polkit) ; aucun mot de passe ne passe par l'application
    let plan = Plan { argv: vec![fp.to_string_lossy().into_owned(), "update".into(), "--noninteractive".into(), "-y".into()], elevated: false, out_flag: None, out_pos: 0 };
    run_wait(parent.clone(), "Mise à jour des applications Flatpak", plan, "Applications Flatpak mises à jour.", "Certaines applications Flatpak n'ont pas été mises à jour (autorisation refusée ou erreur : voir ci-dessus).").await;
}

async fn flatpak_unused_step(parent: &Option<gtk::Window>) {
    let Some(unused) = off_thread(crate::maint::flatpak_unused).await else { return };
    if unused.is_empty() {
        return;
    }
    let Some(fp) = abs_prog("flatpak") else { return };
    let body = format!("Ces éléments Flatpak ne sont plus utilisés par aucune application installée.\n\nSeront supprimés ({}) :\n{}", unused.len(), bullets(&unused, 25));
    if !confirm_step(parent, "Supprimer les éléments Flatpak inutilisés ?", &body, "Passer", "Supprimer", true).await {
        return;
    }
    let plan = Plan { argv: vec![fp.to_string_lossy().into_owned(), "uninstall".into(), "--unused".into(), "--noninteractive".into(), "-y".into()], elevated: false, out_flag: None, out_pos: 0 };
    run_wait(parent.clone(), "Suppression des éléments Flatpak inutilisés", plan, "Éléments Flatpak inutilisés supprimés.", "Rien n'a été supprimé (autorisation refusée ou erreur : voir ci-dessus).").await;
}

async fn cache_step(parent: &Option<gtk::Window>) {
    let n = off_thread(crate::maint::cache_candidates).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let body = format!("Le cache garde les archives de tous les paquets téléchargés : {n} archive(s) ancienne(s) ou de paquets désinstallés peuvent être supprimées.\n\nSeront supprimées : les versions anciennes (les 3 dernières de chaque paquet sont gardées) et les archives des paquets déjà désinstallés.\n\nVos programmes ne sont pas touchés ; seules les archives de retour en arrière disparaissent.");
    if !confirm_step(parent, "Nettoyer le cache de pacman ?", &body, "Passer", "Nettoyer", false).await {
        return;
    }
    run_wait(parent.clone(), "Nettoyage du cache de pacman", admin_script_plan(crate::clean::PACCACHE_SCRIPT), "Cache de pacman nettoyé.", "Rien n'a été nettoyé (autorisation refusée ou erreur : voir ci-dessus).").await;
}

async fn services_step(parent: &Option<gtk::Window>) {
    if abs_prog("checkservices").is_none() {
        return;
    }
    let (code, out) = run_capture(&admin_script_plan(crate::maint::SERVICES_LIST_SCRIPT)).await;
    if code != 0 {
        return;
    }
    let services: Vec<String> = out.lines().map(str::trim).filter(|l| crate::maint::valid_service(l)).map(String::from).collect();
    if services.is_empty() {
        return;
    }
    let body = format!("Ces services utilisent d'anciens fichiers remplacés par la mise à jour : ils doivent être relancés pour utiliser les nouvelles versions.\n\nSeront relancés ({}) :\n{}\n\nUn service relancé est coupé une seconde ; le gestionnaire de session (écran de connexion) n'est jamais relancé.", services.len(), bullets(&services, 25));
    if !confirm_step(parent, "Relancer les services mis à jour ?", &body, "Passer", "Relancer", false).await {
        return;
    }
    run_wait(parent.clone(), "Relance des services", admin_args_plan(crate::maint::SERVICES_RESTART_SCRIPT, &services), "Services relancés.", "Certains services n'ont pas été relancés (autorisation refusée ou erreur : voir ci-dessus).").await;
}

async fn reboot_step(ctx: &Rc<Ctx>) {
    if !off_thread(crate::maint::reboot_pending).await.unwrap_or(false) {
        return;
    }
    let (tx, rx) = async_channel::bounded::<()>(1);
    reboot(ctx, Box::new(move || {
        let _ = tx.send_blocking(());
    }));
    let _ = rx.recv().await;
}

/// Entretien complet. `updated` : des paquets viennent d'être installés (alors les services sont vérifiés aussi, comme arch-update).
pub fn maintenance_flow(ctx: &Rc<Ctx>, updated: bool, then: Box<dyn FnOnce()>) {
    let (ctx, parent) = (ctx.clone(), ctx.window());
    glib::spawn_future_local(async move {
        let _guard = Then(Some(then));
        if updated {
            flatpak_update_step(&parent).await;
        }
        orphans_step(&parent).await;
        flatpak_unused_step(&parent).await;
        cache_step(&parent).await;
        if updated {
            services_step(&parent).await;
        }
        reboot_step(&ctx).await;
    });
}
