//! Page générique d'un outil : options, résultats, sortie brute, commande exécutée.

use super::options::Panel;
use super::results::{Results, tool_sev};
use super::{Ctx, plain_label, when};
use crate::model::ScanResult;
use crate::runner::{self, Msg};
use crate::tools::{Tool, Values};
use crate::util::Saved;
use gtk4 as gtk;
use gtk::{gio, glib, prelude::*};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

type DoneCb = Box<dyn Fn(&str, &ScanResult)>;

/// Avancement d'une analyse, pour les bandeaux de progression des modules.
#[derive(Clone, Debug)]
pub enum Progress {
    /// L'analyse démarre ; `elevated` = elle attend d'abord le mot de passe administrateur.
    Start { elevated: bool },
    /// Dernière ligne de sortie (l'analyse avance).
    Line(String),
    End,
}

type ProgressCb = Box<dyn Fn(&Progress)>;

pub struct ToolPage {
    pub tool: Tool,
    pub ctx: Rc<Ctx>,
    pub root: gtk::Box,
    pub panel: Panel,
    results: Rc<Results>,
    console: gtk::TextView,
    cmdview: gtk::TextView,
    tabs: gtk::Notebook,
    run_btn: gtk::Button,
    stop_btn: gtk::Button,
    spinner: gtk::Spinner,
    status: gtk::Label,
    bar: gtk::Box,
    cancel: RefCell<Option<Arc<AtomicBool>>>,
    done_cbs: RefCell<Vec<DoneCb>>,
    waiters: RefCell<Vec<async_channel::Sender<ScanResult>>>,
    progress_cbs: RefCell<Vec<ProgressCb>>,
    last_error: RefCell<Option<String>>,
}

fn text_view() -> gtk::TextView {
    let t = gtk::TextView::new();
    t.set_editable(false);
    t.set_cursor_visible(false);
    t.set_monospace(true);
    t.set_wrap_mode(gtk::WrapMode::WordChar);
    t.set_left_margin(8);
    t.set_top_margin(8);
    t
}

fn scrolled(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder().child(child).hexpand(true).vexpand(true).build()
}

impl ToolPage {
    pub fn new(ctx: Rc<Ctx>, tool: Tool) -> Rc<ToolPage> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
        for f in [gtk::Box::set_margin_start, gtk::Box::set_margin_end] {
            f(&root, 24);
        }
        root.set_margin_top(20);
        root.set_margin_bottom(16);

        let title = gtk::Label::new(Some(crate::i18n::tr(tool.title).as_str()));
        title.add_css_class("title-2");
        title.set_xalign(0.0);
        title.set_use_markup(false);
        let desc = plain_label(tool.desc);
        desc.add_css_class("dim-label");
        root.append(&title);
        root.append(&desc);

        let notice = plain_label(&(tool.notice)().unwrap_or_default());
        notice.add_css_class("warning");
        notice.set_visible(!notice.text().is_empty());
        root.append(&notice);

        let cmd_refresh: Rc<RefCell<Option<Box<dyn Fn()>>>> = Rc::new(RefCell::new(None));
        let cr = cmd_refresh.clone();
        let on_change: Rc<dyn Fn()> = Rc::new(move || {
            if let Some(f) = cr.borrow().as_ref() {
                f();
            }
        });
        let panel = Panel::new(&(tool.options)(), on_change);

        let results = Results::new(tool.columns, tool.widths, tool.sev_col.map(|c| (c, tool_sev as _)));
        let console = text_view();
        let cmdview = text_view();
        let tabs = gtk::Notebook::new();
        tabs.append_page(&results.widget, Some(&gtk::Label::new(Some(crate::i18n::tr("Résultats").as_str()))));
        tabs.append_page(&scrolled(&console), Some(&gtk::Label::new(Some(crate::i18n::tr("Sortie brute").as_str()))));
        tabs.append_page(&scrolled(&cmdview), Some(&gtk::Label::new(Some(crate::i18n::tr("Commande").as_str()))));
        tabs.set_vexpand(true);

        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("Filtrer les résultats…"));
        let r2 = results.clone();
        search.connect_search_changed(move |s| r2.set_filter(&s.text()));

        let left = gtk::Box::new(gtk::Orientation::Vertical, 8);
        left.append(&search);
        left.append(&tabs);

        let opts = gtk::ScrolledWindow::builder().child(&panel.root).hscrollbar_policy(gtk::PolicyType::Never).min_content_width(360).build();
        let paned = gtk::Paned::new(gtk::Orientation::Horizontal);
        paned.set_start_child(Some(&left));
        paned.set_end_child(Some(&opts));
        paned.set_resize_start_child(true);
        paned.set_shrink_start_child(false);
        paned.set_vexpand(true);
        root.append(&paned);

        let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        let run_btn = gtk::Button::with_label(&crate::i18n::tr("Lancer l'analyse"));
        run_btn.add_css_class("suggested-action");
        let stop_btn = gtk::Button::with_label(&crate::i18n::tr("Arrêter"));
        stop_btn.set_sensitive(false);
        let spinner = gtk::Spinner::new();
        let status = gtk::Label::new(Some(crate::i18n::tr("Prêt").as_str()));
        status.add_css_class("dim-label");
        status.set_hexpand(true);
        status.set_xalign(1.0);
        status.set_ellipsize(gtk::pango::EllipsizeMode::End);
        bar.append(&run_btn);
        bar.append(&stop_btn);
        bar.append(&spinner);
        bar.append(&status);
        root.append(&bar);

        let page = Rc::new(ToolPage {
            tool,
            ctx,
            root,
            panel,
            results,
            console,
            cmdview,
            tabs,
            run_btn,
            stop_btn,
            spinner,
            status,
            bar,
            cancel: RefCell::new(None),
            done_cbs: RefCell::new(vec![]),
            waiters: RefCell::new(vec![]),
            progress_cbs: RefCell::new(vec![]),
            last_error: RefCell::new(None),
        });

        let p = page.clone();
        *cmd_refresh.borrow_mut() = Some(Box::new(move || p.refresh_preview()));
        let p = page.clone();
        page.run_btn.connect_clicked(move |_| {
            p.run();
        });
        let p = page.clone();
        page.stop_btn.connect_clicked(move |_| {
            if let Some(c) = p.cancel.borrow().as_ref() {
                c.store(true, Ordering::Relaxed);
            }
        });
        if let Some((col, f)) = page.tool.link {
            let p = page.clone();
            page.results.view.connect_activate(move |_, pos| {
                let url = p.results.row_at(pos).and_then(|r| f(r.get(col)?));
                if let Some(u) = url.filter(|u| u.starts_with("https://")) {
                    let _ = gio::AppInfo::launch_default_for_uri(&u, None::<&gio::AppLaunchContext>);
                }
            });
        }
        // résultats précédents
        if let Some(s) = page.ctx.state.borrow().tools.get(page.tool.key) {
            page.results.set_rows(&s.rows);
            page.status.set_text(&when(s.result.time));
        }
        page.refresh_preview();
        page
    }

    pub fn values(&self) -> Values {
        self.panel.values()
    }

    pub fn add_button(&self, b: &gtk::Button) {
        self.bar.insert_child_after(b, Some(&self.stop_btn));
    }

    pub fn is_running(&self) -> bool {
        self.cancel.borrow().is_some()
    }

    pub fn on_done(&self, f: impl Fn(&str, &ScanResult) + 'static) {
        self.done_cbs.borrow_mut().push(Box::new(f));
    }

    /// Lance l'analyse et attend sa fin (None si elle n'a pas pu démarrer).
    pub async fn run_await(self: &Rc<Self>) -> Option<ScanResult> {
        let (tx, rx) = async_channel::bounded(1);
        self.waiters.borrow_mut().push(tx);
        if !self.run() {
            self.waiters.borrow_mut().pop();
            return None;
        }
        rx.recv().await.ok()
    }

    /// Raison pour laquelle la dernière analyse n'a pas pu démarrer (option invalide, outil absent…).
    pub fn last_error(&self) -> Option<String> {
        self.last_error.borrow().clone()
    }

    /// Demande l'arrêt de l'analyse en cours (sans effet sur une analyse administrateur).
    pub fn stop(&self) {
        if let Some(c) = self.cancel.borrow().as_ref() {
            c.store(true, Ordering::Relaxed);
        }
    }

    fn refresh_preview(&self) {
        let text = match (self.tool.build)(&self.panel.values()) {
            Ok(plan) => runner::preview(&plan),
            Err(e) => format!("(option invalide : {e})"),
        };
        self.cmdview.buffer().set_text(&text);
    }

    pub fn on_progress(&self, f: impl Fn(&Progress) + 'static) {
        self.progress_cbs.borrow_mut().push(Box::new(f));
    }

    pub fn emit(&self, p: Progress) {
        for cb in self.progress_cbs.borrow().iter() {
            cb(&p);
        }
    }

    fn append(&self, line: &str) {
        let t = line.trim();
        if !t.is_empty() {
            self.emit(Progress::Line(t.chars().take(140).map(|c| if c.is_control() { ' ' } else { c }).collect()));
        }
        let buf = self.console.buffer();
        if buf.char_count() > 3_000_000 {
            let mut start = buf.start_iter();
            let mut mid = buf.iter_at_offset(1_500_000);
            buf.delete(&mut start, &mut mid);
        }
        let mut end = buf.end_iter();
        buf.insert(&mut end, line);
        buf.insert(&mut end, "\n");
    }

    pub fn run(self: &Rc<Self>) -> bool {
        if self.is_running() {
            return false;
        }
        let values = self.panel.values();
        let plan = match (self.tool.build)(&values) {
            Ok(p) => p,
            Err(e) => {
                self.status.set_text(&e);
                *self.last_error.borrow_mut() = Some(e);
                return false;
            }
        };
        let running = match runner::spawn(&plan, self.tool.noise, None) {
            Ok(r) => r,
            Err(e) => {
                self.status.set_text(&e);
                *self.last_error.borrow_mut() = Some(e);
                return false;
            }
        };
        *self.last_error.borrow_mut() = None;
        self.console.buffer().set_text("");
        self.cmdview.buffer().set_text(&runner::preview(&plan));
        *self.cancel.borrow_mut() = Some(running.cancel.clone());
        self.run_btn.set_sensitive(false);
        // un processus lancé en root via pkexec ne peut pas être interrompu proprement depuis l'application
        self.stop_btn.set_sensitive(!plan.elevated);
        self.stop_btn.set_tooltip_text(plan.elevated.then_some("Une analyse administrateur ne peut pas être interrompue ici."));
        self.spinner.start();
        self.status.set_text(&crate::i18n::tr("Analyse en cours…"));
        {
            let (me, t0) = (self.clone(), std::time::Instant::now());
            glib::timeout_add_seconds_local(1, move || {
                if !me.is_running() {
                    return glib::ControlFlow::Break;
                }
                me.status.set_text(&format!("{} ({} s)", crate::i18n::tr("Analyse en cours…"), t0.elapsed().as_secs()));
                glib::ControlFlow::Continue
            });
        }
        self.tabs.set_current_page(Some(1));
        self.emit(Progress::Start { elevated: plan.elevated && crate::privileged::session().is_none() });

        let me = self.clone();
        let rx = running.rx;
        glib::spawn_future_local(async move {
            while let Ok(msg) = rx.recv().await {
                match msg {
                    Msg::Line(l) => me.append(&l),
                    Msg::Done { code, blob, text, .. } => {
                        me.finish(&values, code, blob, &text);
                        break;
                    }
                }
            }
        });
        true
    }

    /// Enregistre le résultat d'une analyse exécutée ailleurs (ex. lot administrateur : une seule autorisation pour plusieurs outils).
    pub fn ingest(&self, values: &Values, code: i32, blob: Option<String>, text: &str) {
        self.finish(values, code, blob, text);
    }

    fn finish(&self, values: &Values, code: i32, blob: Option<String>, text: &str) {
        *self.cancel.borrow_mut() = None;
        self.run_btn.set_sensitive(true);
        self.stop_btn.set_sensitive(false);
        self.spinner.stop();
        let outcome = (self.tool.parse)(values, text, blob.as_deref());
        self.results.set_rows(&outcome.rows);
        // un échec (sortie illisible, aucun résultat) ne remplace jamais un résultat valide précédent
        let failed = outcome.rows.is_empty() && outcome.result.time == 0 && (outcome.result.headline.starts_with("Aucun résultat") || outcome.result.headline.starts_with("Résultat illisible") || outcome.result.headline.starts_with("Analyse non terminée"));
        let had_good = self.ctx.state.borrow().tools.get(self.tool.key).is_some_and(|s| !s.rows.is_empty());
        if !(failed && had_good) {
            self.ctx.state.borrow_mut().tools.insert(self.tool.key.to_string(), Saved { result: outcome.result.clone(), rows: outcome.rows.clone() });
            self.ctx.save();
        }
        let _ = code;
        self.status.set_text(&format!("Terminé — {}", outcome.result.headline));
        self.tabs.set_current_page(Some(if outcome.rows.is_empty() { 1 } else { 0 }));
        self.emit(Progress::End);
        for cb in self.done_cbs.borrow().iter() {
            cb(self.tool.key, &outcome.result);
        }
        for w in self.waiters.borrow_mut().drain(..) {
            let _ = w.try_send(outcome.result.clone());
        }
    }
}
