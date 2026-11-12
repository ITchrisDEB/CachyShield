//! Tableau de résultats (ColumnView) : tri, filtre, couleurs de gravité.

use gtk4 as gtk;
use gtk::{gio, glib, pango, prelude::*};
use std::cell::RefCell;
use std::rc::Rc;

const SEP: char = '\u{1f}';

/// (colonne, fonction : valeur de la cellule -> (libellé, classe CSS, rang de tri))
pub type SevFn = fn(&str) -> (String, &'static str, u8);

pub struct Results {
    pub widget: gtk::ScrolledWindow,
    pub view: gtk::ColumnView,
    store: gtk::StringList,
    filter: gtk::CustomFilter,
    needle: Rc<RefCell<String>>,
    pub selection: gtk::SingleSelection,
}

fn field(s: &str, i: usize) -> &str {
    s.split(SEP).nth(i).unwrap_or("")
}

impl Results {
    pub fn new(columns: &[&str], widths: &[i32], sev: Option<(usize, SevFn)>) -> Rc<Results> {
        let store = gtk::StringList::new(&[]);
        let needle = Rc::new(RefCell::new(String::new()));
        let n2 = needle.clone();
        let filter = gtk::CustomFilter::new(move |o| {
            let n = n2.borrow();
            n.is_empty() || o.downcast_ref::<gtk::StringObject>().is_some_and(|s| s.string().to_lowercase().contains(n.as_str()))
        });
        let view = gtk::ColumnView::new(None::<gtk::SelectionModel>);
        view.set_show_row_separators(true);
        view.set_reorderable(false);
        let mut first_sev_col = None;

        for (i, title) in columns.iter().enumerate() {
            let factory = gtk::SignalListItemFactory::new();
            factory.connect_setup(|_, item| {
                let item = item.downcast_ref::<gtk::ListItem>().expect("ListItem");
                let l = gtk::Label::new(None);
                l.set_use_markup(false);
                l.set_xalign(0.0);
                l.set_halign(gtk::Align::Start);
                l.set_ellipsize(pango::EllipsizeMode::End);
                l.set_margin_top(4);
                l.set_margin_bottom(4);
                item.set_child(Some(&l));
            });
            let sev_here = sev.filter(|(c, _)| *c == i).map(|(_, f)| f);
            factory.connect_bind(move |_, item| {
                let item = item.downcast_ref::<gtk::ListItem>().expect("ListItem");
                let (Some(obj), Some(l)) = (item.item().and_downcast::<gtk::StringObject>(), item.child().and_downcast::<gtk::Label>()) else { return };
                let text = obj.string();
                let raw = field(&text, i);
                for c in ["sev-pill", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-ok", "sev-unknown"] {
                    l.remove_css_class(c);
                }
                match sev_here {
                    Some(f) => {
                        let (label, css, _) = f(raw);
                        l.set_text(&label);
                        if !css.is_empty() {
                            l.add_css_class("sev-pill");
                            l.add_css_class(css);
                        }
                    }
                    None => l.set_text(raw),
                }
                l.set_tooltip_text(Some(raw));
            });
            let col = gtk::ColumnViewColumn::new(Some(title), Some(factory));
            col.set_resizable(true);
            col.set_fixed_width(widths.get(i).copied().unwrap_or(120));
            let sev_fn = sev.filter(|(c, _)| *c == i).map(|(_, f)| f);
            col.set_sorter(Some(&gtk::CustomSorter::new(move |a, b| {
                let get = |o: &glib::Object| o.downcast_ref::<gtk::StringObject>().map(|s| field(&s.string(), i).to_string()).unwrap_or_default();
                let (x, y) = (get(a), get(b));
                let ord = if let Some(f) = sev_fn {
                    f(&x).2.cmp(&f(&y).2)
                } else if let (Ok(p), Ok(q)) = (x.parse::<f64>(), y.parse::<f64>()) {
                    p.partial_cmp(&q).unwrap_or(std::cmp::Ordering::Equal)
                } else {
                    x.to_lowercase().cmp(&y.to_lowercase())
                };
                ord.into()
            })));
            view.append_column(&col);
            if sev_here.is_some() {
                first_sev_col = Some(col);
            }
        }

        let filtered = gtk::FilterListModel::new(Some(store.clone()), Some(filter.clone()));
        let sorted = gtk::SortListModel::new(Some(filtered), view.sorter());
        let selection = gtk::SingleSelection::new(Some(sorted));
        selection.set_autoselect(false);
        selection.set_can_unselect(true);
        view.set_model(Some(&selection));
        if let Some(c) = first_sev_col {
            view.sort_by_column(Some(&c), gtk::SortType::Ascending);
        }
        let widget = gtk::ScrolledWindow::builder().child(&view).hexpand(true).vexpand(true).build();
        Rc::new(Results { widget, view, store, filter, needle, selection })
    }

    pub fn set_rows(&self, rows: &[Vec<String>]) {
        let enc: Vec<String> = rows.iter().map(|r| r.iter().map(|c| c.replace(SEP, " ")).collect::<Vec<_>>().join(&SEP.to_string())).collect();
        let refs: Vec<&str> = enc.iter().map(String::as_str).collect();
        self.store.splice(0, self.store.n_items(), &refs);
    }

    pub fn set_filter(&self, text: &str) {
        *self.needle.borrow_mut() = text.trim().to_lowercase();
        self.filter.changed(gtk::FilterChange::Different);
    }

    pub fn row_at(&self, pos: u32) -> Option<Vec<String>> {
        let obj = self.selection.item(pos)?.downcast::<gtk::StringObject>().ok()?;
        Some(obj.string().split(SEP).map(String::from).collect())
    }

    pub fn selected(&self) -> Option<Vec<String>> {
        let pos = self.selection.selected();
        (pos != gtk::INVALID_LIST_POSITION).then(|| self.row_at(pos)).flatten()
    }

    #[allow(dead_code)]
    pub fn model(&self) -> gio::ListModel {
        self.selection.clone().upcast()
    }
}

/// Gravité des outils : la cellule contient la clé (critical, high…).
pub fn tool_sev(key: &str) -> (String, &'static str, u8) {
    let (label, rank) = crate::model::sev_info(key);
    (label.to_string(), crate::model::sev_css(key), rank)
}
