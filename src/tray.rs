//! Icône dans la zone de notification (StatusNotifierItem : KDE Plasma, GNOME avec extension, XFCE, Sway/waybar…).
//! Elle ne fait que demander à la fenêtre principale d'agir : aucune action sur le système n'est lancée d'ici.
//! Quand des mises à jour attendent, l'icône passe en « attention » et le menu affiche leur nombre en tête.

use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};

/// Ce que l'icône demande à l'interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Open,
    Page(&'static str),
    Quit,
}

pub struct AppTray {
    tx: async_channel::Sender<Cmd>,
    /// Mises à jour en attente (dépôts officiels + AUR) ; 0 = à jour.
    pub updates: usize,
}

/// Poignée pour modifier l'icône après son démarrage (nombre de mises à jour).
pub type Handle = ksni::blocking::Handle<AppTray>;

fn entry(label: &str, icon: &str, cmd: Cmd) -> MenuItem<AppTray> {
    StandardItem {
        label: crate::i18n::tr(label),
        icon_name: icon.into(),
        activate: Box::new(move |t: &mut AppTray| {
            let _ = t.tx.try_send(cmd);
        }),
        ..Default::default()
    }
    .into()
}

/// Entrée du menu : nom de la page de la fenêtre, texte, icône.
const PAGES: [(&str, &str, &str); 6] = [
    ("failles", "Failles", "dialog-warning-symbolic"),
    ("maj", "Mises à jour", "software-update-available-symbolic"),
    ("protection", "Protection", "security-high-symbolic"),
    ("clean", "Nettoyage", "user-trash-symbolic"),
    ("reseau", "Réseau", "network-wired-symbolic"),
    ("config", "Configuration", "preferences-system-symbolic"),
];

impl ksni::Tray for AppTray {
    fn id(&self) -> String {
        "cachy-shield".into()
    }
    fn title(&self) -> String {
        crate::i18n::tr("Cachy Shield")
    }
    fn icon_name(&self) -> String {
        "cachy-shield".into()
    }
    fn attention_icon_name(&self) -> String {
        "cachy-shield-attention".into()
    }
    fn status(&self) -> ksni::Status {
        if self.updates > 0 { ksni::Status::NeedsAttention } else { ksni::Status::Active }
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            icon_name: if self.updates > 0 { "cachy-shield-attention" } else { "cachy-shield" }.into(),
            title: crate::i18n::tr("Cachy Shield"),
            description: if self.updates > 0 { updates_label(self.updates) } else { String::new() },
            ..Default::default()
        }
    }
    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }
    /// Clic gauche : ouvrir la fenêtre.
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.try_send(Cmd::Open);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut m = Vec::new();
        if self.updates > 0 {
            m.push(entry(&updates_label(self.updates), "software-update-available-symbolic", Cmd::Page("maj")));
            m.push(MenuItem::Separator);
        }
        m.push(entry("Ouvrir", "window-new-symbolic", Cmd::Open));
        m.push(entry("Analyser", "starred-symbolic", Cmd::Page("smart")));
        m.push(MenuItem::Separator);
        for (page, label, icon) in PAGES {
            m.push(entry(label, icon, Cmd::Page(page)));
        }
        m.push(MenuItem::Separator);
        m.push(entry("Quitter", "application-exit-symbolic", Cmd::Quit));
        m
    }
}

/// « 3 mises à jour disponibles » (traduit, singulier ou pluriel selon le nombre).
pub fn updates_label(n: usize) -> String {
    if n == 1 { crate::i18n::tr("1 mise à jour disponible") } else { crate::i18n::tr("{n} mises à jour disponibles").replace("{n}", &n.to_string()) }
}

/// Démarre l'icône. Renvoie une erreur (sans conséquence) si le bureau n'offre pas de zone de notification.
/// La poignée renvoyée doit rester vivante tant que l'icône doit exister.
pub fn start(tx: async_channel::Sender<Cmd>) -> Result<Handle, String> {
    AppTray { tx, updates: 0 }.spawn().map_err(|e| e.to_string())
}
