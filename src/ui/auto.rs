//! Mises à jour automatiques des données de CVE (catalogue CISA, base Trivy) : sans droits administrateur,
//! sans fenêtre. Vérification À CHAQUE LANCEMENT (quelques secondes après l'ouverture), puis toutes les heures
//! pour les données de plus de 6 h. Trivy ne retélécharge sa base que si une version plus récente existe.

use super::Ctx;
use super::databases_page::step;
use super::dialogs::run_silent;
use super::global_page::GlobalPage;
use crate::util::{Stamp, now_unix};
use gtk4::glib;
use std::rc::Rc;

fn age(ctx: &Ctx, key: &str) -> i64 {
    ctx.state.borrow().db.get(key).filter(|s| s.ok).map(|s| now_unix() - s.time).unwrap_or(i64::MAX)
}

/// Met à jour les données plus vieilles que `max_hours` (0 = toujours vérifier). Renvoie true si tout est à jour à la fin.
pub async fn update_cve_data(ctx: &Rc<Ctx>, global: &Rc<GlobalPage>, max_hours: i64) -> bool {
    ctx.updating.set(ctx.updating.get() + 1);
    let limit = max_hours * 3600;
    let mut ok = true;
    if age(ctx, "kev") >= limit || !global.kev_loaded() {
        ok &= global.update_kev_async().await;
    }
    if age(ctx, "avg") >= limit {
        match super::global_page::fetch("https://security.archlinux.org/issues/all.json").await {
            Ok(text) if crate::tracker::parse(&text).len() > 100 => {
                let _ = crate::util::save_private("avg.json", text.as_bytes());
                ctx.state.borrow_mut().db.insert("avg".into(), Stamp { time: now_unix(), ok: true });
                ctx.save();
            }
            _ => ok = false,
        }
    }
    if age(ctx, "trivy") >= limit {
        match step("trivy") {
            Ok(s) => {
                let done = run_silent(&s.plan, s.ok_codes).await;
                ctx.state.borrow_mut().db.insert("trivy".into(), Stamp { time: now_unix(), ok: done });
                ctx.save();
                ok &= done;
            }
            Err(_) => ok = false,
        }
    }
    ctx.updating.set(ctx.updating.get().saturating_sub(1));
    ok
}

/// Signature stable d'un ensemble de mises à jour (noms + versions cibles) : sert à ne notifier qu'une fois chaque nouvel ensemble.
pub fn updates_signature(ups: &[crate::risk::Update], aur: &[crate::risk::Update]) -> String {
    let mut v: Vec<String> = ups.iter().map(|u| format!("{}={}", u.name, u.new)).chain(aur.iter().map(|u| format!("aur:{}={}", u.name, u.new))).collect();
    v.sort();
    v.join(";")
}

/// Texte de la notification : nombre de mises à jour, dont AUR et points sensibles.
pub fn updates_message(n: usize, n_aur: usize, risky: usize) -> (String, String) {
    use crate::i18n::tr;
    let title = if n + n_aur == 1 { tr("1 mise à jour disponible") } else { tr("{n} mises à jour disponibles").replace("{n}", &(n + n_aur).to_string()) };
    let mut body = tr("{n} dans les dépôts officiels").replace("{n}", &n.to_string());
    if n_aur > 0 {
        body += &format!(", {}", tr("{n} dans l'AUR (à relire avant d'installer)").replace("{n}", &n_aur.to_string()));
    }
    if risky > 0 {
        body += &format!(". {}", tr("{n} point(s) sensible(s) : vous serez prévenu avant l'installation").replace("{n}", &risky.to_string()));
    }
    body += &format!(". {}", tr("Ouvrez « Mises à jour » pour les installer."));
    (title, body)
}

/// Vérifie les mises à jour en lecture seule (checkupdates, paru/yay -Qua) et notifie UNE fois chaque nouvel ensemble.
pub fn check_updates(ctx: &Rc<Ctx>) {
    let (notif, tray) = { let st = ctx.state.borrow(); (st.settings.notifications, st.settings.tray) };
    if !notif && !tray {
        return;
    }
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        super::actions::invalidate_pending(&ctx);
        let ups = super::actions::pending(&ctx).await;
        let aur = super::actions::pending_aur().await;
        ctx.set_tray_updates(ups.len() + aur.len());
        if !ctx.state.borrow().settings.notifications {
            return;
        }
        if ups.is_empty() && aur.is_empty() {
            if !ctx.state.borrow().settings.notified_updates.is_empty() {
                ctx.state.borrow_mut().settings.notified_updates.clear();
                ctx.save();
            }
            return;
        }
        let sig = updates_signature(&ups, &aur);
        // déjà notifié : on ne répète que s'il y a du nouveau, ou en rappel après 24 h si tout est encore en attente
        let (same, at) = { let st = ctx.state.borrow(); (st.settings.notified_updates == sig, st.settings.notified_at) };
        if same && crate::util::now_unix() - at < 24 * 3600 {
            return;
        }
        let risky = crate::risk::assess(&ups).len();
        let (t, b) = updates_message(ups.len(), aur.len(), risky);
        ctx.notify_action("mises-a-jour", &t, &b, Some("app.show-updates"));
        ctx.state.borrow_mut().settings.notified_updates = sig;
        ctx.state.borrow_mut().settings.notified_at = crate::util::now_unix();
        ctx.save();
    });
}

/// Démarre la mise à jour automatique (désactivable dans l'interface).
pub fn start(ctx: Rc<Ctx>, global: Rc<GlobalPage>) {
    // notification des mises à jour : peu après le lancement, puis toutes les heures
    let c0 = ctx.clone();
    glib::timeout_add_seconds_local_once(20, move || check_updates(&c0));
    let c1 = ctx.clone();
    glib::timeout_add_seconds_local(3600, move || {
        check_updates(&c1);
        glib::ControlFlow::Continue
    });
    // à chaque lancement : vérification immédiate (0 h) ; ensuite, toutes les heures, seulement si les données ont plus de 6 h
    let run = |ctx: Rc<Ctx>, global: Rc<GlobalPage>, max_hours: i64| {
        if !ctx.state.borrow().settings.auto_update {
            return;
        }
        glib::spawn_future_local(async move {
            update_cve_data(&ctx, &global, max_hours).await;
        });
    };
    let (c1, g1) = (ctx.clone(), global.clone());
    glib::timeout_add_seconds_local_once(3, move || run(c1, g1, 0));
    glib::timeout_add_seconds_local(3600, move || {
        run(ctx.clone(), global.clone(), 6);
        glib::ControlFlow::Continue
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Update;
    fn u(n: &str, v: &str) -> Update {
        Update { name: n.into(), old: "1".into(), new: v.into() }
    }

    #[test]
    fn signature_stable_et_sensible_aux_versions() {
        let a = updates_signature(&[u("b", "2"), u("a", "3")], &[u("x", "1")]);
        assert_eq!(a, updates_signature(&[u("a", "3"), u("b", "2")], &[u("x", "1")]), "indépendante de l'ordre");
        assert_ne!(a, updates_signature(&[u("a", "4"), u("b", "2")], &[u("x", "1")]), "une nouvelle version = nouvelle notification");
        assert_ne!(updates_signature(&[u("x", "1")], &[]), updates_signature(&[], &[u("x", "1")]), "AUR distingué du dépôt");
    }

    #[test]
    fn message_de_notification() {
        let (t, b) = updates_message(3, 2, 1);
        assert!(t.contains("5") && b.contains("3") && b.contains("2") && b.contains("1"));
        assert!(updates_message(1, 0, 0).0.contains("1 "));
    }
}
