//! Langue de l'interface : suit la langue du système (KDE, GNOME, XFCE, Sway… sous X11 comme sous Wayland), car tous
//! les bureaux exportent la locale dans LANGUAGE / LC_ALL / LC_MESSAGES / LANG. Le texte source du programme est en
//! français ; `tr()` le remplace par sa traduction si elle existe, sinon laisse le français (jamais de texte vide).
//!
//! Traduction COMPLÈTE par trois mécanismes :
//!  1. textes exacts ;
//!  2. règles à motifs (`~motif` TAB `remplacement`, captures $1, $2…) pour les phrases construites avec des chiffres ou des noms ;
//!  3. découpage : un long texte est traduit ligne par ligne (puces « • », « ✔ »… conservées), puis segment par segment (« · »).
//!
//! Langues : le français est la langue d'origine, l'anglais est fourni. Toute autre langue s'ajoute SANS recompiler en
//! déposant `~/.config/cachy-shield/lang/<code>.tsv` (mêmes règles : `texte français` TAB `traduction`).

use regex::{Regex, RegexSet};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Code de langue principal d'une valeur de locale : « fr_FR.UTF-8@euro » -> « fr ». « C », « POSIX », vide : aucune langue.
pub fn parse_locale(v: &str) -> Option<String> {
    let first = v.split(':').next().unwrap_or("").trim();
    let base = first.split(['.', '@']).next().unwrap_or("");
    let lang = base.split(['_', '-']).next().unwrap_or("").to_lowercase();
    if lang.is_empty() || lang == "c" || lang == "posix" || !lang.chars().all(|c| c.is_ascii_alphabetic()) || lang.len() > 3 {
        return None;
    }
    Some(lang)
}

/// Ordre standard de POSIX/gettext : LANGUAGE, puis LC_ALL, LC_MESSAGES, LANG. `CACHY_SHIELD_LANG` force un choix.
pub fn detect(get: &dyn Fn(&str) -> Option<String>) -> String {
    for var in ["CACHY_SHIELD_LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(l) = get(var).and_then(|v| parse_locale(&v)) {
            return l;
        }
    }
    "en".into() // aucune langue définie : anglais, langue internationale par défaut
}

#[derive(Default)]
pub struct Catalog {
    exact: HashMap<String, String>,
    rules: Vec<(Regex, String)>,
    /// Tous les motifs d'un seul coup : un texte qui ne correspond à aucune règle est écarté en un seul passage (au lieu d'essayer chaque règle).
    set: Option<RegexSet>,
}

impl Catalog {
    pub fn from_tsv(text: &str) -> Catalog {
        let mut c = Catalog::default();
        for (k, v) in text.lines().filter_map(|l| l.split_once('\t')).filter(|(k, v)| !k.is_empty() && !v.is_empty()) {
            match k.strip_prefix('~') {
                Some(pat) => {
                    if let Ok(re) = Regex::new(pat) {
                        c.rules.push((re, v.replace("\\n", "\n")));
                    }
                }
                None => {
                    c.exact.insert(k.to_string(), v.replace("\\n", "\n"));
                }
            }
        }
        c.index();
        c
    }

    fn index(&mut self) {
        self.set = RegexSet::new(self.rules.iter().map(|(r, _)| r.as_str())).ok();
    }

    /// Catalogue construit à partir de paires (texte français, traduction) ; même règle que `from_tsv`.
    pub fn from_pairs(pairs: &[(String, String)]) -> Catalog {
        let mut c = Catalog::default();
        for (k, v) in pairs.iter().filter(|(k, v)| !k.is_empty() && !v.is_empty()) {
            match k.strip_prefix('~') {
                Some(pat) => {
                    if let Ok(re) = Regex::new(pat) {
                        c.rules.push((re, v.replace("\\n", "\n")));
                    }
                }
                None => {
                    c.exact.insert(k.to_string(), v.replace("\\n", "\n"));
                }
            }
        }
        c.index();
        c
    }

    fn extend(&mut self, o: Catalog) {

        self.exact.extend(o.exact);
        let mut rules = o.rules;
        rules.append(&mut self.rules); // les règles de l'utilisateur passent d'abord
        self.rules = rules;
        self.index();
    }

    fn atom(&self, s: &str) -> Option<String> {
        if let Some(t) = self.exact.get(s) {
            return Some(t.clone());
        }
        // première règle qui correspond (même résultat qu'un essai règle par règle, bien plus rapide quand rien ne correspond)
        let first = match &self.set {
            Some(set) => Some(set.matches(s).iter().next()?),
            None => None,
        };
        let candidates: Box<dyn Iterator<Item = &(Regex, String)>> = match first {
            Some(i) => Box::new(self.rules.iter().skip(i)),
            None => Box::new(self.rules.iter()),
        };
        candidates.into_iter().find_map(|(re, rep)| {
            let c = re.captures(s)?;
            let m = c.get(0)?;
            // les parties variables (« $1 », « ${2} ») sont elles-mêmes traduites si elles sont connues (raisons, noms de tâches…)
            let mut out = rep.clone();
            for i in (1..c.len()).rev() {
                let t = self.translate(c.get(i).map_or("", |g| g.as_str()));
                out = out.replace(&format!("${{{i}}}"), &t).replace(&format!("${i}"), &t);
            }
            Some(format!("{}{}{}", &s[..m.start()], out, &s[m.end()..]))
        })
    }

    /// Un segment (entre « · ») : exact, motif, ou inchangé.
    fn segment(&self, s: &str) -> String {
        let t = s.trim();
        if t.is_empty() {
            return s.to_string();
        }
        match self.atom(t) {
            Some(x) => s.replacen(t, &x, 1),
            None => s.to_string(),
        }
    }

    /// Une ligne : puces conservées, texte exact/motif, sinon découpage par « · » puis « : ».
    fn line(&self, l: &str) -> String {
        const BULLETS: [&str; 7] = ["• ", "✔ ", "✘ ", "⚠ ", "▶ ", "- ", "  "];
        let (prefix, body) = BULLETS.iter().find_map(|b| l.strip_prefix(b).map(|r| (*b, r))).unwrap_or(("", l));
        if let Some(t) = self.atom(body.trim()) {
            return format!("{prefix}{t}");
        }
        if body.contains(" · ") {
            return format!("{prefix}{}", body.split(" · ").map(|s| self.segment(s)).collect::<Vec<_>>().join(" · "));
        }
        // « Libellé : valeur » : on traduit chaque côté
        if let Some((a, b)) = body.split_once(" : ") {
            let (ta, tb) = (self.segment(a), self.segment(b));
            if ta != a || tb != b {
                return format!("{prefix}{ta} : {tb}");
            }
        }
        l.to_string()
    }

    pub fn translate(&self, s: &str) -> String {
        if s.is_empty() {
            return String::new();
        }
        if let Some(t) = self.atom(s) {
            return t;
        }
        s.split('\n').map(|l| self.line(l)).collect::<Vec<_>>().join("\n")
    }
}

/// Catalogues anglais fournis (concaténés) : textes d'origine, écrans, fenêtres, conseils, outils.
pub const EN_FILES: [&str; 5] = [include_str!("../lang/en.tsv"), include_str!("../lang/en_ui.tsv"), include_str!("../lang/en_dialogs.tsv"), include_str!("../lang/en_screens.tsv"), include_str!("../lang/en_tools.tsv")];

fn english() -> Catalog {
    Catalog::from_tsv(&EN_FILES.join("\n"))
}

/// Entrées du catalogue de référence (texte français, anglais), dans l'ordre des fichiers : l'INDICE d'une entrée (0, 1, 2…) sert
/// d'identifiant dans les fichiers de traduction `lang/<code>.tsv` (format « indice<TAB>traduction »).
pub fn reference_entries() -> Vec<(String, String)> {
    EN_FILES.join("\n").lines().filter_map(|l| l.split_once('\t')).filter(|(k, v)| !k.is_empty() && !v.is_empty()).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Langues fournies avec l'application (en plus du français d'origine et de l'anglais).
pub const BUNDLED: [(&str, &str); 4] = [("de", include_str!("../lang/de.tsv")), ("es", include_str!("../lang/es.tsv")), ("it", include_str!("../lang/it.tsv")), ("nl", include_str!("../lang/nl.tsv"))];

/// Traductions « indice<TAB>texte » d'un fichier fourni.
pub fn parse_translations(text: &str) -> HashMap<usize, String> {
    text.lines().filter_map(|l| l.split_once('\t')).filter_map(|(id, v)| Some((id.trim().parse::<usize>().ok()?, v.to_string()))).filter(|(_, v)| !v.is_empty()).collect()
}

/// Catalogue d'une langue fournie : chaque entrée de référence prend sa traduction si elle existe, sinon l'anglais.
fn bundled_catalog(code: &str) -> Option<Catalog> {
    let text = BUNDLED.iter().find(|(c, _)| *c == code)?.1;
    let tr = parse_translations(text);
    let pairs: Vec<(String, String)> = reference_entries().into_iter().enumerate().map(|(i, (k, en))| (k, tr.get(&i).cloned().unwrap_or(en))).collect();
    Some(Catalog::from_pairs(&pairs))
}


static LANG: OnceLock<String> = OnceLock::new();
static CATALOG: OnceLock<Catalog> = OnceLock::new();

/// Langue choisie manuellement dans l'application (« auto » ou absente : celle du système). À appeler avant le premier texte affiché.
static OVERRIDE: OnceLock<String> = OnceLock::new();

pub fn set_override(code: &str) {
    let _ = OVERRIDE.set(code.to_string());
}

pub fn lang() -> &'static str {
    LANG.get_or_init(|| match OVERRIDE.get().and_then(|o| parse_locale(o).filter(|_| o != "auto")) {
        Some(l) => l,
        None => detect(&|k| std::env::var(k).ok()),
    })
}

/// Nom d'une langue dans cette langue (liste courte ; sinon le code en majuscules).
pub fn lang_name(code: &str) -> String {
    match code {
        "fr" => "Français",
        "en" => "English",
        "de" => "Deutsch",
        "es" => "Español",
        "it" => "Italiano",
        "pt" => "Português",
        "nl" => "Nederlands", // néerlandais (Belgique ou Pays-Bas) : simplement « Nederlands »
        "pl" => "Polski",
        "ru" => "Русский",
        "ja" => "日本語",
        "zh" => "中文",
        "tr" => "Türkçe",
        "sv" => "Svenska",
        "cs" => "Čeština",
        "uk" => "Українська",
        "ar" => "العربية",
        other => return other.to_uppercase(),
    }
    .to_string()
}

/// Langues proposées : français et anglais (fournis) + celles que l'utilisateur a ajoutées dans ~/.config/cachy-shield/lang/<code>.tsv.
pub fn available_languages() -> Vec<String> {
    let mut v: Vec<String> = ["fr", "en"].iter().chain(BUNDLED.iter().map(|(c, _)| c)).map(|s| s.to_string()).collect();
    let dir = crate::util::xdg_dir("XDG_CONFIG_HOME", ".config").map(|d| d.join("cachy-shield/lang"));
    if let Some(rd) = dir.and_then(|d| std::fs::read_dir(d).ok()) {
        let mut extra: Vec<String> = rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".tsv")).map(str::to_string)).filter(|c| parse_locale(c).as_deref() == Some(c.as_str()) && !v.contains(c)).collect();
        extra.sort();
        v.extend(extra);
    }
    v
}


fn user_catalog(l: &str) -> Option<Catalog> {
    let dir = crate::util::xdg_dir("XDG_CONFIG_HOME", ".config")?.join("cachy-shield/lang");
    let f = dir.join(format!("{l}.tsv"));
    f.metadata().ok().filter(|m| m.is_file() && m.len() < 4 << 20)?;
    Some(Catalog::from_tsv(&std::fs::read_to_string(f).ok()?))
}

/// Catalogue d'une langue : l'anglais fourni sert de base à toute langue autre que le français ; le catalogue de l'utilisateur (`~/.config/cachy-shield/lang/<code>.tsv`) passe devant.
/// Un texte absent du catalogue utilisateur s'affiche donc en anglais (langue commune) plutôt qu'en français.
fn build_catalog(l: &str, user: Option<Catalog>) -> Catalog {
    let mut c = if l == "fr" { Catalog::default() } else { bundled_catalog(l).unwrap_or_else(english) };
    if let Some(u) = user {
        c.extend(u);
    }
    c
}

fn catalog() -> &'static Catalog {
    CATALOG.get_or_init(|| {
        let l = lang();
        build_catalog(l, user_catalog(l))
    })
}

/// Accords du singulier et du pluriel : les textes sont écrits « {n} faille(s) », « {singulier|pluriel} » ou « librar(y/ies) »,
/// puis résolus d'après le nombre qui précède (aucun « (s) » ni « / » n'est jamais affiché). Sans nombre : pluriel.
pub fn plural(s: &str) -> String {
    if !s.contains('(') && !s.contains('{') {
        return s.to_string();
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(\d+)|\{([^{}|]+)\|([^{}|]+)\}|\(([a-zäöüéèêàùâîôûëïç]{1,5})\)|\(([a-zäöüéèêàù]{0,4})/([a-zäöüéèêàù]{1,5})\)").expect("regex d'accord")
    });
    let single = |n: Option<u64>| n.map(|n| if lang() == "fr" { n < 2 } else { n == 1 }).unwrap_or(false);
    let mut n: Option<u64> = None;
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for c in re.captures_iter(s) {
        let m = c.get(0).expect("match");
        out.push_str(&s[last..m.start()]);
        last = m.end();
        if let Some(d) = c.get(1) {
            n = d.as_str().parse().ok();
            out.push_str(d.as_str());
        } else if let (Some(a), Some(b)) = (c.get(2), c.get(3)) {
            out.push_str(if single(n) { a.as_str() } else { b.as_str() });
        } else if let Some(suf) = c.get(4) {
            // « (s) » collé à un mot ; une parenthèse précédée d'une espace (« (CISA) ») n'est pas un accord
            let attached = s[..m.start()].chars().next_back().is_some_and(|ch| ch.is_alphabetic());
            if !attached {
                out.push_str(m.as_str());
            } else if !single(n) {
                out.push_str(suf.as_str());
            }
        } else if let (Some(a), Some(b)) = (c.get(5), c.get(6)) {
            out.push_str(if single(n) { a.as_str() } else { b.as_str() });
        }
    }
    out.push_str(&s[last..]);
    out
}

/// Traduit un texte source français ; renvoie le français si aucune traduction n'existe.
pub fn tr(fr: &str) -> String {
    if lang() == "fr" {
        return plural(fr);
    }
    // mémoire des traductions déjà calculées : le balayage de l'interface repasse sans cesse sur les mêmes textes
    thread_local! {
        static MEMO: std::cell::RefCell<HashMap<String, String>> = std::cell::RefCell::new(HashMap::new());
    }
    if let Some(t) = MEMO.with(|m| m.borrow().get(fr).cloned()) {
        return t;
    }
    let t = plural(&catalog().translate(fr));
    MEMO.with(|m| {
        let mut m = m.borrow_mut();
        if m.len() > 40_000 {
            m.clear();
        }
        m.insert(fr.to_string(), t.clone());
    });
    t
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn langue_sans_catalogue_complet_retombe_sur_l_anglais() {
        let user = Catalog::from_tsv("Fermer\tSchließen\n~^(\\d+) faille\\(s\\)$\t$1 Schwachstelle(n)\n");
        let de = build_catalog("pl", Some(user));
        assert_eq!(de.translate("Fermer"), "Schließen", "le catalogue de l'utilisateur passe devant");
        assert_eq!(de.translate("3 faille(s)"), "3 Schwachstelle(n)");
        assert_eq!(de.translate("Annuler"), "Cancel", "texte absent : anglais, pas français");
        for (code, mot) in [("de", "Abbrechen"), ("es", "Cancelar"), ("it", "Annulla"), ("nl", "Annuleren")] {
            assert_eq!(build_catalog(code, None).translate("Annuler"), mot, "langue fournie : {code}");
        }
        assert_eq!(build_catalog("ja", None).translate("Fermer"), "Close", "langue sans catalogue : anglais");
        assert_eq!(build_catalog("fr", None).translate("Fermer"), "Fermer", "français : texte d'origine");
    }

    #[test]
    fn locales_courantes() {
        assert_eq!(parse_locale("fr_FR.UTF-8").as_deref(), Some("fr"));
        assert_eq!(parse_locale("en_US.UTF-8").as_deref(), Some("en"));
        assert_eq!(parse_locale("de_DE@euro").as_deref(), Some("de"));
        assert_eq!(parse_locale("pt-BR").as_deref(), Some("pt"));
        assert_eq!(parse_locale("fr_CA:en_US:en").as_deref(), Some("fr"), "LANGUAGE est une liste : la première compte");
        assert_eq!(parse_locale("C"), None);
        assert_eq!(parse_locale("POSIX"), None);
        assert_eq!(parse_locale(""), None);
        assert_eq!(parse_locale("../../etc"), None, "valeur suspecte refusée");
    }

    #[test]
    fn ordre_de_priorite_des_variables() {
        let env = |pairs: &'static [(&str, &str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        assert_eq!(detect(&env(&[("LANG", "fr_FR.UTF-8")])), "fr");
        assert_eq!(detect(&env(&[("LANG", "fr_FR.UTF-8"), ("LC_MESSAGES", "de_DE.UTF-8")])), "de");
        assert_eq!(detect(&env(&[("LANG", "fr_FR.UTF-8"), ("LANGUAGE", "es:fr")])), "es");
        assert_eq!(detect(&env(&[("LANG", "C")])), "en");
        assert_eq!(detect(&env(&[])), "en");
        assert_eq!(detect(&env(&[("LANG", "fr_FR.UTF-8"), ("CACHY_SHIELD_LANG", "it")])), "it");
    }

    fn cat() -> Catalog {
        Catalog::from_tsv("Analyser\tScan\nAutorisé\tIntended\n~^(\\d+) logiciel\\(s\\)$\t$1 software item(s)\n~^la plus récente signalée le (\\S+)$\tlatest reported on $1\nmettez ce logiciel à jour\tupdate this software\nPortée\tScope\n")
    }

    #[test]
    fn texte_exact_et_motif_avec_chiffre() {
        let c = cat();
        assert_eq!(c.translate("Analyser"), "Scan");
        assert_eq!(c.translate("21 logiciel(s)"), "21 software item(s)");
        assert_eq!(c.translate("inconnu"), "inconnu", "sans traduction : le français est conservé");
    }

    #[test]
    fn segments_et_lignes() {
        let c = cat();
        assert_eq!(c.translate("la plus récente signalée le 2026-09-09 · mettez ce logiciel à jour"), "latest reported on 2026-09-09 · update this software");
        assert_eq!(c.translate("• Analyser\n✔ Autorisé\nligne inconnue"), "• Scan\n✔ Intended\nligne inconnue");
        assert_eq!(c.translate("Portée : Autorisé"), "Scope : Intended", "libellé : valeur");
    }

    #[test]
    fn catalogue_tsv_regles_invalides_ignorees() {
        let c = Catalog::from_tsv("Analyser\tScan\n~(\tbad\nligne sans tabulation\n\tvide\n");
        assert_eq!(c.exact.len(), 1);
        assert!(c.rules.is_empty(), "un motif invalide est ignoré, sans planter");
    }

    #[test]
    fn le_catalogue_anglais_fourni_est_valide() {
        let c = english();
        assert!(c.exact.len() > 150 && c.rules.len() > 50, "catalogue anglais incomplet");
        for l in EN_FILES.iter().flat_map(|f| f.lines()).filter(|l| !l.trim().is_empty()) {
            assert_eq!(l.matches('\t').count(), 1, "une seule tabulation par ligne : {l}");
            if let Some(p) = l.strip_prefix('~') {
                assert!(Regex::new(p.split('\t').next().unwrap()).is_ok(), "motif invalide : {l}");
            }
        }
    }
}

#[cfg(test)]
mod diag_i18n {
    use super::*;

    /// Diagnostic : textes français des sources sans traduction anglaise. `cargo test diag_i18n -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn textes_sans_traduction() {
        let cat = english();
        let lit = Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).unwrap();
        let fr = Regex::new(r"[àâçéèêëîïôùûüœÀÉÈ]|\b(le|la|les|des|du|vous|votre|vos|est|pas|une|un|avec|pour|sans|dans|sur|ce|cette|ou|et)\b").unwrap();
        let mut missing: Vec<(String, String)> = Vec::new();
        let mut templates = 0;
        let mut stack = vec![std::path::PathBuf::from("src")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p).unwrap();
                    let body = text.split("#[cfg(test)]").next().unwrap_or(&text);
                    for line in body.lines() {
                        let t = line.trim_start();
                        if t.starts_with("//") || t.contains("eprintln!") || t.contains("assert") || t.contains(".expect(") || t.contains("set_icon_name") || t.contains("from_icon_name") {
                            continue;
                        }
                        for c in lit.captures_iter(line) {
                            let s = c[1].replace("\\n", "\n").replace("\\\"", "\"").replace("\\'", "'");
                            if s.len() < 4 || !fr.is_match(&s) || s.contains("::") {
                                continue;
                            }
                            if s.contains('{') {
                                templates += 1;
                                continue;
                            }
                            if cat.translate(&s) == s {
                                missing.push((p.display().to_string(), s));
                            }
                        }
                    }
                }
            }
        }
        missing.sort();
        missing.dedup();
        println!("MODÈLES avec {{}} (non vérifiés ici) : {templates}");
        println!("SANS TRADUCTION : {}", missing.len());
        for (f, s) in &missing {
            println!("MISS\t{f}\t{}", s.replace('\n', "\\n"));
        }
    }
}

#[cfg(test)]
mod tests_nouveaux_textes {
    use super::*;

    #[test]
    fn textes_recents_traduits_en_anglais() {
        let cat = english();
        for fr in [
            "Mettre à jour l'AUR…",
            "Relire avant d'installer :",
            "J'ai relu : installer",
            "Ignorer ce paquet",
            "Téléchargement : 12 / 239",
            "Installation : 3 / 10",
            "Paquet 1 / 2 : example-pkg",
            "✔ example-pkg installé",
            "✘ git n'est pas installé",
            "⚠ télécharge puis exécute un script (curl/wget vers sh) dans le PKGBUILD",
            "⚠ touche un fichier sensible (.ssh/)",
            "1 mise à jour disponible",
            "2 mise(s) à jour AUR disponible(s)",
            "Étapes : 1) téléchargement des recettes (PKGBUILD) ; 2) VOUS relisez chacune ; 3) construction et installation de ce que vous avez relu.",
        ] {
            let en = cat.translate(fr);
            assert_ne!(en, fr, "non traduit : {fr}");
        }
        assert_eq!(cat.translate("Téléchargement : 12 / 239"), "Downloading: 12 / 239");
    }
}

#[cfg(test)]
mod tests_langue_manuelle {
    use super::*;

    #[test]
    fn choix_manuel_et_noms() {
        assert_eq!(parse_locale("auto"), None, "« auto » n'est pas un code de langue : on retombe sur la langue du système");
        assert_eq!(parse_locale("de").as_deref(), Some("de"));
        assert_eq!(lang_name("fr"), "Français");
        assert_eq!(lang_name("en"), "English");
        assert_eq!(lang_name("xx"), "XX");
        let l = available_languages();
        assert_eq!(&l[..2], ["fr", "en"]);
    }
}

#[cfg(test)]
mod tests_catalogues_fournis {
    use super::*;

    fn tokens(s: &str, open: char, close: char) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let mut cur: Option<String> = None;
        for c in s.chars() {
            match (c, cur.as_mut()) {
                (c, None) if c == open => cur = Some(String::new()),
                (c, Some(t)) if c == close => {
                    v.push(t.clone());
                    cur = None;
                }
                (c, Some(t)) => t.push(c),
                _ => {}
            }
        }
        v.retain(|t| !t.contains('|'));
        v.sort();
        v
    }

    fn dollars(s: &str) -> Vec<String> {
        let re = Regex::new(r"\$\{?(\d+)\}?").unwrap();
        let mut v: Vec<String> = re.captures_iter(s).map(|c| c[1].to_string()).collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn la_reference_anglaise_est_coherente() {
        let mut problemes: Vec<String> = Vec::new();
        let fr_acc = Regex::new(r"[àâçéèêëîïôùûüœÀÉÈÊ]").unwrap();
        for (i, (k, en)) in reference_entries().iter().enumerate() {
            if let Some(pat) = k.strip_prefix('~') {
                match Regex::new(pat) {
                    Err(e) => problemes.push(format!("#{i} règle invalide ({e}) : {k}")),
                    Ok(re) => {
                        let groups = re.captures_len() - 1;
                        for d in dollars(en) {
                            if d.parse::<usize>().unwrap() > groups {
                                problemes.push(format!("#{i} ${d} dépasse les {groups} groupes : {k}"));
                            }
                        }
                    }
                }
            }
            if !k.starts_with('~') && tokens(k, '{', '}') != tokens(en, '{', '}') {
                problemes.push(format!("#{i} modèles {{…}} différents\n   fr: {k}\n   en: {en}"));
            }
            // l'anglais ne doit pas contenir de lettres accentuées françaises (traduction oubliée ou mélange)
            if fr_acc.is_match(en) {
                problemes.push(format!("#{i} accents français dans l'anglais\n   fr: {k}\n   en: {en}"));
            }
        }
        assert!(problemes.is_empty(), "{} problème(s) dans la référence anglaise :\n{}", problemes.len(), problemes.join("\n"));
    }

    #[test]
    fn chaque_langue_fournie_garde_ses_marqueurs() {
        let refs = reference_entries();
        let mut problemes: Vec<String> = Vec::new();
        for (code, text) in BUNDLED {
            let tr = parse_translations(text);
            for (id, v) in &tr {
                let Some((k, en)) = refs.get(*id) else {
                    problemes.push(format!("{code} : indice {id} inexistant"));
                    continue;
                };
                if dollars(en) != dollars(v) {
                    problemes.push(format!("{code} #{id} : les $n diffèrent de l'anglais\n  fr: {k}\n  en: {en}\n  {code}: {v}"));
                }
                if tokens(en, '{', '}') != tokens(v, '{', '}') {
                    problemes.push(format!("{code} #{id} : les modèles {{…}} diffèrent\n  en: {en}\n  {code}: {v}"));
                }
                if en.matches("\\n").count() != v.matches("\\n").count() {
                    problemes.push(format!("{code} #{id} : sauts de ligne différents\n  en: {en}\n  {code}: {v}"));
                }
                if en.starts_with(' ') != v.starts_with(' ') || en.ends_with(' ') != v.ends_with(' ') {
                    problemes.push(format!("{code} #{id} : espaces de début/fin différents\n  en: {en:?}\n  {code}: {v:?}"));
                }
            }
            // une langue fournie est complète : aucune entrée ne reste sans traduction
            let manquantes: Vec<usize> = (0..refs.len()).filter(|i| !tr.contains_key(i)).take(10).collect();
            if !manquantes.is_empty() {
                problemes.push(format!("{code} : entrées sans traduction (10 premières) : {manquantes:?}"));
            }
        }
        assert!(problemes.is_empty(), "{} problème(s) :\n{}", problemes.len(), problemes.join("\n"));
    }

    #[test]
    fn langues_proposees() {
        let l = available_languages();
        for c in ["fr", "en", "de", "es", "it", "nl"] {
            assert!(l.iter().any(|x| x == c), "{c} doit être proposée");
        }
        assert_eq!(lang_name("nl"), "Nederlands");
        assert_eq!(lang_name("de"), "Deutsch");
        assert_eq!(lang_name("es"), "Español");
        assert_eq!(lang_name("it"), "Italiano");
    }
}

#[cfg(test)]
mod tests_vitesse {
    use super::*;

    /// Le balayage de l'interface traduit des milliers de textes toutes les 0,12 s : un texte qui ne correspond à aucune règle doit être écarté très vite.
    #[test]
    fn texte_sans_traduction_ecarte_rapidement() {
        let c = build_catalog("nl", None);
        let t0 = std::time::Instant::now();
        for i in 0..3000 {
            let _ = c.translate(&format!("Un texte inconnu numéro {i} · autre segment : valeur {i}"));
        }
        let ms = t0.elapsed().as_millis();
        assert!(ms < 1500, "3000 textes inconnus ont pris {ms} ms");
        // et le résultat reste identique à l'ancienne méthode (règle par règle)
        assert_eq!(c.translate("3 mise(s) à jour disponible(s)"), c.translate("3 mise(s) à jour disponible(s)"));
        assert_eq!(c.translate("Annuler"), "Annuleren");
    }
}

#[cfg(test)]
mod tests_accords {
    use super::*;

    #[test]
    fn accords_resolus_selon_le_nombre() {
        assert_eq!(plural("1 faille(s) dont 1 grave(s)"), "1 faille dont 1 grave");
        assert_eq!(plural("3 faille(s) dont 2 grave(s)"), "3 failles dont 2 graves");
        assert_eq!(plural("1 librar(y/ies) · 2 flaw(s)"), "1 library · 2 flaws");
        assert_eq!(plural("2 {Bibliothek|Bibliotheken}"), "2 Bibliotheken");
        assert_eq!(plural("1 {Bibliothek|Bibliotheken}"), "1 Bibliothek");
        assert_eq!(plural("Failles (CISA) (KEV)"), "Failles (CISA) (KEV)");
        assert_eq!(plural("{pacchetto|pacchetti} trovati"), "pacchetti trovati");
    }

    #[test]
    fn aucun_marqueur_d_accord_ne_s_affiche() {
        for code in ["de", "es", "it", "nl", "en"] {
            let cat = build_catalog(code, None);
            for (i, (k, _)) in reference_entries().iter().enumerate() {
                let _ = i;
                if k.starts_with('~') {
                    continue;
                }
                let r = plural(&cat.translate(k));
                assert!(!r.contains('{') || k.contains('{'), "{code}: marqueur restant dans « {r} »");
                assert!(!r.contains("(s)") && !r.contains("(n)") && !r.contains("(en)"), "{code}: « {r} »");
            }
        }
    }
}
