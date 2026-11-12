//! Types partagés : niveaux, résultats d'analyse, gravités.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Bad,
    #[default]
    None,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub headline: String,
    pub level: Level,
    pub score: Option<u32>,
    pub time: i64,
    pub counts: BTreeMap<String, u64>,
}

/// Résultat d'un parseur : lignes de tableau + résumé.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub rows: Vec<Vec<String>>,
    pub result: ScanResult,
}

impl Outcome {
    pub fn simple(headline: impl Into<String>, level: Level) -> Self {
        Outcome { rows: vec![], result: ScanResult { headline: headline.into(), level, ..Default::default() } }
    }
}

/// Libellé français et rang de tri d'une gravité.
pub fn sev_info(key: &str) -> (&'static str, u8) {
    match key {
        "critical" => ("Critique", 0),
        "warning" => ("Alerte", 0),
        "high" => ("Élevée", 1),
        "medium" => ("Moyenne", 2),
        "suggestion" => ("Suggestion", 2),
        "low" => ("Faible", 3),
        "info" => ("Info", 3),
        _ => ("Inconnue", 4),
    }
}

/// Classe CSS associée (définie dans style.css).
pub fn sev_css(key: &str) -> &'static str {
    match key {
        "critical" | "warning" => "sev-critical",
        "high" => "sev-high",
        "medium" | "suggestion" => "sev-medium",
        "low" | "info" => "sev-low",
        _ => "sev-unknown",
    }
}

/// Classe de gravité d'un résultat arch-audit / OSV à partir d'un score CVSS.
pub fn level_from_counts(counts: &BTreeMap<String, u64>, any: bool) -> Level {
    let c = |k: &str| counts.get(k).copied().unwrap_or(0);
    if c("critical") + c("high") > 0 {
        Level::Bad
    } else if any {
        Level::Warn
    } else {
        Level::Ok
    }
}
