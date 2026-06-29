//! Métriques d'observabilité au format d'exposition Prometheus — WS2.
//!
//! Fournit :
//!   * [`Metriques`] — instantané déterministe des compteurs (alertes,
//!     latence canaux, dédup, constats, serveurs, store) ;
//!   * [`RegistreMetriques`] — accumulateur thread-safe alimenté en runtime
//!     par le moteur d'alertes (latence d'envoi par canal, alertes émises) ;
//!   * [`rendre_prometheus`] — génère le texte d'exposition Prometheus
//!     (`text/plain; version=0.0.4`) de façon **déterministe et testable**,
//!     sans aucune dépendance réseau ni serveur.
//!
//! Le rendu trie toutes les séries (BTreeMap) pour une sortie reproductible.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use sentinel_protocol::Severite;

/// Content-type d'exposition Prometheus (format texte version 0.0.4).
pub const CONTENT_TYPE_PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Agrégat de latence pour un canal — summary minimaliste (somme + count).
///
/// Permet de calculer une latence moyenne (`somme_secondes / count`) côté
/// Prometheus via la division des deux séries `_sum` et `_count`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgregatLatence {
    /// Nombre d'envois observés.
    pub count: u64,
    /// Somme cumulée des durées d'envoi, en secondes.
    pub somme_secondes: f64,
}

impl AgregatLatence {
    /// Enregistre une nouvelle observation de durée.
    pub fn observer(&mut self, duree: Duration) {
        self.count += 1;
        self.somme_secondes += duree.as_secs_f64();
    }
}

/// Instantané déterministe de l'ensemble des métriques exposées.
///
/// Toutes les séries labellisées utilisent des `BTreeMap` afin que le rendu
/// soit ordonné et reproductible (indispensable pour des tests stables).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metriques {
    /// `severity` → nombre d'alertes (`sentinel_alerts_total`).
    pub alertes_par_severite: BTreeMap<String, u64>,
    /// `channel` → agrégat de latence (`sentinel_channel_send_duration_seconds`).
    pub latence_canaux: BTreeMap<String, AgregatLatence>,
    /// Taille courante de la table de déduplication (`sentinel_dedup_size`).
    pub dedup_size: u64,
    /// `type` → nombre de constats (`sentinel_findings_total`).
    pub findings_par_type: BTreeMap<String, u64>,
    /// `couleur` → nombre de serveurs (`sentinel_servers_total`).
    pub serveurs_par_couleur: BTreeMap<String, u64>,
    /// Nombre de serveurs dans le store (`sentinel_db_servers_total`).
    pub db_serveurs_total: u64,
    /// Nombre d'outils dans le store (`sentinel_db_tools_total`).
    pub db_outils_total: u64,
    /// Nombre de constats dans le store (`sentinel_db_findings_total`).
    pub db_constats_total: u64,
    /// Nombre d'alertes dans le store (`sentinel_db_alerts_total`).
    pub db_alertes_total: u64,
}

impl Metriques {
    /// Instantané vide.
    pub fn nouveau() -> Self {
        Self::default()
    }

    /// Construit les compteurs issus du store (serveurs, constats, alertes,
    /// outils) à partir d'un agrégat lu en lecture seule.
    ///
    /// Les champs runtime (latence canaux, `dedup_size`) restent à zéro :
    /// ils sont alimentés par un [`RegistreMetriques`] via [`Self::appliquer_registre`].
    pub fn depuis_stats_store(stats: &sentinel_store::StatsMetriques) -> Self {
        Self {
            alertes_par_severite: stats.alertes_par_severite.clone(),
            latence_canaux: BTreeMap::new(),
            dedup_size: 0,
            findings_par_type: stats.constats_par_type.clone(),
            serveurs_par_couleur: stats.serveurs_par_couleur.clone(),
            db_serveurs_total: stats.serveurs_total,
            db_outils_total: stats.outils_total,
            db_constats_total: stats.constats_total,
            db_alertes_total: stats.alertes_total,
        }
    }

    /// Fusionne les compteurs runtime accumulés par un registre.
    ///
    /// La latence des canaux est recopiée telle quelle ; les compteurs
    /// d'alertes par sévérité sont additionnés (le registre étant la source
    /// vivante de comptage du processus). Permet à la CLI de combiner une
    /// vue store + une vue runtime dans un même export.
    pub fn appliquer_registre(&mut self, registre: &RegistreMetriques) {
        let etat = registre.etat.lock().unwrap_or_else(|e| e.into_inner());
        for (canal, agg) in &etat.latence_canaux {
            self.latence_canaux.insert(canal.clone(), agg.clone());
        }
        for (sev, n) in &etat.alertes_par_severite {
            *self.alertes_par_severite.entry(sev.clone()).or_insert(0) += *n;
        }
    }
}

/// Accumulateur thread-safe des métriques runtime.
///
/// Partagé via `Arc` par le moteur d'alertes : chaque envoi de canal y
/// dépose sa durée mesurée par `Instant`, et chaque alerte émise y
/// incrémente un compteur par sévérité. La lecture se fait via
/// [`Metriques::appliquer_registre`] ou [`RegistreMetriques::instantane`].
#[derive(Debug, Default)]
pub struct RegistreMetriques {
    etat: Mutex<EtatRegistre>,
}

#[derive(Debug, Default)]
struct EtatRegistre {
    latence_canaux: BTreeMap<String, AgregatLatence>,
    alertes_par_severite: BTreeMap<String, u64>,
}

impl RegistreMetriques {
    /// Crée un registre vide.
    pub fn nouveau() -> Self {
        Self::default()
    }

    /// Enregistre la durée d'un envoi pour un canal nommé.
    ///
    /// Tolère un mutex empoisonné (un panic d'un autre thread ne doit pas
    /// rendre l'observabilité indisponible).
    pub fn observer_latence_canal(&self, canal: &str, duree: Duration) {
        let mut etat = self.etat.lock().unwrap_or_else(|e| e.into_inner());
        etat
            .latence_canaux
            .entry(canal.to_string())
            .or_default()
            .observer(duree);
    }

    /// Incrémente le compteur d'alertes émises pour une sévérité (libellé).
    pub fn incr_alerte(&self, severite: &str) {
        let mut etat = self.etat.lock().unwrap_or_else(|e| e.into_inner());
        *etat
            .alertes_par_severite
            .entry(severite.to_string())
            .or_insert(0) += 1;
    }

    /// Instantané autonome des seules métriques runtime (latence + alertes).
    pub fn instantane(&self) -> Metriques {
        let mut m = Metriques::nouveau();
        m.appliquer_registre(self);
        m
    }
}

/// Libellé `snake_case` d'une sévérité, aligné sur la sérialisation serde.
pub fn label_severite(severite: Severite) -> &'static str {
    match severite {
        Severite::Info => "info",
        Severite::Moyenne => "moyenne",
        Severite::Haute => "haute",
        Severite::Critique => "critique",
    }
}

/// Génère le texte d'exposition Prometheus à partir d'un instantané.
///
/// Sortie **déterministe** : séries triées par clé, formatage de flottants
/// stable (Display Rust = représentation la plus courte qui round-trip).
/// Aucune dépendance réseau — directement testable.
pub fn rendre_prometheus(m: &Metriques) -> String {
    let mut sortie = String::new();

    // ── sentinel_alerts_total{severity=...} ────────────────────────────────
    bloc_entete(
        &mut sortie,
        "sentinel_alerts_total",
        "Nombre total d'alertes par sévérité.",
        "counter",
    );
    for (severite, n) in &m.alertes_par_severite {
        ligne_label(&mut sortie, "sentinel_alerts_total", "severity", severite, *n);
    }

    // ── sentinel_channel_send_duration_seconds (summary par canal) ──────────
    bloc_entete(
        &mut sortie,
        "sentinel_channel_send_duration_seconds",
        "Latence d'envoi des alertes par canal (somme + count).",
        "summary",
    );
    for (canal, agg) in &m.latence_canaux {
        sortie.push_str(&format!(
            "sentinel_channel_send_duration_seconds_sum{{channel=\"{}\"}} {}\n",
            echapper_label(canal),
            formater_flottant(agg.somme_secondes),
        ));
        sortie.push_str(&format!(
            "sentinel_channel_send_duration_seconds_count{{channel=\"{}\"}} {}\n",
            echapper_label(canal),
            agg.count,
        ));
    }

    // ── sentinel_dedup_size ────────────────────────────────────────────────
    bloc_entete(
        &mut sortie,
        "sentinel_dedup_size",
        "Nombre d'entrées suivies par la déduplication anti-bruit.",
        "gauge",
    );
    sortie.push_str(&format!("sentinel_dedup_size {}\n", m.dedup_size));

    // ── sentinel_findings_total{type=...} ──────────────────────────────────
    bloc_entete(
        &mut sortie,
        "sentinel_findings_total",
        "Nombre de constats par type de détection.",
        "gauge",
    );
    for (type_c, n) in &m.findings_par_type {
        ligne_label(&mut sortie, "sentinel_findings_total", "type", type_c, *n);
    }

    // ── sentinel_servers_total{couleur=...} ────────────────────────────────
    bloc_entete(
        &mut sortie,
        "sentinel_servers_total",
        "Nombre de serveurs MCP par couleur de criticité.",
        "gauge",
    );
    for (couleur, n) in &m.serveurs_par_couleur {
        ligne_label(&mut sortie, "sentinel_servers_total", "couleur", couleur, *n);
    }

    // ── sentinel_db_* (compteurs du store) ─────────────────────────────────
    bloc_simple(
        &mut sortie,
        "sentinel_db_servers_total",
        "Nombre de serveurs persistés dans le store.",
        m.db_serveurs_total,
    );
    bloc_simple(
        &mut sortie,
        "sentinel_db_tools_total",
        "Nombre d'outils persistés dans le store.",
        m.db_outils_total,
    );
    bloc_simple(
        &mut sortie,
        "sentinel_db_findings_total",
        "Nombre de constats persistés dans le store.",
        m.db_constats_total,
    );
    bloc_simple(
        &mut sortie,
        "sentinel_db_alerts_total",
        "Nombre d'alertes persistées dans le store.",
        m.db_alertes_total,
    );

    sortie
}

// ── Helpers de rendu ────────────────────────────────────────────────────────

/// Écrit les lignes `# HELP` / `# TYPE` d'une métrique.
fn bloc_entete(sortie: &mut String, nom: &str, aide: &str, type_metrique: &str) {
    sortie.push_str(&format!("# HELP {} {}\n", nom, aide));
    sortie.push_str(&format!("# TYPE {} {}\n", nom, type_metrique));
}

/// Écrit un bloc gauge scalaire complet (HELP + TYPE + valeur).
fn bloc_simple(sortie: &mut String, nom: &str, aide: &str, valeur: u64) {
    bloc_entete(sortie, nom, aide, "gauge");
    sortie.push_str(&format!("{} {}\n", nom, valeur));
}

/// Écrit une ligne d'échantillon avec un unique label.
fn ligne_label(sortie: &mut String, nom: &str, label: &str, valeur_label: &str, valeur: u64) {
    sortie.push_str(&format!(
        "{}{{{}=\"{}\"}} {}\n",
        nom,
        label,
        echapper_label(valeur_label),
        valeur
    ));
}

/// Échappe une valeur de label selon les règles Prometheus :
/// `\` → `\\`, `"` → `\"`, saut de ligne → `\n`.
fn echapper_label(valeur: &str) -> String {
    let mut s = String::with_capacity(valeur.len());
    for c in valeur.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            autre => s.push(autre),
        }
    }
    s
}

/// Formate un flottant de façon déterministe ; un entier reste sans `.0`
/// superflu pour rester lisible (`1` plutôt que `1.0`), sinon Display Rust.
fn formater_flottant(v: f64) -> String {
    if v == 0.0 {
        "0".to_string()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construit un instantané connu pour tester le rendu déterministe.
    fn metriques_exemple() -> Metriques {
        let mut m = Metriques::nouveau();
        m.alertes_par_severite.insert("critique".into(), 3);
        m.alertes_par_severite.insert("haute".into(), 1);
        m.latence_canaux.insert(
            "webhook".into(),
            AgregatLatence {
                count: 4,
                somme_secondes: 0.5,
            },
        );
        m.dedup_size = 7;
        m.findings_par_type.insert("poisoning".into(), 2);
        m.serveurs_par_couleur.insert("rouge".into(), 1);
        m.serveurs_par_couleur.insert("vert".into(), 5);
        m.db_serveurs_total = 6;
        m.db_outils_total = 42;
        m.db_constats_total = 2;
        m.db_alertes_total = 4;
        m
    }

    #[test]
    fn rendu_contient_help_type_et_lignes() {
        let texte = rendre_prometheus(&metriques_exemple());

        // Les en-têtes HELP/TYPE sont présents pour chaque métrique.
        assert!(texte.contains("# HELP sentinel_alerts_total"));
        assert!(texte.contains("# TYPE sentinel_alerts_total counter"));
        assert!(texte.contains("# TYPE sentinel_channel_send_duration_seconds summary"));
        assert!(texte.contains("# TYPE sentinel_dedup_size gauge"));
        assert!(texte.contains("# TYPE sentinel_findings_total gauge"));
        assert!(texte.contains("# TYPE sentinel_servers_total gauge"));
        assert!(texte.contains("# TYPE sentinel_db_servers_total gauge"));

        // Les échantillons labellisés sont rendus avec leurs valeurs.
        assert!(texte.contains("sentinel_alerts_total{severity=\"critique\"} 3"));
        assert!(texte.contains("sentinel_alerts_total{severity=\"haute\"} 1"));
        assert!(texte
            .contains("sentinel_channel_send_duration_seconds_sum{channel=\"webhook\"} 0.5"));
        assert!(texte
            .contains("sentinel_channel_send_duration_seconds_count{channel=\"webhook\"} 4"));
        assert!(texte.contains("sentinel_dedup_size 7"));
        assert!(texte.contains("sentinel_findings_total{type=\"poisoning\"} 2"));
        assert!(texte.contains("sentinel_servers_total{couleur=\"rouge\"} 1"));
        assert!(texte.contains("sentinel_servers_total{couleur=\"vert\"} 5"));
        assert!(texte.contains("sentinel_db_servers_total 6"));
        assert!(texte.contains("sentinel_db_tools_total 42"));
        assert!(texte.contains("sentinel_db_findings_total 2"));
        assert!(texte.contains("sentinel_db_alerts_total 4"));
    }

    #[test]
    fn rendu_est_deterministe() {
        let m = metriques_exemple();
        assert_eq!(rendre_prometheus(&m), rendre_prometheus(&m));
    }

    #[test]
    fn rendu_serie_triee_par_label() {
        // rouge < vert dans l'ordre BTreeMap ; rouge doit précéder vert.
        let texte = rendre_prometheus(&metriques_exemple());
        let pos_rouge = texte.find("couleur=\"rouge\"").unwrap();
        let pos_vert = texte.find("couleur=\"vert\"").unwrap();
        assert!(pos_rouge < pos_vert, "les séries doivent être triées");
    }

    #[test]
    fn chaque_ligne_help_type_precede_les_echantillons() {
        // Le bloc HELP/TYPE de alerts_total doit précéder ses échantillons.
        let texte = rendre_prometheus(&metriques_exemple());
        let pos_type = texte.find("# TYPE sentinel_alerts_total counter").unwrap();
        let pos_echantillon = texte.find("sentinel_alerts_total{severity=").unwrap();
        assert!(pos_type < pos_echantillon);
    }

    #[test]
    fn registre_enregistre_la_latence() {
        let reg = RegistreMetriques::nouveau();
        reg.observer_latence_canal("webhook", Duration::from_millis(100));
        reg.observer_latence_canal("webhook", Duration::from_millis(300));
        reg.observer_latence_canal("email", Duration::from_millis(50));

        let snap = reg.instantane();
        let webhook = snap.latence_canaux.get("webhook").unwrap();
        assert_eq!(webhook.count, 2);
        assert!((webhook.somme_secondes - 0.4).abs() < 1e-9);
        let email = snap.latence_canaux.get("email").unwrap();
        assert_eq!(email.count, 1);
    }

    #[test]
    fn registre_compte_les_alertes_par_severite() {
        let reg = RegistreMetriques::nouveau();
        reg.incr_alerte(label_severite(Severite::Critique));
        reg.incr_alerte(label_severite(Severite::Critique));
        reg.incr_alerte(label_severite(Severite::Info));

        let snap = reg.instantane();
        assert_eq!(snap.alertes_par_severite.get("critique"), Some(&2));
        assert_eq!(snap.alertes_par_severite.get("info"), Some(&1));
    }

    #[test]
    fn depuis_stats_store_recopie_les_compteurs() {
        let mut stats = sentinel_store::StatsMetriques::default();
        stats.serveurs_total = 3;
        stats.outils_total = 9;
        stats.constats_total = 2;
        stats.alertes_total = 5;
        stats.serveurs_par_couleur.insert("orange".into(), 3);
        stats.constats_par_type.insert("rug_pull".into(), 2);
        stats.alertes_par_severite.insert("haute".into(), 5);

        let m = Metriques::depuis_stats_store(&stats);
        assert_eq!(m.db_serveurs_total, 3);
        assert_eq!(m.db_outils_total, 9);
        assert_eq!(m.db_constats_total, 2);
        assert_eq!(m.db_alertes_total, 5);
        assert_eq!(m.serveurs_par_couleur.get("orange"), Some(&3));
        assert_eq!(m.findings_par_type.get("rug_pull"), Some(&2));
        assert_eq!(m.alertes_par_severite.get("haute"), Some(&5));
    }

    #[test]
    fn appliquer_registre_fusionne_runtime() {
        let mut stats = sentinel_store::StatsMetriques::default();
        stats.alertes_par_severite.insert("critique".into(), 1);
        let mut m = Metriques::depuis_stats_store(&stats);

        let reg = RegistreMetriques::nouveau();
        reg.incr_alerte("critique");
        reg.observer_latence_canal("siem", Duration::from_millis(20));
        m.appliquer_registre(&reg);

        // 1 (store) + 1 (runtime) = 2.
        assert_eq!(m.alertes_par_severite.get("critique"), Some(&2));
        assert!(m.latence_canaux.contains_key("siem"));
    }

    #[test]
    fn echappement_label_protege_guillemets_et_backslash() {
        assert_eq!(echapper_label("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn formatage_flottant_entier_sans_decimale() {
        assert_eq!(formater_flottant(0.0), "0");
        assert_eq!(formater_flottant(4.0), "4");
        assert_eq!(formater_flottant(0.5), "0.5");
    }
}
