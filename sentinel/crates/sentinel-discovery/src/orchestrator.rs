//! Orchestrator that runs every detection source in parallel and aggregates.

use std::collections::BTreeMap;

use crate::config_baseline::{grouper_serveurs_projet, BaselineConfigsProjet};
use crate::model::{ClientDecouvert, ServeurMcpDeclare};
use crate::runtime_inspector::{correler_avec_inventaire, InspecteurSockets, SocketEnEcoute};
use crate::skills::{rattacher_aux_clients, DecouvreurSkills, SkillDecouvert};
use crate::sources::{sources_par_defaut, SourceClient};
use chrono::{DateTime, Utc};
use sentinel_protocol::Constat;
use serde::{Deserialize, Serialize};

/// Aggregated report produced by a discovery sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RapportDecouverte {
    pub clients: Vec<ClientDecouvert>,
    /// F2 — sockets TCP en écoute observés sur la machine au moment du
    /// balayage (énumération best-effort `lsof`/`ss`). Champ additif :
    /// `#[serde(default)]` pour la rétrocompat des payloads existants.
    #[serde(default)]
    pub sockets_observes: Vec<SocketEnEcoute>,
    /// F2 — constats « NeighborJack » : sockets exposés à toutes les
    /// interfaces, sur un port haut, sans correspondance dans l'inventaire MCP
    /// déclaré par les clients découverts. Un serveur MCP lancé hors config
    /// (script, docker, autre utilisateur) échappe sinon à toute surveillance.
    /// Champ additif (`#[serde(default)]`).
    #[serde(default)]
    pub constats_runtime: Vec<Constat>,
    pub demarre_a: DateTime<Utc>,
    pub termine_a: DateTime<Utc>,
}

impl RapportDecouverte {
    /// Inventaire MCP **déclaré** : tous les serveurs déclarés par les clients
    /// découverts, à plat. Sert de référentiel de corrélation (sockets
    /// runtime) et de source pour la baseline de configs projet.
    pub fn serveurs_declares(&self) -> Vec<ServeurMcpDeclare> {
        self.clients
            .iter()
            .flat_map(|c| c.serveurs.iter().cloned())
            .collect()
    }

    /// Serveurs MCP de **portée projet**, regroupés par chemin de projet.
    ///
    /// Chemin d'intégration prêt à consommer pour le suivi MCPoison
    /// (CVE-2025-54136) : un appelant alimente
    /// [`BaselineConfigsProjet::observer`] avec chaque entrée pour diffuser le
    /// contenu approuvé contre le contenu courant. Voir [`Self::observer_baseline`].
    pub fn serveurs_projet(&self) -> BTreeMap<String, Vec<ServeurMcpDeclare>> {
        grouper_serveurs_projet(&self.serveurs_declares())
    }

    /// Diffuse les configs de projet de ce rapport contre une `baseline`
    /// persistante et retourne les constats de dérive (MCPoison). La première
    /// observation d'un projet est silencieuse (rien à comparer) ; la baseline
    /// est mise à jour pour chaque projet observé.
    ///
    /// C'est la **fonction/chemin** que le monitor/CLI/desktop appelle pour
    /// détecter l'échange de contenu d'une config approuvée par nom
    /// (CVE-2025-54136) sans dépendre du store.
    pub fn observer_baseline(&self, baseline: &mut BaselineConfigsProjet) -> Vec<Constat> {
        let mut constats = Vec::new();
        for (chemin, serveurs) in self.serveurs_projet() {
            constats.extend(baseline.observer(&chemin, &serveurs));
        }
        constats
    }
}

pub struct OrchestrateurDecouverte {
    sources: Vec<Box<dyn SourceClient>>,
    /// Découverte des skills/agents (voir [`crate::skills`]) activée par
    /// défaut — désactivable via [`Self::sans_skills`].
    inclure_skills: bool,
    /// Inspection runtime des sockets en écoute (F2 « NeighborJack »), activée
    /// par défaut — désactivable via [`Self::sans_runtime`] pour les tests qui
    /// ne veulent balayer que des sources synthétiques sans toucher au système.
    inclure_runtime: bool,
}

impl Default for OrchestrateurDecouverte {
    fn default() -> Self {
        Self { sources: sources_par_defaut(), inclure_skills: true, inclure_runtime: true }
    }
}

impl OrchestrateurDecouverte {
    pub fn nouveau(sources: Vec<Box<dyn SourceClient>>) -> Self {
        Self { sources, inclure_skills: true, inclure_runtime: true }
    }

    /// Désactive la découverte des skills/agents (utile pour les tests qui
    /// ne veulent balayer que des sources synthétiques).
    pub fn sans_skills(mut self) -> Self {
        self.inclure_skills = false;
        self
    }

    /// Désactive l'inspection runtime des sockets en écoute (utile pour les
    /// tests déterministes qui ne doivent pas dépendre des sockets réels de la
    /// machine ni invoquer `lsof`/`ss`).
    pub fn sans_runtime(mut self) -> Self {
        self.inclure_runtime = false;
        self
    }

    /// Runs every source concurrently and produces a sweep report. Les
    /// skills/agents découverts sont rattachés aux `ClientDecouvert`
    /// correspondants (champ `skills`).
    pub async fn balayer(&self) -> RapportDecouverte {
        let demarre_a = Utc::now();
        let futures = self.sources.iter().map(|s| s.detecter());
        let resultats = futures::future::join_all(futures).await;
        let mut clients: Vec<ClientDecouvert> = resultats.into_iter().flatten().collect();
        if self.inclure_skills {
            // Scan disque synchrone — déporté hors du runtime async.
            let skills = decouvrir_skills_loggue(|| DecouvreurSkills.decouvrir()).await;
            rattacher_aux_clients(&mut clients, skills);
        }

        // F2 — énumération des sockets en écoute (« NeighborJack »), corrélée à
        // l'inventaire déclaré par les clients ci-dessus. Best-effort : aucun
        // échec (lsof/ss absents, panic du thread bloquant) n'interrompt le
        // balayage, qui produit alors simplement un rapport sans observation
        // runtime.
        let serveurs_connus: Vec<ServeurMcpDeclare> =
            clients.iter().flat_map(|c| c.serveurs.iter().cloned()).collect();
        let (sockets_observes, constats_runtime) = if self.inclure_runtime {
            inspecter_sockets_loggue(serveurs_connus).await
        } else {
            (Vec::new(), Vec::new())
        };

        let termine_a = Utc::now();
        RapportDecouverte { clients, sockets_observes, constats_runtime, demarre_a, termine_a }
    }
}

/// Énumère les sockets en écoute dans une **tâche bloquante** (la commande
/// système `lsof`/`ss` est synchrone) puis corrèle avec l'inventaire connu.
///
/// Rend **visible** tout échec du join (panic/cancellation) via un log `error!`
/// avant de retomber sur des `Vec` vides : un angle mort runtime muet serait un
/// faux négatif silencieux. L'énumération elle-même est déjà best-effort et ne
/// panique jamais (voir [`InspecteurSockets::scanner_local`]).
async fn inspecter_sockets_loggue(
    serveurs_connus: Vec<ServeurMcpDeclare>,
) -> (Vec<SocketEnEcoute>, Vec<Constat>) {
    let travail = move || {
        let sockets = InspecteurSockets::scanner_local();
        let constats = correler_avec_inventaire(&sockets, &serveurs_connus);
        (sockets, constats)
    };
    match tokio::task::spawn_blocking(travail).await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(
                erreur = %e,
                "inspection runtime des sockets échouée (tâche bloquante) — \
                 rapport produit sans observation runtime"
            );
            (Vec::new(), Vec::new())
        }
    }
}

/// Exécute le scan des skills/agents dans une tâche bloquante et rend
/// **visible** tout échec du join (panic/cancellation) via un log `error!`
/// avant de retomber sur un `Vec` vide. Les skills sont une surface d'attaque
/// majeure : un `Vec` vide muet serait un faux négatif silencieux.
async fn decouvrir_skills_loggue<F>(scan: F) -> Vec<SkillDecouvert>
where
    F: FnOnce() -> Vec<SkillDecouvert> + Send + 'static,
{
    match tokio::task::spawn_blocking(scan).await {
        Ok(skills) => skills,
        Err(e) => {
            tracing::error!(
                erreur = %e,
                "découverte des skills/agents échouée (tâche bloquante) — \
                 rapport produit sans skills"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Souscripteur de test minimal : lève un drapeau dès qu'un évènement de
    /// niveau `ERROR` est émis.
    struct CaptureErreur(Arc<AtomicBool>);

    impl tracing::Subscriber for CaptureErreur {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::ERROR {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Un panic du scan (→ `JoinError`) doit retomber sur un `Vec` vide ET
    /// émettre un log d'erreur — sans ce log on aurait un faux négatif muet.
    #[tokio::test]
    async fn join_error_loggue_et_retombe_sur_vide() {
        let flag = Arc::new(AtomicBool::new(false));
        let _guard = tracing::subscriber::set_default(CaptureErreur(flag.clone()));

        let skills = decouvrir_skills_loggue(|| panic!("scan disque cassé")).await;

        assert!(skills.is_empty());
        assert!(
            flag.load(Ordering::SeqCst),
            "un échec du join doit émettre un log de niveau ERROR"
        );
    }

    /// Cas nominal : le résultat du scan est transmis tel quel, sans log
    /// d'erreur.
    #[tokio::test]
    async fn succes_transmet_le_resultat() {
        let flag = Arc::new(AtomicBool::new(false));
        let _guard = tracing::subscriber::set_default(CaptureErreur(flag.clone()));

        let skills = decouvrir_skills_loggue(Vec::new).await;

        assert!(skills.is_empty());
        assert!(!flag.load(Ordering::SeqCst), "aucun ERROR attendu en cas de succès");
    }

    // ───────────────────────────────────────────────────────────────────────
    // F2 — câblage runtime sockets + baseline configs projet
    // ───────────────────────────────────────────────────────────────────────

    use crate::model::{ClientKind, ServeurMcpDeclare};
    use crate::runtime_inspector::{correler_avec_inventaire, SocketEnEcoute};
    use async_trait::async_trait;
    use sentinel_protocol::{ScopeServeur, Severite, TypeConstat};

    fn serveur(nom: &str, scope: ScopeServeur, commande: &str, url: Option<&str>) -> ServeurMcpDeclare {
        ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: if url.is_some() { "http".to_string() } else { "stdio".to_string() },
            commande: if url.is_some() { None } else { Some(commande.to_string()) },
            args: vec![],
            env_keys: vec![],
            url: url.map(str::to_string),
            disabled: false,
            scope,
        }
    }

    fn client_avec(kind: ClientKind, serveurs: Vec<ServeurMcpDeclare>) -> ClientDecouvert {
        let mut c = ClientDecouvert::nouveau(kind);
        c.serveurs = serveurs;
        c
    }

    fn rapport_avec(clients: Vec<ClientDecouvert>) -> RapportDecouverte {
        let t = Utc::now();
        RapportDecouverte {
            clients,
            sockets_observes: vec![],
            constats_runtime: vec![],
            demarre_a: t,
            termine_a: t,
        }
    }

    fn socket_bind_all(port: u16) -> SocketEnEcoute {
        SocketEnEcoute {
            protocole: "tcp".to_string(),
            adresse: "0.0.0.0".to_string(),
            port,
            pid: Some(4242),
            processus: Some("node".to_string()),
            bind_toutes_interfaces: true,
        }
    }

    /// Source synthétique qui rend un client fixe (aucun accès disque/système).
    struct SourceFixe(ClientDecouvert);

    #[async_trait]
    impl SourceClient for SourceFixe {
        fn id(&self) -> &'static str {
            "fixe-test"
        }
        async fn detecter(&self) -> Vec<ClientDecouvert> {
            vec![self.0.clone()]
        }
    }

    /// `serveurs_declares` aplatit l'inventaire de tous les clients.
    #[test]
    fn serveurs_declares_aplatit_les_clients() {
        let r = rapport_avec(vec![
            client_avec(ClientKind::Cursor, vec![serveur("a", ScopeServeur::User, "npx", None)]),
            client_avec(
                ClientKind::ClaudeCodeCli,
                vec![serveur(
                    "b",
                    ScopeServeur::Project { path: "/repo".to_string() },
                    "node",
                    None,
                )],
            ),
        ]);
        assert_eq!(r.serveurs_declares().len(), 2);
    }

    /// `serveurs_projet` ne regroupe que la portée projet (User ignorée).
    #[test]
    fn serveurs_projet_ignore_la_portee_user() {
        let r = rapport_avec(vec![client_avec(
            ClientKind::Cursor,
            vec![
                serveur("user-srv", ScopeServeur::User, "npx", None),
                serveur("proj-srv", ScopeServeur::Project { path: "/repo".to_string() }, "node", None),
            ],
        )]);
        let groupes = r.serveurs_projet();
        assert_eq!(groupes.len(), 1, "seule la config projet est regroupée");
        assert!(groupes.contains_key("/repo"));
        assert_eq!(groupes["/repo"].len(), 1);
    }

    /// `observer_baseline` : 1ʳᵉ observation silencieuse, puis l'échange de
    /// commande d'un serveur projet approuvé par nom est détecté (MCPoison).
    #[test]
    fn observer_baseline_detecte_mcpoison_apres_premiere_observation() {
        let mut baseline = BaselineConfigsProjet::new();
        let proj = ScopeServeur::Project { path: "/repo".to_string() };

        let r1 = rapport_avec(vec![client_avec(
            ClientKind::Cursor,
            vec![serveur("fs", proj.clone(), "npx", None)],
        )]);
        // Première observation : rien à comparer.
        assert!(r1.observer_baseline(&mut baseline).is_empty());

        // Même nom approuvé, commande échangée → RugPull critique (CVE-2025-54136).
        let r2 = rapport_avec(vec![client_avec(
            ClientKind::Cursor,
            vec![serveur("fs", proj, "/tmp/evil.sh", None)],
        )]);
        let constats = r2.observer_baseline(&mut baseline);
        assert_eq!(constats.len(), 1);
        assert_eq!(constats[0].type_constat, TypeConstat::RugPull);
        assert_eq!(constats[0].severite, Severite::Critique);
    }

    /// Wiring runtime : un socket bind-all inconnu est rapporté ; un socket dont
    /// le port est dans l'inventaire déclaré ne l'est pas.
    #[test]
    fn correlation_runtime_utilise_l_inventaire_du_rapport() {
        let r = rapport_avec(vec![client_avec(
            ClientKind::Cursor,
            vec![serveur("local", ScopeServeur::User, "", Some("http://0.0.0.0:8080/mcp"))],
        )]);
        let inventaire = r.serveurs_declares();
        // 8080 est déclaré (connu) ; 9000 ne l'est pas.
        let sockets = vec![socket_bind_all(8080), socket_bind_all(9000)];
        let constats = correler_avec_inventaire(&sockets, &inventaire);
        assert_eq!(constats.len(), 1, "seul le port hors inventaire est signalé");
        assert!(constats[0].titre.contains("9000"));
        assert_eq!(constats[0].type_constat, TypeConstat::ShadowMcp);
    }

    /// Faux positif proscrit : sans aucun socket observé, rien n'est inventé,
    /// même avec un inventaire vide.
    #[test]
    fn correlation_runtime_environnement_vide_n_invente_rien() {
        let r = rapport_avec(vec![]);
        let constats = correler_avec_inventaire(&[], &r.serveurs_declares());
        assert!(constats.is_empty());
    }

    /// `sans_runtime` : le balayage n'invoque pas le système et produit des
    /// champs runtime vides — utile pour des tests déterministes.
    #[tokio::test]
    async fn balayer_sans_runtime_laisse_les_champs_runtime_vides() {
        let client = client_avec(ClientKind::Cursor, vec![]);
        let orch = OrchestrateurDecouverte::nouveau(vec![Box::new(SourceFixe(client))])
            .sans_skills()
            .sans_runtime();
        let rapport = orch.balayer().await;
        assert_eq!(rapport.clients.len(), 1);
        assert!(rapport.sockets_observes.is_empty());
        assert!(rapport.constats_runtime.is_empty());
    }

    /// Robustesse : le balayage avec inspection runtime activée ne panique
    /// jamais, même si `lsof`/`ss` sont absents (best-effort).
    #[tokio::test]
    async fn balayer_avec_runtime_ne_panique_pas() {
        let client = client_avec(ClientKind::Cursor, vec![]);
        let orch = OrchestrateurDecouverte::nouveau(vec![Box::new(SourceFixe(client))]).sans_skills();
        // On ne fait aucune assertion sur le nombre de sockets (dépend de la
        // machine) : seul l'absence de panic et la cohérence du rapport comptent.
        let rapport = orch.balayer().await;
        assert_eq!(rapport.clients.len(), 1);
    }
}
