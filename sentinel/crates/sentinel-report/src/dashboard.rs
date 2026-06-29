//! Tableau de bord d'inventaire — agent 5.8.
//!
//! Une carte par serveur (nom, outils, portée, statut, couleur),
//! remplissage progressif pendant le scan, filtres, vue détail avec diff.
//! Lit le store en lecture seule.

use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::header,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use sentinel_alerts::metrics::{rendre_prometheus, Metriques, CONTENT_TYPE_PROMETHEUS};
use sentinel_protocol::{Couleur, Outil, ServeurId, StatutServeur, Transport};
use sentinel_store::Store;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Carte résumée d'un serveur, exposée via l'API et l'UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CarteServeur {
    pub id: String,
    pub endpoint: String,
    pub transport: String,
    pub statut: String,
    pub couleur: String,
    pub portees: Vec<String>,
    pub nombre_outils: u64,
    pub premiere_vue: String,
    pub derniere_vue: String,
    pub empreinte_courante: Option<String>,
}

/// Vue détaillée d'un serveur (cartes + outils + constats ouverts).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetailServeur {
    pub serveur: CarteServeur,
    pub outils: Vec<Outil>,
    pub constats_ouverts: u64,
}

// ---------------------------------------------------------------------------
// Helpers de conversion
// ---------------------------------------------------------------------------

fn libelle_transport(t: Transport) -> &'static str {
    match t {
        Transport::Stdio => "stdio",
        Transport::Http => "http",
    }
}

fn libelle_statut(s: StatutServeur) -> &'static str {
    match s {
        StatutServeur::Approuve => "approuve",
        StatutServeur::Inconnu => "inconnu",
        StatutServeur::Suspect => "suspect",
        StatutServeur::AInvestiguer => "a_investiguer",
        StatutServeur::Bloque => "bloque",
    }
}

fn libelle_couleur(c: Couleur) -> &'static str {
    match c {
        Couleur::Vert => "vert",
        Couleur::Orange => "orange",
        Couleur::Rouge => "rouge",
    }
}

fn libelle_portee(p: &sentinel_protocol::Portee) -> &'static str {
    use sentinel_protocol::Portee;
    match p {
        Portee::Filesystem => "filesystem",
        Portee::BaseDonnees => "base_donnees",
        Portee::ApiExterne => "api_externe",
        Portee::Secrets => "secrets",
        Portee::Reseau => "reseau",
        Portee::Lecture => "lecture",
        Portee::Ecriture => "ecriture",
        Portee::Inconnu => "inconnu",
    }
}

fn serveur_en_carte(s: &sentinel_protocol::Serveur, nombre_outils: u64) -> CarteServeur {
    CarteServeur {
        id: s.id.to_string(),
        endpoint: s.endpoint.clone(),
        transport: libelle_transport(s.transport).to_string(),
        statut: libelle_statut(s.statut).to_string(),
        couleur: libelle_couleur(s.couleur).to_string(),
        portees: s.portees.iter().map(|p| libelle_portee(p).to_string()).collect(),
        nombre_outils,
        premiere_vue: s.premiere_vue.to_rfc3339(),
        derniere_vue: s.derniere_vue.to_rfc3339(),
        empreinte_courante: s.empreinte_courante.clone(),
    }
}

// ---------------------------------------------------------------------------
// TableauBord
// ---------------------------------------------------------------------------

/// Tableau de bord d'inventaire. Lit le store en lecture seule.
pub struct TableauBord {
    pub store: Store,
}

impl TableauBord {
    /// Crée un nouveau tableau de bord à partir d'un store.
    pub fn nouveau(store: Store) -> Self {
        Self { store }
    }

    /// Construit la liste complète des cartes pour l'UI.
    pub fn cartes(&self) -> Result<Vec<CarteServeur>> {
        let serveurs = self.store.lister_serveurs()?;
        let mut cartes = Vec::with_capacity(serveurs.len());
        for s in &serveurs {
            let outils = self.store.lister_outils(s.id)?;
            cartes.push(serveur_en_carte(s, outils.len() as u64));
        }
        Ok(cartes)
    }

    /// Retourne les cartes filtrées par couleur de criticité.
    pub fn cartes_par_couleur(&self, c: Couleur) -> Result<Vec<CarteServeur>> {
        let toutes = self.cartes()?;
        let filtre = libelle_couleur(c);
        Ok(toutes.into_iter().filter(|carte| carte.couleur == filtre).collect())
    }

    /// Retourne le détail complet d'un serveur : carte + outils + constats ouverts.
    pub fn detail(&self, serveur_id: ServeurId) -> Result<DetailServeur> {
        let serveurs = self.store.lister_serveurs()?;
        let s = serveurs
            .iter()
            .find(|s| s.id == serveur_id)
            .ok_or_else(|| anyhow::anyhow!("Serveur introuvable : {}", serveur_id))?;

        let outils = self.store.lister_outils(serveur_id)?;
        let carte = serveur_en_carte(s, outils.len() as u64);

        let constats_ouverts = self
            .store
            .lister_constats_ouverts()?
            .into_iter()
            .filter(|c| c.serveur_id == serveur_id)
            .count() as u64;

        Ok(DetailServeur {
            serveur: carte,
            outils,
            constats_ouverts,
        })
    }

    /// Démarre le serveur HTTP sur le port donné.
    ///
    /// Endpoints :
    ///   GET /api/cartes              → liste toutes les cartes
    ///   GET /api/cartes/{couleur}    → liste filtrée par couleur (vert|orange|rouge)
    ///   GET /api/detail/{id}         → détail d'un serveur par UUID
    ///   GET /metrics                 → métriques d'observabilité Prometheus
    ///   GET /                        → page HTML minimaliste
    pub async fn servir(&self, port: u16) -> Result<()> {
        let store = Arc::new(self.store.clone());
        let app = Router::new()
            .route("/", get(handle_index))
            .route("/api/cartes", get(handle_cartes))
            .route("/api/cartes/:couleur", get(handle_cartes_couleur))
            .route("/api/detail/:id", get(handle_detail))
            .route("/metrics", get(handle_metrics))
            .with_state(store);

        let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Tableau de bord Sentinel MCP sur http://{}", addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handlers axum
// ---------------------------------------------------------------------------

async fn handle_index() -> Html<&'static str> {
    Html(PAGE_HTML)
}

async fn handle_cartes(State(store): State<Arc<Store>>) -> Result<Json<Vec<CarteServeur>>, String> {
    let tb = TableauBord::nouveau((*store).clone());
    tb.cartes().map(Json).map_err(|e| e.to_string())
}

async fn handle_cartes_couleur(
    State(store): State<Arc<Store>>,
    Path(couleur): Path<String>,
) -> Result<Json<Vec<CarteServeur>>, String> {
    let c = parse_couleur(&couleur)
        .ok_or_else(|| format!("Couleur inconnue : {}", couleur))?;
    let tb = TableauBord::nouveau((*store).clone());
    tb.cartes_par_couleur(c).map(Json).map_err(|e| e.to_string())
}

async fn handle_detail(
    State(store): State<Arc<Store>>,
    Path(id): Path<String>,
) -> Result<Json<DetailServeur>, String> {
    let serveur_id: ServeurId = id.parse().map_err(|_| format!("UUID invalide : {}", id))?;
    let tb = TableauBord::nouveau((*store).clone());
    tb.detail(serveur_id).map(Json).map_err(|e| e.to_string())
}

/// Expose les métriques d'observabilité au format Prometheus
/// (`text/plain; version=0.0.4`).
///
/// Construites en **lecture seule** depuis le store (serveurs, constats,
/// alertes, outils). En cas d'erreur de collecte, renvoie un commentaire
/// Prometheus (toujours 200, content-type stable) plutôt qu'une erreur HTTP,
/// pour ne pas casser un scraper.
async fn handle_metrics(State(store): State<Arc<Store>>) -> impl IntoResponse {
    let corps = match store.stats_metriques() {
        Ok(stats) => rendre_prometheus(&Metriques::depuis_stats_store(&stats)),
        Err(e) => format!("# erreur de collecte des métriques: {}\n", e),
    };
    (
        [(header::CONTENT_TYPE, CONTENT_TYPE_PROMETHEUS)],
        corps,
    )
}

fn parse_couleur(s: &str) -> Option<Couleur> {
    match s {
        "vert" => Some(Couleur::Vert),
        "orange" => Some(Couleur::Orange),
        "rouge" => Some(Couleur::Rouge),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Page HTML inline
// ---------------------------------------------------------------------------

const PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Sentinel MCP — Tableau de bord</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0f1117; color: #e2e8f0; padding: 1.5rem; }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; color: #f8fafc; }
    #filtres { display: flex; gap: 0.5rem; margin-bottom: 1.25rem; }
    button { padding: 0.4rem 1rem; border: none; border-radius: 6px; cursor: pointer;
             font-size: 0.85rem; background: #1e293b; color: #94a3b8; }
    button.actif { background: #334155; color: #f8fafc; }
    button.rouge { border-left: 3px solid #ef4444; }
    button.orange { border-left: 3px solid #f97316; }
    button.vert { border-left: 3px solid #22c55e; }
    #grille { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1rem; }
    .carte { background: #1e293b; border-radius: 10px; padding: 1rem;
             border-left: 5px solid #475569; }
    .carte.rouge { border-left-color: #ef4444; }
    .carte.orange { border-left-color: #f97316; }
    .carte.vert { border-left-color: #22c55e; }
    .carte h2 { font-size: 0.95rem; word-break: break-all; margin-bottom: 0.5rem; }
    .meta { font-size: 0.78rem; color: #94a3b8; margin-top: 0.25rem; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
             font-size: 0.72rem; font-weight: 600; text-transform: uppercase; margin-right: 0.3rem; }
    .badge.rouge { background: #450a0a; color: #fca5a5; }
    .badge.orange { background: #431407; color: #fdba74; }
    .badge.vert { background: #052e16; color: #86efac; }
    .detail-btn { margin-top: 0.75rem; font-size: 0.78rem; padding: 0.3rem 0.7rem;
                  background: #334155; color: #cbd5e1; border-radius: 4px; border: none; cursor: pointer; }
    #modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.7);
                     z-index: 100; align-items: center; justify-content: center; }
    #modal-overlay.visible { display: flex; }
    #modal { background: #1e293b; border-radius: 12px; padding: 1.5rem; max-width: 640px;
             width: 90%; max-height: 80vh; overflow-y: auto; }
    #modal h2 { font-size: 1rem; margin-bottom: 0.75rem; }
    #modal pre { background: #0f172a; padding: 0.75rem; border-radius: 6px;
                 font-size: 0.75rem; white-space: pre-wrap; overflow-wrap: anywhere; }
    #fermer { float: right; background: #ef4444; color: #fff; border: none;
              border-radius: 4px; padding: 0.2rem 0.6rem; cursor: pointer; font-size: 0.8rem; }
    #chargement { color: #64748b; font-size: 0.9rem; }
  </style>
</head>
<body>
  <h1>Sentinel MCP — Inventaire des serveurs</h1>
  <div id="filtres">
    <button class="actif" onclick="filtrer(null, this)">Tous</button>
    <button class="rouge" onclick="filtrer('rouge', this)">Rouge</button>
    <button class="orange" onclick="filtrer('orange', this)">Orange</button>
    <button class="vert" onclick="filtrer('vert', this)">Vert</button>
  </div>
  <div id="grille"><span id="chargement">Chargement...</span></div>

  <div id="modal-overlay">
    <div id="modal">
      <button id="fermer" onclick="fermerModal()">Fermer</button>
      <h2 id="modal-titre">Détail</h2>
      <div id="modal-corps"></div>
    </div>
  </div>

  <script>
    let toutesLesCartes = [];

    async function charger() {
      try {
        const r = await fetch('/api/cartes');
        toutesLesCartes = await r.json();
        afficher(toutesLesCartes);
      } catch (e) {
        document.getElementById('chargement').textContent = 'Erreur de chargement : ' + e.message;
      }
    }

    function afficher(cartes) {
      const g = document.getElementById('grille');
      if (!cartes.length) { g.innerHTML = '<span id="chargement">Aucun serveur détecté.</span>'; return; }
      g.innerHTML = cartes.map(c => `
        <div class="carte ${c.couleur}">
          <h2>${escHtml(c.endpoint)}</h2>
          <span class="badge ${c.couleur}">${c.couleur}</span>
          <span class="badge" style="background:#1e3a5f;color:#93c5fd">${escHtml(c.transport)}</span>
          <p class="meta">Statut : ${escHtml(c.statut)}</p>
          <p class="meta">Outils : ${c.nombre_outils}</p>
          ${c.portees.length ? '<p class="meta">Portées : ' + c.portees.map(escHtml).join(', ') + '</p>' : ''}
          <p class="meta">Première vue : ${escHtml(c.premiere_vue)}</p>
          <p class="meta">Dernière vue : ${escHtml(c.derniere_vue)}</p>
          ${c.empreinte_courante ? '<p class="meta" style="font-family:monospace;font-size:.7rem">' + escHtml(c.empreinte_courante) + '</p>' : ''}
          <button class="detail-btn" onclick="voirDetail('${escHtml(c.id)}')">Voir le détail</button>
        </div>
      `).join('');
    }

    function filtrer(couleur, btn) {
      document.querySelectorAll('#filtres button').forEach(b => b.classList.remove('actif'));
      btn.classList.add('actif');
      if (!couleur) { afficher(toutesLesCartes); return; }
      afficher(toutesLesCartes.filter(c => c.couleur === couleur));
    }

    async function voirDetail(id) {
      try {
        const r = await fetch('/api/detail/' + id);
        const d = await r.json();
        document.getElementById('modal-titre').textContent = d.serveur.endpoint;
        document.getElementById('modal-corps').innerHTML =
          '<p class="meta">Constats ouverts : <strong>' + d.constats_ouverts + '</strong></p>' +
          '<p class="meta" style="margin-top:.5rem">Outils (' + d.outils.length + ') :</p>' +
          '<pre>' + escHtml(JSON.stringify(d.outils, null, 2)) + '</pre>';
        document.getElementById('modal-overlay').classList.add('visible');
      } catch (e) {
        alert('Erreur : ' + e.message);
      }
    }

    function fermerModal() {
      document.getElementById('modal-overlay').classList.remove('visible');
    }

    function escHtml(s) {
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    charger();
    setInterval(charger, 15000);
  </script>
</body>
</html>
"#;
