-- V1 — schéma initial de Sentinel MCP. Copie verbatim de l'ancien
-- `SCHEMA_SQL` (constante avant refonte refinery). Aucun `IF NOT EXISTS`
-- n'est requis : refinery garantit qu'une migration n'est appliquée
-- qu'une seule fois. On garde quand même `IF NOT EXISTS` pour la
-- compatibilité avec les DB existantes qui se réouvrent (refinery
-- détecte par hash que la migration a déjà tourné — voir lib.rs).

CREATE TABLE IF NOT EXISTS serveurs (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    transport TEXT NOT NULL,
    portees TEXT NOT NULL,
    statut TEXT NOT NULL,
    couleur TEXT NOT NULL,
    premiere_vue TEXT NOT NULL,
    derniere_vue TEXT NOT NULL,
    empreinte_courante TEXT
);

CREATE TABLE IF NOT EXISTS outils (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    nom TEXT NOT NULL,
    description TEXT,
    input_schema TEXT NOT NULL,
    empreinte TEXT NOT NULL,
    UNIQUE(serveur_id, nom),
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    empreinte_serveur TEXT NOT NULL,
    empreintes_outils TEXT NOT NULL,
    outils TEXT NOT NULL,
    date_approbation TEXT NOT NULL,
    approuve_par TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS historique_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serveur_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    methode TEXT NOT NULL,
    horodatage TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE INDEX IF NOT EXISTS idx_hist_serveur ON historique_contacts(serveur_id);

CREATE TABLE IF NOT EXISTS constats (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    outil_nom TEXT,
    type_constat TEXT NOT NULL,
    severite TEXT NOT NULL,
    titre TEXT NOT NULL,
    detail TEXT NOT NULL,
    diff TEXT,
    references_conformite TEXT NOT NULL,
    horodatage TEXT NOT NULL,
    etat TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS alertes (
    id TEXT PRIMARY KEY,
    constat_id TEXT NOT NULL,
    canal TEXT NOT NULL,
    severite TEXT NOT NULL,
    titre TEXT NOT NULL,
    message TEXT NOT NULL,
    diff TEXT,
    horodatage TEXT NOT NULL,
    envoyee INTEGER NOT NULL,
    tentatives INTEGER NOT NULL,
    FOREIGN KEY(constat_id) REFERENCES constats(id)
);

CREATE TABLE IF NOT EXISTS inventaire_approuve (
    serveur_id TEXT PRIMARY KEY,
    approuve INTEGER NOT NULL,
    note TEXT,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    note TEXT NOT NULL,
    cree_par TEXT NOT NULL,
    cree_a TEXT NOT NULL,
    etat TEXT NOT NULL DEFAULT '"ouvert"'
);

CREATE INDEX IF NOT EXISTS idx_investigations_serveur ON investigations(serveur_id);
