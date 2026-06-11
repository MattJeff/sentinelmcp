-- V5 — historique versionné des baselines.
--
-- Jusqu'à V4, la table `baselines` accumulait les approbations sans
-- notion de version ni de raison : impossible de répondre à « qui a
-- changé quoi, quand, et pourquoi » ni de revenir à un état antérieur.
--
-- V5 ajoute `historique_baselines` : chaque enregistrement de baseline
-- y archive une version complète (empreintes + outils sérialisés) avec
-- un numéro de version monotone par serveur, l'approbateur et la
-- raison du changement (approbation initiale, ré-approbation, rollback,
-- import d'une golden baseline signée…). L'ancienne version n'est
-- jamais écrasée — elle reste consultable et restaurable via
-- `Store::rollback_baseline`, sous réserve du GC configurable
-- (`Store::gc_historique_baselines`, 50 versions par défaut).

CREATE TABLE IF NOT EXISTS historique_baselines (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    baseline_id TEXT NOT NULL,
    empreinte_serveur TEXT NOT NULL,
    empreintes_outils TEXT NOT NULL,
    outils TEXT NOT NULL,
    horodatage TEXT NOT NULL,
    approbateur TEXT NOT NULL,
    raison TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL,
    UNIQUE(serveur_id, version),
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE INDEX IF NOT EXISTS idx_hist_baselines_serveur
    ON historique_baselines(serveur_id);
