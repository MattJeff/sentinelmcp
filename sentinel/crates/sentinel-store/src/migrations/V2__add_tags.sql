-- V2 — Ajout d'un champ `tags` (JSON array) à la table `serveurs`.
-- Permet à l'opérateur d'étiqueter chaque serveur (prod/staging,
-- ownership, sensibilité…). Sérialisé en JSON pour rester souple
-- sans introduire de table dédiée tant que le volume reste faible.
ALTER TABLE serveurs ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
