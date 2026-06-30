-- V6 — Reset unique des constats/alertes hérités (déduplication).
--
-- Avant cette version, chaque détection produisait un `id` ALÉATOIRE
-- (Uuid::new_v4) et le store faisait un INSERT aveugle : la boucle de
-- surveillance continue ré-insérait donc le MÊME constat logique à chaque
-- cycle (toutes les ~30 s), gonflant la table de centaines de doublons
-- identiques (p. ex. la règle YARA « MCP_Exfiltration_Reseau » sur
-- read_media_file vue 200+ fois).
--
-- À partir de maintenant, l'`id` d'un constat est DÉTERMINISTE (dérivé du
-- contenu via `sentinel_detect::id_constat`) et `enregistrer_constat` fait un
-- UPSERT — une re-détection retombe sur la même ligne. Cette migration vide
-- une fois pour toutes les lignes héritées (id aléatoires, impossibles à
-- ré-aligner sur le nouvel id en SQL pur). Les constats sont des sorties de
-- détection TRANSITOIRES : ils se repeuplent intégralement au prochain scan,
-- cette fois dédupliqués.
--
-- N'affecte QUE `constats` et `alertes` (qui référence constats.id). Les
-- approbations, tags, baselines, historique et inventaire sont préservés.

DELETE FROM alertes;
DELETE FROM constats;
