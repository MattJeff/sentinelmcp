-- V3 — Ajout d'un champ `scope` sur `serveurs` pour distinguer les
-- déclarations top-level (`mcpServers` racine, scope user) des
-- déclarations sous `projects.<chemin>.mcpServers` (scope projet,
-- spécifique à un dossier de travail).
--
-- Sérialisation du scope dans la colonne TEXT :
--   * "user"               → `ScopeServeur::User`
--   * "project:<chemin>"   → `ScopeServeur::Project { path }`
--
-- Le séparateur logique est le **premier** `:` après "project". Un
-- chemin Windows (`project:C:\...`) reste donc parsable sans ambiguïté
-- via `strip_prefix("project:")`.
--
-- Migration non destructive : ALTER ADD COLUMN avec valeur par défaut
-- `'user'`, garantit la rétrocompat pour les DB qui n'ont que V1 ou V1+V2.
ALTER TABLE serveurs ADD COLUMN scope TEXT NOT NULL DEFAULT 'user';
CREATE INDEX IF NOT EXISTS idx_serveurs_scope ON serveurs(scope);
