//! Commandes Tauri pour la gestion des tags persistants posés sur les
//! serveurs MCP. Toutes les opérations sont locales (lecture/écriture
//! SQLite via `sentinel_store`) — aucun trafic sortant n'est généré.

use std::collections::HashSet;

use sentinel_protocol::ServeurId;
use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

/// Longueur maximale d'un tag (caractères UTF-8). Au-delà, on rejette
/// pour garder la sérialisation JSON compacte et éviter qu'un opérateur
/// ne colle accidentellement une description entière.
const TAG_MAX_LEN: usize = 32;
/// Nombre maximum de tags par serveur. Limite cosmétique qui évite les
/// dérives — l'inventaire reste lisible dans la UI.
const TAGS_MAX_PAR_SERVEUR: usize = 32;

/// Normalise une liste de tags brute reçue de la UI :
///  - trim
///  - filtre les vides
///  - valide la longueur (TAG_MAX_LEN)
///  - déduplique en préservant le premier ordre d'apparition
///  - rejette si on dépasse TAGS_MAX_PAR_SERVEUR
///
/// Retourne `Err(message)` si une contrainte est violée.
fn nettoyer_tags(brut: Vec<String>) -> Result<Vec<String>, String> {
    let mut vus: HashSet<String> = HashSet::new();
    let mut propres: Vec<String> = Vec::with_capacity(brut.len());
    for tag in brut {
        let t = tag.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if t.chars().count() > TAG_MAX_LEN {
            return Err(format!(
                "tag « {} » trop long (max {} caractères)",
                t, TAG_MAX_LEN
            ));
        }
        if vus.insert(t.clone()) {
            propres.push(t);
        }
    }
    if propres.len() > TAGS_MAX_PAR_SERVEUR {
        return Err(format!(
            "nombre de tags ({}) dépasse la limite ({})",
            propres.len(),
            TAGS_MAX_PAR_SERVEUR
        ));
    }
    Ok(propres)
}

#[tauri::command]
pub async fn server_set_tags(
    state: State<'_, AppState>,
    server_id: String,
    tags: Vec<String>,
) -> Result<(), String> {
    let id: ServeurId =
        Uuid::parse_str(&server_id).map_err(|e| format!("server_id invalide : {}", e))?;
    let propres = nettoyer_tags(tags)?;
    let store = state.store.clone();
    let n = tokio::task::spawn_blocking(move || store.definir_tags_serveur(&id, &propres))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("unknown server: {}", server_id));
    }
    Ok(())
}

#[tauri::command]
pub async fn server_list_tags(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.lister_tags_distincts())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nettoyer_trim_et_filtre_vides() {
        let r = nettoyer_tags(vec!["  prod ".into(), "".into(), "  ".into()]).unwrap();
        assert_eq!(r, vec!["prod".to_string()]);
    }

    #[test]
    fn nettoyer_deduplique_en_preservant_ordre() {
        let r = nettoyer_tags(vec![
            "a".into(),
            "b".into(),
            "a".into(),
            "c".into(),
            "b".into(),
        ])
        .unwrap();
        assert_eq!(r, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn nettoyer_rejette_tag_trop_long() {
        let long = "x".repeat(TAG_MAX_LEN + 1);
        let err = nettoyer_tags(vec![long]).unwrap_err();
        assert!(err.contains("trop long"), "message inattendu: {}", err);
    }

    #[test]
    fn nettoyer_accepte_pile_a_la_limite() {
        let pile = "x".repeat(TAG_MAX_LEN);
        let r = nettoyer_tags(vec![pile.clone()]).unwrap();
        assert_eq!(r, vec![pile]);
    }

    #[test]
    fn nettoyer_rejette_au_dela_du_max_tags() {
        let trop: Vec<String> = (0..(TAGS_MAX_PAR_SERVEUR + 1))
            .map(|i| format!("t{}", i))
            .collect();
        let err = nettoyer_tags(trop).unwrap_err();
        assert!(err.contains("dépasse la limite"), "message: {}", err);
    }

    #[test]
    fn nettoyer_compte_codepoints_pas_octets() {
        // 32 caractères français (accents) — chacun est 1 codepoint
        // mais peut occuper plusieurs octets en UTF-8. On doit accepter.
        let s: String = "é".repeat(TAG_MAX_LEN);
        let r = nettoyer_tags(vec![s.clone()]).unwrap();
        assert_eq!(r, vec![s]);
    }
}
