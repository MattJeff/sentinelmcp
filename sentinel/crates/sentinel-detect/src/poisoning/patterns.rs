//! Bibliothèque de patterns de poisoning — agent 3.6.
//! Couvre SAFE-T1001 (Tool Poisoning) / OWASP MCP03.
//!
//! Huit catégories :
//!   1. instructions_imperatives — manipulation directe du modèle (Haute)
//!   2. chemins_sensibles        — accès fichiers secrets (Critique)
//!   3. balises_pseudo_systeme   — injection de contexte privilégié (Critique)
//!   4. texte_invisible_encode   — obfuscation / stéganographie (Moyenne)
//!   5. lecture_exfiltration     — vol de secrets / envoi réseau (Critique)
//!   6. injection_commande       — métacaractères shell + binaire réseau/shell (Critique)
//!   7. persistance_memoire      — persistance mémoire / réponse suivante, OWASP ASI06 (Haute)
//!   8. demande_secrets          — demande de mot de passe / clé API / paiement / PII (Critique)

use sentinel_protocol::Severite;

/// Définition d'un pattern de détection.
pub struct Pattern {
    pub nom: &'static str,
    pub categorie: &'static str,
    pub regex: &'static str,
    pub severite: Severite,
}

/// Retourne l'ensemble des patterns de détection versionnés (v1.0.0).
pub fn bibliotheque() -> Vec<Pattern> {
    vec![
        // ── 1. INSTRUCTIONS IMPÉRATIVES AU MODÈLE ────────────────────────────
        Pattern {
            nom: "ignore_instructions_precedentes",
            categorie: "instructions_imperatives",
            regex: r"(?i)\b(ignore|disregard|forget|override)\b.{0,60}(previous|prior|earlier|above)\s+instructions",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "avant_de_repondre",
            categorie: "instructions_imperatives",
            regex: r"(?i)before\s+you\s+(respond|answer|reply|continue)",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "vous_devez_maintenant",
            categorie: "instructions_imperatives",
            regex: r"(?i)you\s+must\s+(now|first|always|immediately)\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "pretendre_etre",
            categorie: "instructions_imperatives",
            regex: r"(?i)\bpretend\s+to\s+be\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "agir_comme_si",
            categorie: "instructions_imperatives",
            regex: r"(?i)\bact\s+as\s+if\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "ne_suivez_pas_les_regles",
            categorie: "instructions_imperatives",
            regex: r"(?i)(do\s+not|don't|never)\s+(follow|obey|apply|respect)\s+(the\s+)?(rules|guidelines|instructions|restrictions|constraints)",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "nouveau_prompt_systeme",
            categorie: "instructions_imperatives",
            regex: r"(?i)(new|updated|revised)\s+(system\s+)?(prompt|instruction|directive)\s*:",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "ignorer_contexte_precedent",
            categorie: "instructions_imperatives",
            regex: r"(?i)\b(discard|clear|reset|wipe)\s+(all\s+)?(previous|prior|earlier|above|context|history)",
            severite: Severite::Haute,
        },

        // ── 2. CHEMINS SENSIBLES ──────────────────────────────────────────────
        Pattern {
            nom: "chemin_ssh",
            categorie: "chemins_sensibles",
            regex: r"~/\.ssh\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "fichier_env",
            categorie: "chemins_sensibles",
            regex: r"(?:^|[\s/])\.env(?:\b|$)",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "etc_passwd",
            categorie: "chemins_sensibles",
            regex: r"/etc/passwd\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "etc_shadow",
            categorie: "chemins_sensibles",
            regex: r"/etc/shadow\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "cle_rsa_privee",
            categorie: "chemins_sensibles",
            regex: r"\bid_rsa\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "credentials_aws",
            categorie: "chemins_sensibles",
            regex: r"\.aws/credentials\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "config_kube",
            categorie: "chemins_sensibles",
            regex: r"\.kube/config\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "fichier_netrc",
            categorie: "chemins_sensibles",
            regex: r"~/\.netrc\b",
            severite: Severite::Critique,
        },

        // ── 3. BALISES PSEUDO-SYSTÈME ─────────────────────────────────────────
        Pattern {
            nom: "balise_system",
            categorie: "balises_pseudo_systeme",
            regex: r"\[SYSTEM\]",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_admin",
            categorie: "balises_pseudo_systeme",
            regex: r"\[ADMIN\]",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_instruction",
            categorie: "balises_pseudo_systeme",
            regex: r"\[INSTRUCTION\]",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_sys_llama",
            categorie: "balises_pseudo_systeme",
            regex: r"<<SYS>>",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "override_protocol",
            categorie: "balises_pseudo_systeme",
            regex: r"(?i)\boverride\s+protocol\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_prompt_injection",
            categorie: "balises_pseudo_systeme",
            regex: r"(?i)<\s*(system|s)\s*>",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_root_access",
            categorie: "balises_pseudo_systeme",
            regex: r"(?i)\[ROOT[-_]?(ACCESS|OVERRIDE|COMMAND)\]",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "balise_important_wrapper",
            categorie: "balises_pseudo_systeme",
            regex: r"(?i)<\s*important\s*>",
            severite: Severite::Critique,
        },

        // ── 4. TEXTE INVISIBLE / ENCODÉ ───────────────────────────────────────
        Pattern {
            nom: "caractere_zero_width",
            categorie: "texte_invisible_encode",
            regex: r"[\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}]",
            severite: Severite::Moyenne,
        },
        Pattern {
            nom: "caractere_jointure_invisible",
            categorie: "texte_invisible_encode",
            regex: r"[\u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\u{2065}\u{2066}\u{2067}\u{2068}\u{2069}]",
            severite: Severite::Moyenne,
        },
        Pattern {
            nom: "base64_inline_long",
            categorie: "texte_invisible_encode",
            regex: r"[A-Za-z0-9+/]{40,}={0,2}",
            severite: Severite::Moyenne,
        },
        Pattern {
            nom: "sequence_hex_inline",
            categorie: "texte_invisible_encode",
            regex: r"\\x[0-9a-fA-F]{2}",
            severite: Severite::Moyenne,
        },
        Pattern {
            nom: "unicode_escape_inline",
            categorie: "texte_invisible_encode",
            regex: r"\\u[0-9a-fA-F]{4}",
            severite: Severite::Moyenne,
        },
        Pattern {
            nom: "caractere_rtl_override",
            categorie: "texte_invisible_encode",
            regex: r"[\u{202A}-\u{202E}]",
            severite: Severite::Moyenne,
        },

        // ── 5. LECTURE / EXFILTRATION DE SECRETS ─────────────────────────────
        Pattern {
            nom: "lecture_secret_direct",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bread\s+the\s+(secret|key|token|password|credential)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "lecture_repertoire_home",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bread\s+~/",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "envoi_vers_http",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bsend\s+(it\s+)?to\s+https?://",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "exfiltrer",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bexfiltrate\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "curl_url_distant",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bcurl\s+https?://[^\s]+",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "wget_url_distant",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\bwget\s+https?://[^\s]+",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "post_donnees_sensibles",
            categorie: "lecture_exfiltration",
            regex: r"(?i)\b(post|upload|transmit|leak)\s+(the\s+)?(secret|token|key|password|credentials)\b",
            severite: Severite::Critique,
        },

        // ── 6. INJECTION DE COMMANDE (métacaractères shell — règle Datadog) ──
        Pattern {
            nom: "point_virgule_binaire_reseau",
            categorie: "injection_commande",
            regex: r"(?i);\s*(curl|wget|nc|bash|sh)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "pipe_vers_shell",
            categorie: "injection_commande",
            regex: r"(?i)\|\s*(bash|sh|zsh)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "chainage_binaire_reseau",
            categorie: "injection_commande",
            regex: r"(?i)&&\s*(curl|wget|nc)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "substitution_commande_reseau",
            categorie: "injection_commande",
            regex: r"(?i)\$\(\s*(curl|wget)\b",
            severite: Severite::Critique,
        },

        // ── 7. PERSISTANCE MÉMOIRE / CONTEXTE (OWASP ASI06, sampling Unit 42) ─
        Pattern {
            nom: "souvenir_permanent",
            categorie: "persistance_memoire",
            regex: r"(?i)\bremember\s+(this|these|it)\b.{0,40}\b(future|always|every|all\s+sessions?)\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "ecriture_memoire",
            categorie: "persistance_memoire",
            regex: r"(?i)\b(add|store|save|write|persist)\b.{0,30}\b(to|into|in)\s+(your\s+)?(long[\s-]?term\s+)?memory\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "directive_prochaine_reponse",
            categorie: "persistance_memoire",
            regex: r"(?i)\b(add|include|append|insert)\b.{0,40}\b(to|in)\s+your\s+next\s+(response|reply|message)\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "desormais_toujours",
            categorie: "persistance_memoire",
            regex: r"(?i)\bfrom\s+now\s+on\b.{0,40}\b(always|never|every|each)\b",
            severite: Severite::Haute,
        },
        Pattern {
            nom: "sessions_futures",
            categorie: "persistance_memoire",
            regex: r"(?i)\b(in|for|across)\s+(all\s+)?future\s+(sessions?|conversations?|responses?)\b",
            severite: Severite::Haute,
        },

        // ── 8. DEMANDE DE SECRETS (interdit par la spec MCP — elicitation) ───
        Pattern {
            nom: "demande_mot_de_passe",
            categorie: "demande_secrets",
            regex: r"(?i)\b(enter|provide|type|paste|input|confirm|share)\b.{0,30}\byour\s+(password|passphrase)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "demande_cle_api",
            categorie: "demande_secrets",
            regex: r"(?i)\b(enter|provide|type|paste|input|share)\b.{0,30}\b(api[\s_-]?key|access[\s_-]?token|secret[\s_-]?key|private\s+key)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "demande_paiement",
            categorie: "demande_secrets",
            regex: r"(?i)\b(credit\s+card\s+number|card\s+number|cvv|cvc|iban)\b",
            severite: Severite::Critique,
        },
        Pattern {
            nom: "demande_pii",
            categorie: "demande_secrets",
            regex: r"(?i)\b(social\s+security\s+number|ssn|passport\s+number)\b",
            severite: Severite::Critique,
        },
    ]
}
