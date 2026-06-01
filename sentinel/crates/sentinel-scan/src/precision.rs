//! Banc de mesure du taux de faux positifs et du débit — Agent 1.8.
//!
//! Évalue la précision du pipeline de détection MCP (filtre grossier + confirmation)
//! sur un corpus contrôlé : trafic MCP réel d'un côté, leurres JSON-RPC de l'autre.

use sentinel_protocol::{Direction, EvenementBrut, Transport};
use serde_json::json;
use chrono::Utc;

// ------------------------------------------------------------------ //
// Rapport de précision                                                //
// ------------------------------------------------------------------ //

/// Métriques de précision issues d'une évaluation sur corpus.
#[derive(Debug, Default)]
pub struct RapportPrecision {
    /// Message non-MCP accepté à tort par le filtre.
    pub faux_positifs: u64,
    /// Message MCP rejeté à tort par le filtre.
    pub faux_negatifs: u64,
    /// Message MCP correctement accepté.
    pub vrais_positifs: u64,
    /// Message non-MCP correctement rejeté.
    pub vrais_negatifs: u64,
    /// Débit mesuré pendant l'évaluation (messages par seconde).
    pub debit_msg_par_sec: f64,
}

impl RapportPrecision {
    /// Précision = VP / (VP + FP). Retourne 1.0 si aucun positif prédit.
    pub fn precision(&self) -> f64 {
        let denominateur = self.vrais_positifs + self.faux_positifs;
        if denominateur == 0 {
            return 1.0;
        }
        self.vrais_positifs as f64 / denominateur as f64
    }

    /// Rappel = VP / (VP + FN). Retourne 1.0 si aucun positif réel.
    pub fn rappel(&self) -> f64 {
        let denominateur = self.vrais_positifs + self.faux_negatifs;
        if denominateur == 0 {
            return 1.0;
        }
        self.vrais_positifs as f64 / denominateur as f64
    }

    /// Score F1 = 2 × (précision × rappel) / (précision + rappel).
    /// Retourne 0.0 si les deux valent zéro.
    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.rappel();
        let denominateur = p + r;
        if denominateur == 0.0 {
            return 0.0;
        }
        2.0 * p * r / denominateur
    }
}

// ------------------------------------------------------------------ //
// Banc de mesure                                                      //
// ------------------------------------------------------------------ //

/// Corpus contrôlé pour évaluer le pipeline de détection.
pub struct BancMesure {
    /// Trafic MCP attendu : chaque message doit être accepté (vrai positif).
    pub corpus_mcp: Vec<EvenementBrut>,
    /// Leurres : chaque message doit être rejeté (vrai négatif).
    pub corpus_leurre: Vec<EvenementBrut>,
}

impl BancMesure {
    /// Construit le jeu de test par défaut avec ≥ 30 messages MCP et ≥ 30 leurres.
    pub fn jeu_par_defaut() -> Self {
        Self {
            corpus_mcp: construire_corpus_mcp(),
            corpus_leurre: construire_corpus_leurre(),
        }
    }

    /// Évalue un filtre binaire sur le corpus et retourne le rapport de précision.
    ///
    /// Le `filtre` doit retourner `true` pour les messages qu'il considère MCP.
    /// - corpus_mcp  → attendu `true`  (vrai positif si accepté, faux négatif sinon)
    /// - corpus_leurre → attendu `false` (vrai négatif si rejeté, faux positif sinon)
    pub fn evaluer<F>(&self, filtre: F) -> RapportPrecision
    where
        F: Fn(&EvenementBrut) -> bool,
    {
        use std::time::Instant;

        let total = (self.corpus_mcp.len() + self.corpus_leurre.len()) as u64;
        let debut = Instant::now();

        let mut rapport = RapportPrecision::default();

        for evt in &self.corpus_mcp {
            if filtre(evt) {
                rapport.vrais_positifs += 1;
            } else {
                rapport.faux_negatifs += 1;
            }
        }

        for evt in &self.corpus_leurre {
            if filtre(evt) {
                rapport.faux_positifs += 1;
            } else {
                rapport.vrais_negatifs += 1;
            }
        }

        let duree = debut.elapsed();
        rapport.debit_msg_par_sec = if duree.as_secs_f64() > 0.0 {
            total as f64 / duree.as_secs_f64()
        } else {
            f64::INFINITY
        };

        rapport
    }
}

// ------------------------------------------------------------------ //
// Constructeur du corpus MCP                                          //
// ------------------------------------------------------------------ //

fn evenement(methode: Option<&str>, payload: serde_json::Value) -> EvenementBrut {
    EvenementBrut {
        session_id: "session-bench-001".to_string(),
        transport: Transport::Http,
        serveur: "localhost:8080".to_string(),
        direction: Direction::ClientVersServeur,
        methode: methode.map(|s| s.to_string()),
        payload,
        horodatage: Utc::now(),
    }
}

/// Construit ≥ 30 messages MCP représentatifs de trafic réel.
fn construire_corpus_mcp() -> Vec<EvenementBrut> {
    let mut corpus = Vec::with_capacity(40);

    // --- initialize (requêtes et réponses) ---
    for id in 1u32..=6 {
        corpus.push(evenement(
            Some("initialize"),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "claude-code", "version": "1.0" }
                }
            }),
        ));
    }

    // Réponse serveur à initialize
    corpus.push(evenement(
        Some("initialize"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "filesystem-server", "version": "0.9" }
            }
        }),
    ));

    // --- tools/list (requêtes) ---
    for id in 10u32..=16 {
        corpus.push(evenement(
            Some("tools/list"),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/list",
                "params": {}
            }),
        ));
    }

    // Réponse tools/list (corpus central — vrais positifs)
    corpus.push(evenement(
        Some("tools/list"),
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Lit un fichier sur le système de fichiers.",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "path": { "type": "string" } },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "write_file",
                        "description": "Écrit dans un fichier.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "content"]
                        }
                    }
                ]
            }
        }),
    ));

    // --- tools/call ---
    for id in 20u32..=26 {
        corpus.push(evenement(
            Some("tools/call"),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": { "path": "/etc/hosts" }
                }
            }),
        ));
    }

    // --- notifications/tools/list_changed ---
    for _ in 0..4 {
        corpus.push(evenement(
            Some("notifications/tools/list_changed"),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            }),
        ));
    }

    // --- Batch JSON-RPC MCP (tableau de messages) ---
    corpus.push(evenement(
        Some("tools/list"),
        json!([
            { "jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {} },
            { "jsonrpc": "2.0", "id": 101, "method": "tools/call",
              "params": { "name": "bash", "arguments": { "cmd": "ls" } } }
        ]),
    ));

    corpus.push(evenement(
        Some("initialize"),
        json!([
            {
                "jsonrpc": "2.0",
                "id": 200,
                "method": "initialize",
                "params": { "protocolVersion": "2024-11-05", "capabilities": {} }
            }
        ]),
    ));

    // --- resources/list et prompts/list ---
    corpus.push(evenement(
        Some("resources/list"),
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "resources/list",
            "params": {}
        }),
    ));

    corpus.push(evenement(
        Some("prompts/list"),
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "prompts/list",
            "params": {}
        }),
    ));

    // Transport stdio
    let mut evt_stdio = evenement(
        Some("tools/list"),
        json!({ "jsonrpc": "2.0", "id": 50, "method": "tools/list", "params": {} }),
    );
    evt_stdio.transport = Transport::Stdio;
    corpus.push(evt_stdio);

    corpus
}

// ------------------------------------------------------------------ //
// Constructeur du corpus leurres                                      //
// ------------------------------------------------------------------ //

/// Construit ≥ 30 leurres couvrant les cas difficiles (LSP, Bitcoin, Ethereum,
/// HTTP banal, JSON ordinaire, MCP malformé).
fn construire_corpus_leurre() -> Vec<EvenementBrut> {
    let mut leurres = Vec::with_capacity(40);

    // --- LSP (Language Server Protocol) — piège principal ---
    // LSP utilise JSON-RPC 2.0 mais ses méthodes n'existent pas dans MCP.
    leurres.push(evenement(
        Some("initialize"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": 12345,
                "rootUri": "file:///home/user/project",
                "capabilities": {
                    "textDocument": { "hover": { "dynamicRegistration": true } }
                }
            }
        }),
    ));

    leurres.push(evenement(
        Some("textDocument/hover"),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/hover",
            "params": {
                "textDocument": { "uri": "file:///home/user/main.rs" },
                "position": { "line": 10, "character": 5 }
            }
        }),
    ));

    leurres.push(evenement(
        Some("textDocument/completion"),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/completion",
            "params": {
                "textDocument": { "uri": "file:///src/lib.rs" },
                "position": { "line": 42, "character": 12 }
            }
        }),
    ));

    leurres.push(evenement(
        Some("textDocument/definition"),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/definition",
            "params": {
                "textDocument": { "uri": "file:///src/main.rs" },
                "position": { "line": 5, "character": 8 }
            }
        }),
    ));

    leurres.push(evenement(
        Some("workspace/symbol"),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "workspace/symbol",
            "params": { "query": "EvenementBrut" }
        }),
    ));

    leurres.push(evenement(
        Some("textDocument/didOpen"),
        json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": "file:///src/lib.rs",
                    "languageId": "rust",
                    "version": 1,
                    "text": "fn main() {}"
                }
            }
        }),
    ));

    leurres.push(evenement(
        Some("$/cancelRequest"),
        json!({
            "jsonrpc": "2.0",
            "method": "$/cancelRequest",
            "params": { "id": 99 }
        }),
    ));

    // --- Bitcoin RPC ---
    leurres.push(evenement(
        Some("getblockcount"),
        json!({
            "jsonrpc": "2.0",
            "id": "btc-1",
            "method": "getblockcount",
            "params": []
        }),
    ));

    leurres.push(evenement(
        Some("getblockhash"),
        json!({
            "jsonrpc": "2.0",
            "id": "btc-2",
            "method": "getblockhash",
            "params": [700000]
        }),
    ));

    leurres.push(evenement(
        Some("getbalance"),
        json!({
            "jsonrpc": "2.0",
            "id": "btc-3",
            "method": "getbalance",
            "params": ["*", 6]
        }),
    ));

    leurres.push(evenement(
        Some("sendrawtransaction"),
        json!({
            "jsonrpc": "2.0",
            "id": "btc-4",
            "method": "sendrawtransaction",
            "params": ["0200000001ab..."]
        }),
    ));

    // --- Ethereum JSON-RPC ---
    leurres.push(evenement(
        Some("eth_blockNumber"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": []
        }),
    ));

    leurres.push(evenement(
        Some("eth_getBalance"),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getBalance",
            "params": ["0xd3CdA913deB6f4967b2Ef3aa68f5A843E21E401b", "latest"]
        }),
    ));

    leurres.push(evenement(
        Some("eth_call"),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "eth_call",
            "params": [
                { "to": "0xContractAddress", "data": "0x70a08231" },
                "latest"
            ]
        }),
    ));

    leurres.push(evenement(
        Some("eth_sendTransaction"),
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "eth_sendTransaction",
            "params": [{
                "from": "0xfrom",
                "to": "0xto",
                "value": "0x9184e72a000"
            }]
        }),
    ));

    leurres.push(evenement(
        Some("net_version"),
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "net_version",
            "params": []
        }),
    ));

    // --- HTTP banal (corps JSON sans JSON-RPC) ---
    leurres.push(evenement(
        None,
        json!({ "status": "ok", "code": 200, "data": null }),
    ));

    leurres.push(evenement(
        None,
        json!({
            "event": "page_view",
            "url": "https://example.com/dashboard",
            "user_id": 42
        }),
    ));

    leurres.push(evenement(
        None,
        json!({
            "metric": "cpu_usage",
            "value": 73.4,
            "timestamp": 1700000000,
            "host": "prod-01"
        }),
    ));

    leurres.push(evenement(
        None,
        json!({
            "type": "webhook",
            "action": "push",
            "ref": "refs/heads/main",
            "repository": { "name": "sentinel" }
        }),
    ));

    leurres.push(evenement(
        None,
        json!({
            "query": "{ user { id name email } }",
            "variables": { "id": 1 }
        }),
    ));

    // --- JSON ordinaire (pas JSON-RPC du tout) ---
    leurres.push(evenement(
        None,
        json!({ "version": "2.0", "app": "my-service", "health": "green" }),
    ));

    leurres.push(evenement(
        None,
        json!([1, 2, 3, 4, 5]),
    ));

    leurres.push(evenement(
        None,
        json!("une simple chaîne JSON"),
    ));

    leurres.push(evenement(
        None,
        json!(null),
    ));

    // --- MCP malformé : manque "jsonrpc" ---
    leurres.push(evenement(
        Some("tools/list"),
        json!({
            "id": 1,
            "method": "tools/list",
            "params": {}
            // Absence de "jsonrpc" — invalide JSON-RPC 2.0
        }),
    ));

    leurres.push(evenement(
        Some("initialize"),
        json!({
            "id": 2,
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" }
            // Absence de "jsonrpc"
        }),
    ));

    leurres.push(evenement(
        Some("tools/call"),
        json!({
            "version": "1.0",          // mauvaise clé de version
            "id": 3,
            "method": "tools/call",
            "params": { "name": "bash", "arguments": {} }
        }),
    ));

    // --- Cas edge : JSON-RPC 1.0 (pas 2.0) ---
    leurres.push(evenement(
        Some("tools/list"),
        json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "tools/list",
            "params": null
        }),
    ));

    // --- Autres protocoles JSON-RPC non-MCP ---
    leurres.push(evenement(
        Some("system.listMethods"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "system.listMethods",
            "params": []
        }),
    ));

    leurres.push(evenement(
        Some("debug_traceTransaction"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "debug_traceTransaction",
            "params": ["0xTransactionHash"]
        }),
    ));

    leurres.push(evenement(
        Some("personal_sign"),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "personal_sign",
            "params": ["0xdeadbeef", "0xaddress"]
        }),
    ));

    leurres.push(evenement(
        Some("generateaddress"),
        json!({
            "jsonrpc": "2.0",
            "id": "wallet-1",
            "method": "generateaddress",
            "params": { "network": "mainnet" }
        }),
    ));

    leurres
}

// ------------------------------------------------------------------ //
// Filtre combiné (grossier + confirmation) pour les benchmarks       //
// ------------------------------------------------------------------ //

/// Filtre combiné exposé pour les benchmarks : applique filtre grossier puis
/// confirmation, sans suivi de session (session vide — évalue la précision
/// sur les méthodes MCP connues uniquement).
pub fn filtre_combine(evt: &EvenementBrut) -> bool {
    use crate::signature::{filtre_grossier, confirmer_message, SuiviSessions};

    if !filtre_grossier(evt) {
        return false;
    }
    let mut suivi = SuiviSessions::nouveau();
    confirmer_message(evt, &mut suivi).is_some()
}
