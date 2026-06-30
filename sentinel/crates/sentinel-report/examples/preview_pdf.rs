//! Visual preview of the premium PDF rendering.
//! `cargo run -p sentinel-report --example preview_pdf` → /tmp/sentinel-preview.pdf

use sentinel_report::pdf::{BarreSeverite, ContenuPdf, KpiPdf, RenduPdf};

fn main() {
    let resume = "# Executive summary — Sentinel MCP\n\n\
        **Analysis period:** 2026-06-01 → 2026-06-30\n\n\
        ## Key figures\n\n\
        | Metric | Value |\n|---|---|\n\
        | MCP servers detected | 9 |\n\
        | Unapproved servers | 5 |\n\
        | At-risk servers (red) | 2 |\n\
        | Open findings | 12 |\n\n\
        > WARNING: 2 red server(s) require immediate action.\n";

    let inventaire = "# MCP server inventory\n\n\
        | ID | Endpoint | Transport | Status | Color | First seen |\n|---|---|---|---|---|---|\n\
        | a1b2 | npx -y @modelcontextprotocol/server-filesystem /Users/x | Stdio | Unknown | Red | 2026-06-01 09:52 |\n\
        | c3d4 | npx -y @modelcontextprotocol/server-memory | Stdio | Approved | Green | 2026-06-02 10:14 |\n\
        | e5f6 | npx chrome-devtools-mcp@latest | Stdio | To investigate | Orange | 2026-06-03 11:01 |\n";

    let journal = "# Open findings log\n\n\
        | Date | Server | Type | Severity | Title |\n|---|---|---|---|---|\n\
        | 2026-06-30 11:16 | a1b2 | Poisoning | High | YARA rule MCP_Exfiltration_Reseau — read_media_file |\n\
        | 2026-06-29 14:02 | e5f6 | Poisoning | Medium | base64_inline pattern detected |\n\
        | 2026-06-28 08:30 | a1b2 | Rug pull | Critical | Fingerprint changed since approval |\n";

    let mapping = "# Compliance mapping\n\n\
        OWASP MCP and SAFE-MCP coverage.\n\n\
        | Finding | Framework | Identifier | Title |\n|---|---|---|---|\n\
        | YARA rule MCP_Exfiltration_Reseau | OWASP MCP | MCP03 | Tool Poisoning |\n\
        | YARA rule MCP_Exfiltration_Reseau | SAFE-MCP | SAFE-T1001 | Tool Description Poisoning |\n\
        | Fingerprint changed | SAFE-MCP | SAFE-T1201 | Rug Pull — Tool Behavior Change |\n";

    let plan = "# Remediation plan\n\n\
        ## Immediate actions — red servers\n\n\
        | Endpoint | Recommended action |\n|---|---|\n\
        | npx -y @modelcontextprotocol/server-filesystem | Investigate |\n\n\
        ## High/critical severity findings\n\n\
        - YARA rule MCP_Exfiltration_Reseau: directive to send data to an external destination.\n\
        - Fingerprint changed since approval: the server changed behavior after validation.\n";

    let contenu = ContenuPdf {
        titre: "Compliance Report — Sentinel MCP".to_string(),
        sous_titre: "MCP09 / MCP03 evidence bundle".to_string(),
        periode: "2026-06-01 → 2026-06-30".to_string(),
        kpis: vec![
            KpiPdf { label: "Servers".into(), valeur: "9".into(), accent: [0.29, 0.33, 0.84] },
            KpiPdf { label: "At risk".into(), valeur: "2".into(), accent: [0.90, 0.45, 0.12] },
            KpiPdf { label: "Critical".into(), valeur: "1".into(), accent: [0.84, 0.19, 0.25] },
            KpiPdf { label: "Open findings".into(), valeur: "12".into(), accent: [0.36, 0.46, 0.62] },
        ],
        graphique_severite: vec![
            BarreSeverite { label: "Critical".into(), valeur: 1, couleur: [0.84, 0.19, 0.25] },
            BarreSeverite { label: "High".into(), valeur: 8, couleur: [0.90, 0.45, 0.12] },
            BarreSeverite { label: "Medium".into(), valeur: 3, couleur: [0.92, 0.66, 0.13] },
        ],
        resume_exec: resume.to_string(),
        inventaire: inventaire.to_string(),
        journal: journal.to_string(),
        mapping_conformite: mapping.to_string(),
        plan_remediation: plan.to_string(),
        horodatage: "2026-06-30 12:00 UTC".to_string(),
    };

    let chemin = std::path::Path::new("/tmp/sentinel-preview.pdf");
    RenduPdf::produire_contenu(&contenu, chemin).expect("rendu PDF");
    println!("PDF written: {}", chemin.display());
}
