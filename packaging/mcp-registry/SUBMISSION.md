# Soumission aux registres & annuaires MCP

> ⚠️ **Important — positionnement honnête.** Sentinel **n'est pas un serveur MCP** : c'est un outil de
> sécurité qui *audite* les serveurs MCP. Il ne faut donc **pas** le soumettre comme un « serveur » au
> registre officiel MCP (`server.json`) — ce serait une erreur de catégorie. Sentinel se liste comme
> **outil / tooling de sécurité**, dans les sections dédiées des annuaires et des awesome-lists.

## Où lister Sentinel (en tant qu'outil)

| Cible | Type | Comment soumettre |
|---|---|---|
| **awesome-mcp-security** (`Puliczek/awesome-mcp-security`) | awesome-list | PR ajoutant Sentinel + proposer le cadrage « MCP Detection & Response (MCPDR) ». |
| **awesome-mcp-servers** (`punkpeye/...`, `wong2/...`) | awesome-list | PR dans la section *Tools / Security* (pas la liste des serveurs). |
| **Smithery** | annuaire | Section outils/sécurité si disponible ; sinon contact co-marketing. |
| **PulseMCP** | annuaire + newsletter | Soumettre l'outil + pitch newsletter (forte audience MCP). |
| **mcp.so** | annuaire | Listing outil. |
| **Glama / MCP directories** | annuaires | Listing outil de sécurité. |

## Blurb de soumission (copiable)

> **Sentinel MCP** — a 100% local, read-only EDR for MCP servers (Rust). Discovers every MCP server across
> 14 AI clients, takes a canonical SHA-256 fingerprint, and detects rug-pulls, tool poisoning (40+ patterns
> + Unicode smuggling + line-jumping + optional local LLM judge), typosquats, CVEs and lethal-trifecta exfil
> combos. Speaks SOC: Splunk/Elastic, STIX/TAXII, Ed25519-signed compliance reports. Free & open for local use.
> https://github.com/MattJeff/sentinelmcp

## Idée produit (future, pour entrer AUSSI dans le registre des serveurs)

Exposer Sentinel **lui-même comme un serveur MCP** (ex. outils `sentinel.scan`, `sentinel.audit`,
`sentinel.report`) permettrait à un agent de **s'auto-auditer** (« scan my own MCP servers ») et de figurer
légitimement dans le registre officiel MCP. À ce moment-là — et seulement à ce moment-là — un `server.json`
serait justifié. Non implémenté à ce jour : ne pas soumettre tant que ce n'est pas réel.
