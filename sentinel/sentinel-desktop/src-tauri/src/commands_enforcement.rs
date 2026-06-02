//! Active enforcement commands.
//!
//! Implements **opt-in** rewriting of an AI client's config file to remove a
//! single offending MCP server entry from its `mcpServers` map. A timestamped
//! safety backup is always written next to the original before any mutation,
//! and [`enforcement_restore`] can put the backup back over the live file.
//!
//! This is the only place in Sentinel that *writes* to the user's home for
//! enforcement purposes, so the contract is intentionally narrow:
//!
//!  * we refuse to act if the target file is missing or unparseable,
//!  * we refuse to wipe the whole `mcpServers` block — only ever one entry,
//!  * we never touch files outside the well-known per-client locations,
//!  * the caller (the React UI) is expected to gate this behind an explicit
//!    user toggle + a confirmation prompt; this module assumes that's done.
//!
//! `server_id` is the *name* of the MCP server entry as it appears as a key
//! under `mcpServers` in the target config — i.e. the value of
//! `DeclaredServer.name` returned by `discover_system`.

use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

/// Result of a successful (or no-op) enforcement removal.
#[derive(Serialize)]
pub struct EnforcementResult {
    /// Absolute path to the config file Sentinel rewrote.
    pub config_path: String,
    /// Absolute path to the `.sentinel.<timestamp>.bak` safety copy.
    pub backup_path: String,
    /// `true` if an entry was actually removed; `false` if it wasn't present
    /// (the backup is still written so the operation stays reversible).
    pub removed: bool,
}

/// Resolve `~` to the user's home directory.
fn home_dir() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "unable to resolve home directory".to_string())
}

/// Map a discovery `kind` (matching the kebab-case strings used in the TS
/// contract) to the canonical config-file path on this Mac.
///
/// Only the well-known top-level config locations are exposed — per-project
/// `.mcp.json` files etc. are intentionally not enforceable from here, as the
/// blast radius of a wrong rewrite would be too high.
fn resolve_config_path(kind: &str) -> Result<PathBuf, String> {
    let home = home_dir()?;
    let path = match kind {
        "claude-code-cli" => home.join(".claude.json"),
        "claude-desktop" => home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json"),
        "cursor" => home.join(".cursor").join("mcp.json"),
        "windsurf" => home.join(".codeium").join("windsurf").join("mcp_config.json"),
        "continue" => home.join(".continue").join("config.json"),
        "vscode" => home
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("settings.json"),
        "zed" => home.join(".config").join("zed").join("settings.json"),
        other => {
            return Err(format!(
                "enforcement not supported for client kind '{}': no known config path",
                other
            ))
        }
    };
    Ok(path)
}

/// Build the backup path for `config_path` using the current UTC timestamp.
fn backup_path_for(config_path: &Path) -> PathBuf {
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string();
    let mut name = config_path.as_os_str().to_os_string();
    name.push(format!(".sentinel.{}.bak", stamp));
    PathBuf::from(name)
}

/// Read + parse `path` as JSON, returning a friendly error on failure.
fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {} as JSON: {}", path.display(), e))
}

/// Remove `server_id` from a `mcpServers` map, in-place.
///
/// Hard safety check: refuse to operate if `mcpServers` is missing, isn't an
/// object, or is the entire object itself — we only ever remove one entry.
/// Returns whether an entry was actually removed.
fn remove_one_entry(root: &mut Value, server_id: &str) -> Result<bool, String> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "config root is not a JSON object".to_string())?;

    let map = obj
        .get_mut("mcpServers")
        .ok_or_else(|| "config has no `mcpServers` block".to_string())?;

    let map = map
        .as_object_mut()
        .ok_or_else(|| "`mcpServers` is not a JSON object".to_string())?;

    // Hard guard: never remove the whole block, only one named entry.
    if !map.contains_key(server_id) {
        return Ok(false);
    }

    // Defensive: even though we only remove(server_id), make sure we leave
    // the `mcpServers` block itself in place (possibly empty) so the file
    // shape is preserved for the host application.
    let _ = map.remove(server_id);
    Ok(true)
}

/// Remove a single MCP server entry from the given client's top-level config.
///
/// Steps:
///   1. Resolve the config path for `kind`.
///   2. Read + parse the JSON file (refuse if missing or unparseable).
///   3. Write a timestamped backup next to the original.
///   4. Remove the entry keyed by `server_id` from `mcpServers` and write
///      the modified JSON back, preserving 2-space indentation.
#[tauri::command]
pub async fn enforcement_remove_server(
    server_id: String,
    kind: String,
) -> Result<EnforcementResult, String> {
    let config_path = resolve_config_path(&kind)?;

    if !config_path.exists() {
        return Err(format!(
            "config file does not exist: {}",
            config_path.display()
        ));
    }

    // Parse first — if the file is corrupt we refuse to touch it.
    let mut root = read_json(&config_path)?;

    // Always write a backup before any mutation, even if we end up not
    // removing anything: this keeps the operation reversible by definition.
    let backup_path = backup_path_for(&config_path);
    std::fs::copy(&config_path, &backup_path).map_err(|e| {
        format!(
            "failed to write backup {}: {}",
            backup_path.display(),
            e
        )
    })?;

    let removed = remove_one_entry(&mut root, &server_id)?;

    if removed {
        let serialised = serde_json::to_vec_pretty(&root)
            .map_err(|e| format!("failed to serialise updated config: {}", e))?;
        std::fs::write(&config_path, &serialised).map_err(|e| {
            format!(
                "failed to write updated config {}: {}",
                config_path.display(),
                e
            )
        })?;
    }

    Ok(EnforcementResult {
        config_path: config_path.to_string_lossy().to_string(),
        backup_path: backup_path.to_string_lossy().to_string(),
        removed,
    })
}

/// Restore a previously written backup over its original config file.
///
/// The caller passes the absolute `backup_path` returned by a prior
/// [`enforcement_remove_server`] call. We refuse to operate if the path
/// doesn't end in `.bak` or doesn't contain the `.sentinel.` marker, to
/// avoid being weaponised into copying arbitrary files around.
#[tauri::command]
pub async fn enforcement_restore(backup_path: String) -> Result<(), String> {
    let backup = PathBuf::from(&backup_path);

    if !backup.exists() {
        return Err(format!("backup file does not exist: {}", backup.display()));
    }

    let file_name = backup
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "backup path has no filename".to_string())?;

    if !file_name.ends_with(".bak") || !file_name.contains(".sentinel.") {
        return Err(format!(
            "refusing to restore from a path that is not a Sentinel backup: {}",
            backup.display()
        ));
    }

    // Reverse of `backup_path_for`: strip the trailing `.sentinel.<stamp>.bak`
    // suffix to recover the original config path.
    let marker = ".sentinel.";
    let original_name = match file_name.find(marker) {
        Some(idx) => &file_name[..idx],
        None => {
            return Err(format!(
                "backup filename missing `.sentinel.` marker: {}",
                file_name
            ))
        }
    };

    let target = backup
        .parent()
        .ok_or_else(|| "backup path has no parent directory".to_string())?
        .join(original_name);

    std::fs::copy(&backup, &target).map_err(|e| {
        format!(
            "failed to restore {} → {}: {}",
            backup.display(),
            target.display(),
            e
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //! These tests exercise the pure helpers only — they never touch the
    //! real user config files.

    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_config_path_known_kinds() {
        // Just check we get a path back for each supported kind, and that
        // unknown kinds are rejected.
        for kind in [
            "claude-code-cli",
            "claude-desktop",
            "cursor",
            "windsurf",
            "continue",
            "vscode",
            "zed",
        ] {
            let p = resolve_config_path(kind).expect("known kind");
            assert!(!p.as_os_str().is_empty(), "empty path for {}", kind);
        }
        assert!(resolve_config_path("totally-unknown").is_err());
    }

    #[test]
    fn remove_one_entry_happy_path() {
        let mut root = json!({
            "mcpServers": {
                "evil": { "command": "rm" },
                "good": { "command": "ls" },
            }
        });
        let removed = remove_one_entry(&mut root, "evil").unwrap();
        assert!(removed);
        let map = root.get("mcpServers").unwrap().as_object().unwrap();
        assert!(!map.contains_key("evil"));
        assert!(map.contains_key("good"));
    }

    #[test]
    fn remove_one_entry_missing_key_is_noop() {
        let mut root = json!({ "mcpServers": { "good": {} } });
        let removed = remove_one_entry(&mut root, "evil").unwrap();
        assert!(!removed);
        // Block is left intact.
        assert!(root
            .get("mcpServers")
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("good"));
    }

    #[test]
    fn remove_one_entry_rejects_missing_block() {
        let mut root = json!({ "other": 1 });
        assert!(remove_one_entry(&mut root, "evil").is_err());
    }

    #[test]
    fn remove_one_entry_rejects_non_object_block() {
        let mut root = json!({ "mcpServers": "oops" });
        assert!(remove_one_entry(&mut root, "evil").is_err());
    }

    #[test]
    fn backup_path_has_expected_suffix() {
        let p = backup_path_for(Path::new("/tmp/foo.json"));
        let s = p.to_string_lossy().to_string();
        assert!(s.starts_with("/tmp/foo.json.sentinel."), "got {}", s);
        assert!(s.ends_with(".bak"), "got {}", s);
    }
}
