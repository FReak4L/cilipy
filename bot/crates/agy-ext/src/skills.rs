//! Skills management: installed skills CRUD, local SkillPort atomic install, and catalog search/install.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use agy_core::error::{BridgeError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tempfile::Builder;
use tracing::warn;
use uuid::Uuid;

use crate::mcp_client::call_stdio_mcp_tool;
use crate::mcp_config::atomic_write_text;

/// Default directory for active installed skills.
pub const DEFAULT_SKILLS_DIR: &str = "/root/.gemini/config/skills";
/// Default directory for the local curated SkillPort repository.
pub const DEFAULT_SKILLPORT_DIR: &str = "/root/.skillport/skills";
/// Default path to the community skills catalog index JSON.
pub const DEFAULT_CATALOG_JSON: &str = "/opt/skills-mcp/data/catalog.json";
/// Default binary for the skills catalog stdio MCP server.
pub const DEFAULT_SKILLS_CATALOG_BIN: &str = "/root/.local/bin/skills-catalog-mcp";

/// Maximum number of characters returned in a skill's body preview.
pub const SKILL_PREVIEW_CHARS: usize = 2000;

/// Summary of an installed skill folder containing `SKILL.md`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSkill {
    pub name: String,
    pub description: String,
    pub category: String,
    pub size_bytes: u64,
}

/// Detailed view of an installed skill including truncated body preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledSkillDetail {
    pub name: String,
    pub description: String,
    pub category: String,
    pub size_bytes: u64,
    pub preview: String,
}

/// A SkillPort namespace directory and the number of valid skills inside it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillPortNamespace {
    pub name: String,
    pub count: usize,
}

/// Entry from the local SkillPort library.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillPortSkill {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub description: String,
    pub installed: bool,
}

/// Domain entry from the community skills catalog index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogDomain {
    pub id: String,
    pub label: String,
}

/// Search result entry from the community skills catalog index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogSkill {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub domain: String,
    pub repo: String,
    pub installed: bool,
}

fn slug_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$").ok())
        .as_ref()
}

fn catalog_wrapper_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\A# [^\n]*\nSource: [^\n]*\nPath: [^\n]*\nRaw URL: [^\n]*\n\n---\n\n").ok()
    })
    .as_ref()
}

/// Validate a skill directory name/slug, rejecting path traversal, separators, NULs, and invalid characters.
pub fn validate_skill_slug(slug: &str) -> Result<String> {
    if slug.is_empty() {
        return Err(BridgeError::Validation(
            "Skill slug must be a non-empty string".to_string(),
        ));
    }
    if slug.contains("..") || slug.contains('/') || slug.contains('\\') || slug.contains('\0') {
        return Err(BridgeError::Validation(format!(
            "Invalid skill slug: {slug:?}"
        )));
    }
    let valid = slug_regex().is_some_and(|re| re.is_match(slug));
    if !valid {
        return Err(BridgeError::Validation(format!(
            "Invalid skill slug: {slug:?}"
        )));
    }
    Ok(slug.to_string())
}

fn unquote_yaml_scalar(value: &str) -> String {
    let s = value.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        // Unescape in single pass to handle `\\n` vs `\n` accurately.
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        return out;
    }
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        let inner = &s[1..s.len() - 1];
        return inner.replace("''", "'");
    }
    s.to_string()
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|&b| b == b' ').count()
}

fn parse_yaml_block(lines: &[&str], start: usize, min_indent: usize) -> (Map<String, Value>, usize) {
    let mut result = Map::new();
    let mut i = start;
    let n = lines.len();

    while i < n {
        let line = lines[i];
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = leading_spaces(line);
        if indent < min_indent {
            break;
        }
        if stripped.starts_with("- ") {
            i += 1;
            continue;
        }
        let Some((raw_key, rest)) = stripped.split_once(':') else {
            i += 1;
            continue;
        };
        let key = raw_key.trim().to_string();
        let val_part = rest.trim();

        if matches!(val_part, ">" | ">-" | ">+" | "|" | "|-" | "|+") {
            let is_folded = val_part.starts_with('>');
            i += 1;
            let mut block_lines: Vec<String> = Vec::new();
            let mut block_indent: Option<usize> = None;

            while i < n {
                let bline = lines[i];
                let bstripped = bline.trim();
                if bstripped.is_empty() {
                    block_lines.push(String::new());
                    i += 1;
                    continue;
                }
                let bindent = leading_spaces(bline);
                if bindent <= indent {
                    break;
                }
                let bi = *block_indent.get_or_insert(bindent);
                let cut = bi.min(bindent);
                block_lines.push(bline[cut..].to_string());
                i += 1;
            }

            let text_val = if is_folded {
                let mut paragraphs: Vec<String> = Vec::new();
                let mut cur: Vec<String> = Vec::new();
                for bl in &block_lines {
                    let t = bl.trim();
                    if t.is_empty() {
                        if !cur.is_empty() {
                            paragraphs.push(cur.join(" "));
                            cur.clear();
                        }
                    } else {
                        cur.push(t.to_string());
                    }
                }
                if !cur.is_empty() {
                    paragraphs.push(cur.join(" "));
                }
                paragraphs.join("\n\n").trim().to_string()
            } else {
                block_lines.join("\n").trim().to_string()
            };
            result.insert(key, Value::String(text_val));
            continue;
        }

        if val_part.is_empty() {
            let mut j = i + 1;
            while j < n {
                let t = lines[j].trim();
                if !t.is_empty() && !t.starts_with('#') {
                    break;
                }
                j += 1;
            }
            if j < n {
                let next_indent = leading_spaces(lines[j]);
                let next_stripped = lines[j].trim();
                if next_indent > indent && !next_stripped.starts_with("- ") {
                    let (nested, next_i) = parse_yaml_block(lines, j, next_indent);
                    result.insert(key, Value::Object(nested));
                    i = next_i;
                    continue;
                }
                if next_indent > indent && next_stripped.starts_with("- ") {
                    let mut items = Vec::new();
                    let mut k = j;
                    while k < n {
                        let kline = lines[k];
                        let kstripped = kline.trim();
                        if kstripped.is_empty() || kstripped.starts_with('#') {
                            k += 1;
                            continue;
                        }
                        let kindent = leading_spaces(kline);
                        if kindent < next_indent || !kstripped.starts_with("- ") {
                            break;
                        }
                        items.push(Value::String(unquote_yaml_scalar(&kstripped[2..])));
                        k += 1;
                    }
                    result.insert(key, Value::Array(items));
                    i = k;
                    continue;
                }
            }
            result.insert(key, Value::String(String::new()));
            i += 1;
            continue;
        }

        if val_part.starts_with('[') && val_part.ends_with(']') {
            let inner = val_part[1..val_part.len() - 1].trim();
            let arr = if inner.is_empty() {
                Vec::new()
            } else {
                inner
                    .split(',')
                    .filter(|item| !item.trim().is_empty())
                    .map(|item| Value::String(unquote_yaml_scalar(item)))
                    .collect()
            };
            result.insert(key, Value::Array(arr));
        } else {
            result.insert(key, Value::String(unquote_yaml_scalar(val_part)));
        }
        i += 1;
    }

    (result, i)
}

/// Parse YAML frontmatter from `SKILL.md` content, returning `(metadata_map, markdown_body)`.
pub fn parse_skill_frontmatter(text: &str) -> (Map<String, Value>, String) {
    let clean = text.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    if !clean.starts_with("---\n") {
        return (Map::new(), clean);
    }
    let Some(rel_end) = clean[3..].find("\n---") else {
        return (Map::new(), clean);
    };
    let end_idx = 3 + rel_end;
    let after_marker = end_idx + 4;
    if after_marker < clean.len() && !clean[after_marker..].starts_with('\n') {
        return (Map::new(), clean);
    }
    let fm_slice = &clean[4..end_idx];
    let fm_lines: Vec<&str> = fm_slice.lines().collect();
    let (meta, _) = parse_yaml_block(&fm_lines, 0, 0);
    let body = clean[after_marker..].trim_start_matches('\n').to_string();
    (meta, body)
}

fn value_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn truncate_preview(src: &str, max_chars: usize) -> String {
    let count = src.chars().count();
    if count <= max_chars {
        return src.to_string();
    }
    let prefix: String = src.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{}...", prefix.trim_end())
}

fn extract_skill_metadata(
    skill_md: &Path,
    fallback_name: &str,
) -> std::io::Result<(String, String, String, String)> {
    let bytes = fs::read(skill_md)?;
    let raw = String::from_utf8_lossy(&bytes);
    let (meta, body) = parse_skill_frontmatter(&raw);

    let parsed_name = value_str(meta.get("name"));
    let name = if parsed_name.is_empty() {
        fallback_name.to_string()
    } else {
        parsed_name
    };
    let description = value_str(meta.get("description"));

    let mut category = String::new();
    if let Some(Value::Object(metadata)) = meta.get("metadata") {
        if let Some(Value::Object(sp)) = metadata.get("skillport") {
            category = value_str(sp.get("category"));
        }
        if category.is_empty() {
            category = value_str(metadata.get("category"));
        }
    }
    if category.is_empty() {
        category = value_str(meta.get("category"));
    }

    let preview_src = if !body.trim().is_empty() {
        body.trim()
    } else {
        raw.trim()
    };
    let preview = truncate_preview(preview_src, SKILL_PREVIEW_CHARS);
    Ok((name, description, category, preview))
}

fn installed_skill_names(base: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    if !base.is_dir() {
        return names;
    }
    let Ok(entries) = fs::read_dir(base) else {
        return names;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if path.is_dir() && path.join("SKILL.md").is_file() {
            names.insert(name);
        }
    }
    names
}

/// List installed skills inside `skills_dir` sorted case-insensitively by folder name.
pub fn list_installed_skills(skills_dir: &Path) -> Result<Vec<InstalledSkill>> {
    if !skills_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(skills_dir)
        .map_err(|e| BridgeError::io(format!("reading skills dir {}", skills_dir.display()), e))?
        .filter_map(|res| res.ok().map(|e| e.path()))
        .collect();
    entries.sort_by(|a, b| {
        let al = a
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let bl = b
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        al.cmp(&bl)
    });

    let mut items = Vec::new();
    for entry in entries {
        let Some(dir_name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if dir_name.starts_with('.') || !entry.is_dir() {
            continue;
        }
        let skill_md = entry.join("SKILL.md");
        if !skill_md.is_file() {
            continue;
        }
        match extract_skill_metadata(&skill_md, dir_name)
            .and_then(|(name, description, category, _)| Ok((name, description, category, fs::metadata(&skill_md)?.len())))
        {
            Ok((name, description, category, size_bytes)) => items.push(InstalledSkill {
                name,
                description,
                category,
                size_bytes,
            }),
            Err(exc) => {
                warn!(skill = dir_name, error = %exc, "Failed reading installed skill");
            }
        }
    }
    Ok(items)
}

/// Return details and preview for an installed skill, rejecting traversal/escaping symlinks.
/// Returns `Ok(None)` when a valid slug is simply not installed.
pub fn get_installed_skill(name: &str, skills_dir: &Path) -> Result<Option<InstalledSkillDetail>> {
    let safe_name = validate_skill_slug(name)?;
    if !skills_dir.is_dir() {
        return Ok(None);
    }
    let base = fs::canonicalize(skills_dir)
        .map_err(|e| BridgeError::io(format!("canonicalizing {}", skills_dir.display()), e))?;
    let raw_target = base.join(&safe_name);
    let meta = match fs::symlink_metadata(&raw_target) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(BridgeError::io(format!("stat {}", raw_target.display()), e)),
    };
    let resolved = fs::canonicalize(&raw_target).map_err(|_| {
        BridgeError::PermissionDenied(format!("Refusing broken or unresolvable skill path: {safe_name}"))
    })?;
    if resolved == base || !resolved.starts_with(&base) {
        return Err(BridgeError::PermissionDenied(format!(
            "Refusing path outside skills directory: {safe_name}"
        )));
    }
    if meta.file_type().is_symlink() && !resolved.starts_with(&base) {
        return Err(BridgeError::PermissionDenied(format!(
            "Refusing symlink outside skills directory: {safe_name}"
        )));
    }
    let skill_md = resolved.join("SKILL.md");
    if !resolved.is_dir() || !skill_md.is_file() {
        return Ok(None);
    }
    let (parsed_name, description, category, preview) =
        extract_skill_metadata(&skill_md, &safe_name)
            .map_err(|e| BridgeError::io(format!("reading {}", skill_md.display()), e))?;
    let size_bytes = fs::metadata(&skill_md)
        .map_err(|e| BridgeError::io(format!("stat {}", skill_md.display()), e))?
        .len();

    Ok(Some(InstalledSkillDetail {
        name: parsed_name,
        description,
        category,
        size_bytes,
        preview,
    }))
}

/// Safely delete an installed skill directory inside `skills_dir`, rejecting traversal and symlink escapes.
pub fn delete_installed_skill(name: &str, skills_dir: &Path) -> Result<String> {
    let safe_name = validate_skill_slug(name)?;
    let base = fs::canonicalize(skills_dir)
        .map_err(|e| BridgeError::io(format!("canonicalizing {}", skills_dir.display()), e))?;
    let raw_target = base.join(&safe_name);

    let sym_meta = match fs::symlink_metadata(&raw_target) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(BridgeError::NotFound(format!(
                "Skill not found: {safe_name}"
            )));
        }
        Err(e) => return Err(BridgeError::io(format!("stat {}", raw_target.display()), e)),
    };

    let resolved = fs::canonicalize(&raw_target).map_err(|_| {
        BridgeError::PermissionDenied(format!("Refusing path outside skills directory: {safe_name}"))
    })?;
    if resolved == base || !resolved.starts_with(&base) {
        return Err(BridgeError::PermissionDenied(format!(
            "Refusing path outside skills directory: {safe_name}"
        )));
    }

    if sym_meta.file_type().is_symlink() {
        fs::remove_file(&raw_target)
            .map_err(|e| BridgeError::io(format!("Failed to delete skill '{safe_name}'"), e))?;
    } else if resolved.is_dir() {
        fs::remove_dir_all(&resolved)
            .map_err(|e| BridgeError::io(format!("Failed to delete skill '{safe_name}'"), e))?;
    } else {
        return Err(BridgeError::Validation(format!(
            "Target is not a skill directory: {safe_name}"
        )));
    }

    Ok(format!("Removed skill '{safe_name}'"))
}

/// Return `(namespace, skill_count)` entries from the local SkillPort library.
pub fn list_skillport_namespaces(skillport_dir: &Path) -> Result<Vec<SkillPortNamespace>> {
    if !skillport_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut ns_dirs: Vec<PathBuf> = fs::read_dir(skillport_dir)
        .map_err(|e| {
            BridgeError::io(
                format!("reading SkillPort dir {}", skillport_dir.display()),
                e,
            )
        })?
        .filter_map(|r| r.ok().map(|e| e.path()))
        .collect();
    ns_dirs.sort_by(|a, b| {
        let al = a
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let bl = b
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        al.cmp(&bl)
    });

    let mut out = Vec::new();
    for ns_dir in ns_dirs {
        let Some(ns_name) = ns_dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if ns_name.starts_with('.') || !ns_dir.is_dir() {
            continue;
        }
        let Ok(subs) = fs::read_dir(&ns_dir) else {
            continue;
        };
        let count = subs
            .filter_map(|r| r.ok().map(|e| e.path()))
            .filter(|sub| {
                sub.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| !n.starts_with('.'))
                    && sub.is_dir()
                    && sub.join("SKILL.md").is_file()
            })
            .count();
        if count > 0 {
            out.push(SkillPortNamespace {
                name: ns_name.to_string(),
                count,
            });
        }
    }
    Ok(out)
}

/// List SkillPort skills, optionally filtered by `namespace` and/or space-separated `query` tokens.
pub fn list_skillport_skills(
    namespace: Option<&str>,
    query: Option<&str>,
    skillport_dir: &Path,
    skills_dir: &Path,
) -> Result<Vec<SkillPortSkill>> {
    if !skillport_dir.is_dir() {
        return Ok(Vec::new());
    }
    let installed_set = installed_skill_names(skills_dir);
    let tokens: Vec<String> = query
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let ns_filter = namespace.map(str::trim).filter(|s| !s.is_empty());

    let mut ns_dirs: Vec<PathBuf> = fs::read_dir(skillport_dir)
        .map_err(|e| {
            BridgeError::io(
                format!("reading SkillPort dir {}", skillport_dir.display()),
                e,
            )
        })?
        .filter_map(|r| r.ok().map(|e| e.path()))
        .collect();
    ns_dirs.sort_by(|a, b| {
        let al = a
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let bl = b
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        al.cmp(&bl)
    });

    let mut results = Vec::new();
    for ns_dir in ns_dirs {
        let Some(ns_name) = ns_dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if ns_name.starts_with('.') || !ns_dir.is_dir() {
            continue;
        }
        if let Some(filter) = ns_filter {
            if ns_name != filter {
                continue;
            }
        }
        let Ok(skill_entries) = fs::read_dir(&ns_dir) else {
            continue;
        };
        let mut skill_dirs: Vec<PathBuf> = skill_entries
            .filter_map(|r| r.ok().map(|e| e.path()))
            .collect();
        skill_dirs.sort_by(|a, b| {
            let al = a
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let bl = b
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            al.cmp(&bl)
        });

        for skill_dir in skill_dirs {
            let Some(skill_name) = skill_dir.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if skill_name.starts_with('.') || !skill_dir.is_dir() {
                continue;
            }
            let skill_md = skill_dir.join("SKILL.md");
            if !skill_md.is_file() {
                continue;
            }
            let skill_id = format!("{ns_name}/{skill_name}");
            let description = extract_skill_metadata(&skill_md, skill_name)
                .map(|(_, d, _, _)| d)
                .unwrap_or_default();

            if !tokens.is_empty() {
                let haystack = format!("{skill_id} {skill_name} {description}").to_ascii_lowercase();
                if !tokens.iter().all(|tok| haystack.contains(tok.as_str())) {
                    continue;
                }
            }

            results.push(SkillPortSkill {
                id: skill_id,
                namespace: ns_name.to_string(),
                name: skill_name.to_string(),
                description,
                installed: installed_set.contains(skill_name),
            });
        }
    }
    Ok(results)
}

fn copy_dir_recursive(src: &Path, dst: &Path, src_root: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .map_err(|e| BridgeError::io(format!("creating directory {}", dst.display()), e))?;
    let entries = fs::read_dir(src)
        .map_err(|e| BridgeError::io(format!("reading directory {}", src.display()), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| BridgeError::io("iterating directory entry", e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let sym_meta = fs::symlink_metadata(&src_path)
            .map_err(|e| BridgeError::io(format!("stat {}", src_path.display()), e))?;

        let resolved = if sym_meta.file_type().is_symlink() {
            let canon = fs::canonicalize(&src_path).map_err(|e| {
                BridgeError::io(format!("resolving symlink {}", src_path.display()), e)
            })?;
            if !canon.starts_with(src_root) {
                return Err(BridgeError::PermissionDenied(format!(
                    "Refusing symlink escaping SkillPort source: {}",
                    src_path.display()
                )));
            }
            canon
        } else {
            src_path
        };

        if resolved.is_dir() {
            copy_dir_recursive(&resolved, &dst_path, src_root)?;
        } else if resolved.is_file() {
            fs::copy(&resolved, &dst_path).map_err(|e| {
                BridgeError::io(
                    format!("copying {} -> {}", resolved.display(), dst_path.display()),
                    e,
                )
            })?;
        }
    }
    Ok(())
}

/// Atomically stage and install a SkillPort skill folder (`namespace/name` or unambiguous `name`)
/// into `skills_dir/<slug>`.
pub fn install_skillport_skill(
    skill_id: &str,
    skillport_dir: &Path,
    skills_dir: &Path,
) -> Result<String> {
    let raw_id = skill_id.trim();
    if raw_id.is_empty() {
        return Err(BridgeError::Validation(
            "Skill ID must not be empty".to_string(),
        ));
    }
    if !skillport_dir.is_dir() {
        return Err(BridgeError::NotFound(format!(
            "SkillPort directory not found: {}",
            skillport_dir.display()
        )));
    }
    let sp_base = fs::canonicalize(skillport_dir)
        .map_err(|e| BridgeError::io(format!("canonicalizing {}", skillport_dir.display()), e))?;

    let (name, src_dir) = if raw_id.contains('/') {
        let parts: Vec<&str> = raw_id.split('/').collect();
        if parts.len() != 2 {
            return Err(BridgeError::Validation(format!(
                "Invalid SkillPort ID: {raw_id:?}"
            )));
        }
        let ns = validate_skill_slug(parts[0])?;
        let name = validate_skill_slug(parts[1])?;
        let candidate = sp_base.join(&ns).join(&name);
        let canon = fs::canonicalize(&candidate).map_err(|_| {
            BridgeError::NotFound(format!(
                "SkillPort skill not found or missing SKILL.md: {raw_id}"
            ))
        })?;
        (name, canon)
    } else {
        let name = validate_skill_slug(raw_id)?;
        let mut matches = Vec::new();
        for entry in fs::read_dir(&sp_base)
            .map_err(|e| BridgeError::io(format!("reading {}", sp_base.display()), e))?
            .flatten()
        {
            let ns_path = entry.path();
            if !ns_path.is_dir()
                || ns_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            let sub = ns_path.join(&name);
            if sub.is_dir() && sub.join("SKILL.md").is_file() {
                if let Ok(canon) = fs::canonicalize(&sub) {
                    matches.push(canon);
                }
            }
        }
        if matches.is_empty() {
            return Err(BridgeError::NotFound(format!(
                "SkillPort skill not found: {raw_id}"
            )));
        }
        if matches.len() > 1 {
            return Err(BridgeError::Validation(format!(
                "Ambiguous SkillPort skill '{raw_id}'; specify namespace/name"
            )));
        }
        (name, matches.swap_remove(0))
    };

    if !src_dir.starts_with(&sp_base) || !src_dir.is_dir() || !src_dir.join("SKILL.md").is_file() {
        return Err(BridgeError::NotFound(format!(
            "SkillPort skill not found or missing SKILL.md: {raw_id}"
        )));
    }

    fs::create_dir_all(skills_dir)
        .map_err(|e| BridgeError::io(format!("creating {}", skills_dir.display()), e))?;
    let dest_base = fs::canonicalize(skills_dir)
        .map_err(|e| BridgeError::io(format!("canonicalizing {}", skills_dir.display()), e))?;
    let dest_dir = dest_base.join(&name);
    if dest_dir == dest_base || !dest_dir.starts_with(&dest_base) {
        return Err(BridgeError::PermissionDenied(format!(
            "Refusing destination outside skills directory: {name}"
        )));
    }

    let token = Uuid::new_v4().simple().to_string();
    let stage_temp = Builder::new()
        .prefix(&format!(".tmp-{name}-"))
        .tempdir_in(&dest_base)
        .map_err(|e| BridgeError::io("creating SkillPort staging directory", e))?;

    copy_dir_recursive(&src_dir, stage_temp.path(), &src_dir)?;
    let stage_dir = stage_temp.keep();
    let backup_dir = dest_base.join(format!(".bak-{name}-{token}"));

    let swap_res: Result<()> = (|| {
        if fs::symlink_metadata(&dest_dir).is_ok() {
            fs::rename(&dest_dir, &backup_dir).map_err(|e| {
                BridgeError::io(
                    format!("moving existing skill {} to backup", dest_dir.display()),
                    e,
                )
            })?;
            if let Err(e) = fs::rename(&stage_dir, &dest_dir) {
                if fs::symlink_metadata(&backup_dir).is_ok()
                    && fs::symlink_metadata(&dest_dir).is_err()
                {
                    let _ = fs::rename(&backup_dir, &dest_dir);
                }
                return Err(BridgeError::io(
                    format!("activating staged skill {}", dest_dir.display()),
                    e,
                ));
            }
            if let Ok(meta) = fs::symlink_metadata(&backup_dir) {
                if meta.file_type().is_symlink() || meta.is_file() {
                    let _ = fs::remove_file(&backup_dir);
                } else {
                    let _ = fs::remove_dir_all(&backup_dir);
                }
            }
        } else {
            fs::rename(&stage_dir, &dest_dir).map_err(|e| {
                BridgeError::io(
                    format!("moving staged skill to {}", dest_dir.display()),
                    e,
                )
            })?;
        }
        Ok(())
    })();

    if stage_dir.exists() {
        let _ = fs::remove_dir_all(&stage_dir);
    }
    swap_res?;
    Ok(format!("Installed SkillPort skill '{name}'"))
}

// ---------------------------------------------------------------------------
// Community skills catalog (mtime + size + inode cached)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStatSig {
    mtime_sec: i64,
    mtime_nsec: i64,
    size: u64,
    ino: u64,
}

#[derive(Debug, Default)]
struct RawCatalogIndex {
    domains: Vec<CatalogDomain>,
    skills: Vec<RawCatalogSkill>,
}

#[derive(Debug, Clone)]
struct RawCatalogSkill {
    id: String,
    slug: String,
    name: String,
    description: String,
    tags: Vec<String>,
    primary_tag: String,
    explicit_domain: String,
    repo: String,
    repo_label: String,
}

#[derive(Debug)]
struct CachedCatalog {
    sig: FileStatSig,
    data: Arc<RawCatalogIndex>,
}

fn catalog_cache() -> &'static Mutex<HashMap<PathBuf, CachedCatalog>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedCatalog>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_catalog(catalog_json: &Path) -> Arc<RawCatalogIndex> {
    if !catalog_json.is_file() {
        return Arc::new(RawCatalogIndex::default());
    }
    let Ok(meta) = fs::metadata(catalog_json) else {
        return Arc::new(RawCatalogIndex::default());
    };
    let sig = FileStatSig {
        mtime_sec: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        size: meta.size(),
        ino: meta.ino(),
    };

    {
        let guard = catalog_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = guard.get(catalog_json) {
            if cached.sig == sig {
                return Arc::clone(&cached.data);
            }
        }
    }

    let raw = match fs::read_to_string(catalog_json) {
        Ok(s) => s,
        Err(exc) => {
            warn!(path = %catalog_json.display(), error = %exc, "Failed reading skills catalog");
            return Arc::new(RawCatalogIndex::default());
        }
    };
    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(exc) => {
            warn!(path = %catalog_json.display(), error = %exc, "Failed parsing skills catalog JSON");
            return Arc::new(RawCatalogIndex::default());
        }
    };
    let Some(obj) = parsed.as_object() else {
        return Arc::new(RawCatalogIndex::default());
    };

    let mut domains = Vec::new();
    if let Some(dom_arr) = obj.get("domains").and_then(Value::as_array) {
        for d in dom_arr {
            let Some(dobj) = d.as_object() else {
                continue;
            };
            let id = value_str(dobj.get("id"));
            if id.is_empty() {
                continue;
            }
            let label = value_str(dobj.get("label"));
            domains.push(CatalogDomain {
                label: if label.is_empty() { id.clone() } else { label },
                id,
            });
        }
    }

    let mut skills = Vec::new();
    if let Some(sk_arr) = obj.get("skills").and_then(Value::as_array) {
        for s in sk_arr {
            let Some(sobj) = s.as_object() else {
                continue;
            };
            let slug = sobj
                .get("slug")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = sobj
                .get("name")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(&slug)
                .to_string();
            let tags = sobj
                .get("tags")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| match v {
                            Value::String(st) => Some(st.clone()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            let repo_label = sobj
                .get("repoLabel")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let repo = sobj
                .get("repo")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(&repo_label)
                .to_string();
            skills.push(RawCatalogSkill {
                id: sobj
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                slug,
                name,
                description: sobj
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                tags,
                primary_tag: sobj
                    .get("primaryTag")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                explicit_domain: sobj
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                repo,
                repo_label,
            });
        }
    }

    let data = Arc::new(RawCatalogIndex { domains, skills });
    let mut guard = catalog_cache().lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(
        catalog_json.to_path_buf(),
        CachedCatalog {
            sig,
            data: Arc::clone(&data),
        },
    );
    data
}

/// Return catalog domains (`id`, `label`) from `catalog.json`.
pub fn list_catalog_domains(catalog_json: &Path) -> Result<Vec<CatalogDomain>> {
    let data = load_catalog(catalog_json);
    Ok(data.domains.clone())
}

/// Search the local skills catalog index, ranking exact slug/name matches first.
pub fn search_catalog_skills(
    query: &str,
    domain: Option<&str>,
    limit: usize,
    catalog_json: &Path,
    skills_dir: &Path,
) -> Result<Vec<CatalogSkill>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let data = load_catalog(catalog_json);
    if data.skills.is_empty() {
        return Ok(Vec::new());
    }

    let installed_set = installed_skill_names(skills_dir);
    let q = query.trim().to_ascii_lowercase();
    let tokens: Vec<&str> = q.split_whitespace().collect();
    let dom = domain.map(str::trim).filter(|s| !s.is_empty());

    let mut scored: Vec<(f64, usize, CatalogSkill)> = Vec::new();
    for (idx, skill) in data.skills.iter().enumerate() {
        if let Some(d) = dom {
            let matches_tag = skill.tags.iter().any(|t| t == d);
            if !matches_tag && skill.primary_tag != d && skill.explicit_domain != d {
                continue;
            }
        }

        let skill_domain = if !skill.primary_tag.is_empty() {
            skill.primary_tag.clone()
        } else if !skill.explicit_domain.is_empty() {
            skill.explicit_domain.clone()
        } else {
            skill.tags.first().cloned().unwrap_or_default()
        };

        let score = if !tokens.is_empty() {
            let slug_l = skill.slug.to_ascii_lowercase();
            let name_l = skill.name.to_ascii_lowercase();
            let desc_l = skill.description.to_ascii_lowercase();
            let tags_l = skill
                .tags
                .iter()
                .map(|t| t.to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(" ");
            let repo_l = format!("{} {}", skill.repo, skill.repo_label).to_ascii_lowercase();
            let haystack = format!("{slug_l} {name_l} {tags_l} {desc_l} {repo_l}");

            if !tokens.iter().all(|tok| haystack.contains(tok)) {
                continue;
            }

            let mut sc = 0.0_f64;
            if slug_l == q || name_l == q {
                sc += 1000.0;
            } else if slug_l.starts_with(&q) || name_l.starts_with(&q) {
                sc += 500.0;
            } else if slug_l.contains(&q) || name_l.contains(&q) {
                sc += 200.0;
            }
            for tok in &tokens {
                if slug_l.contains(tok) || name_l.contains(tok) {
                    sc += 20.0;
                }
                if tags_l.contains(tok) {
                    sc += 10.0;
                }
                if desc_l.contains(tok) {
                    sc += 3.0;
                }
                if repo_l.contains(tok) {
                    sc += 2.0;
                }
            }
            sc -= (name_l.chars().count() as f64) * 0.01;
            sc
        } else {
            0.0
        };

        scored.push((
            -score,
            idx,
            CatalogSkill {
                id: skill.id.clone(),
                slug: skill.slug.clone(),
                name: skill.name.clone(),
                description: skill.description.clone(),
                domain: skill_domain,
                repo: skill.repo.clone(),
                installed: installed_set.contains(&skill.slug) || installed_set.contains(&skill.name),
            },
        ));
    }

    if !tokens.is_empty() {
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    }

    Ok(scored.into_iter().take(limit).map(|item| item.2).collect())
}

fn derive_slug_from_catalog_id(catalog_id: &str) -> Result<String> {
    if catalog_id.contains('\\') || catalog_id.contains('\0') {
        return Err(BridgeError::Validation(format!(
            "Invalid catalog ID: {catalog_id:?}"
        )));
    }
    let parts: Vec<&str> = catalog_id
        .trim()
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return Err(BridgeError::Validation(format!(
            "Invalid catalog ID: {catalog_id:?}"
        )));
    }
    let candidate = if parts.len() >= 2
        && parts
            .last()
            .is_some_and(|p| p.eq_ignore_ascii_case("skill.md"))
    {
        parts[parts.len() - 2]
    } else {
        parts[parts.len() - 1]
    };
    validate_skill_slug(candidate)
}

/// Fetch a catalog skill's `SKILL.md` via stdio MCP (`get_skill`), strip the wrapper header,
/// validate content, and write atomically into `skills_dir/<slug>/SKILL.md`.
pub async fn install_catalog_skill(
    catalog_id: &str,
    slug: Option<&str>,
    skills_dir: &Path,
    catalog_bin: &str,
    timeout_secs: f64,
) -> Result<String> {
    let cid = catalog_id.trim();
    if cid.is_empty() {
        return Err(BridgeError::Validation(
            "Catalog ID must not be empty".to_string(),
        ));
    }
    let safe_slug = match slug {
        Some(s) => validate_skill_slug(s)?,
        None => derive_slug_from_catalog_id(cid)?,
    };

    let raw = call_stdio_mcp_tool(
        catalog_bin,
        "get_skill",
        json!({ "id": cid }),
        None,
        timeout_secs,
    )
    .await?;

    let Value::String(raw_text) = raw else {
        return Err(BridgeError::Mcp {
            server: catalog_bin.to_string(),
            tool: "get_skill".to_string(),
            message: "Unexpected non-text response from skills catalog".to_string(),
        });
    };

    let md = match catalog_wrapper_regex() {
        Some(re) => re.replace(&raw_text, "").into_owned(),
        None => raw_text,
    };

    if md.contains('\0') {
        return Err(BridgeError::Validation(
            "Refused skill content containing NUL byte".to_string(),
        ));
    }
    if md.trim().is_empty() {
        return Err(BridgeError::Validation(
            "Fetched skill markdown is empty".to_string(),
        ));
    }

    fs::create_dir_all(skills_dir)
        .map_err(|e| BridgeError::io(format!("creating {}", skills_dir.display()), e))?;
    let base_resolved = fs::canonicalize(skills_dir)
        .map_err(|e| BridgeError::io(format!("canonicalizing {}", skills_dir.display()), e))?;
    let target_dir = base_resolved.join(&safe_slug);
    if target_dir == base_resolved || !target_dir.starts_with(&base_resolved) {
        return Err(BridgeError::PermissionDenied(format!(
            "Refusing path outside skills directory: {safe_slug}"
        )));
    }
    if let Ok(sym_meta) = fs::symlink_metadata(&target_dir) {
        if sym_meta.file_type().is_symlink() {
            let canon = fs::canonicalize(&target_dir).map_err(|_| {
                BridgeError::PermissionDenied(format!(
                    "Refusing unresolvable symlink at skill destination: {safe_slug}"
                ))
            })?;
            if canon == base_resolved || !canon.starts_with(&base_resolved) {
                return Err(BridgeError::PermissionDenied(format!(
                    "Refusing symlink outside skills directory: {safe_slug}"
                )));
            }
        }
    }

    fs::create_dir_all(&target_dir)
        .map_err(|e| BridgeError::io(format!("creating {}", target_dir.display()), e))?;
    atomic_write_text(&target_dir.join("SKILL.md"), &md, None)?;
    Ok(format!("Installed catalog skill '{safe_slug}'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    fn write_mock_catalog_mcp(dir: &TempDir, name: &str, body: &str) -> String {
        let path = dir.path().join(name);
        let script = format!("#!/usr/bin/env python3\nimport json, sys\n{body}\n");
        fs::write(&path, script).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn test_validate_skill_slug() {
        assert_eq!(validate_skill_slug("my-skill_1.0").unwrap(), "my-skill_1.0");
        let long = "a".repeat(65);
        for bad in [
            "",
            "-leading",
            ".hidden",
            "a..b",
            "a/b",
            "a\\b",
            "has space",
            long.as_str(),
            "x\x00y",
        ] {
            assert!(validate_skill_slug(bad).is_err(), "expected err for {bad:?}");
        }
    }

    #[test]
    fn test_installed_skills_crud_frontmatter_and_traversal() {
        let dir = TempDir::new().unwrap();
        let skills_dir = dir.path().join("skills");
        fs::create_dir(&skills_dir).unwrap();

        let s1 = skills_dir.join("alpha");
        fs::create_dir(&s1).unwrap();
        fs::write(
            s1.join("SKILL.md"),
            "---\nname: alpha\ndescription: >-\n  First line\n  second line\nmetadata:\n  skillport:\n    category: multi-agent\n---\n# Alpha\n\nBody text here.\n",
        )
        .unwrap();

        let s2 = skills_dir.join("beta");
        fs::create_dir(&s2).unwrap();
        let beta_body = format!("Beta body {}", "Z".repeat(2500));
        fs::write(
            s2.join("SKILL.md"),
            format!("---\nname: \"beta\"\ndescription: \"Simple quoted\"\nmetadata:\n  category: development\n---\n{beta_body}"),
        )
        .unwrap();

        fs::create_dir(skills_dir.join(".hidden")).unwrap();
        fs::create_dir(skills_dir.join("not-a-skill")).unwrap();

        let listed = list_installed_skills(&skills_dir).unwrap();
        let names: Vec<&str> = listed.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        assert_eq!(listed[0].description, "First line second line");
        assert_eq!(listed[0].category, "multi-agent");
        assert_eq!(listed[0].size_bytes, fs::metadata(s1.join("SKILL.md")).unwrap().len());
        assert_eq!(listed[1].category, "development");

        let detail = get_installed_skill("beta", &skills_dir).unwrap().unwrap();
        assert_eq!(detail.preview.chars().count(), 2000);
        assert!(detail.preview.ends_with("..."));

        assert!(get_installed_skill("../etc", &skills_dir).is_err());
        assert!(get_installed_skill("missing", &skills_dir).unwrap().is_none());

        // Symlink escape check
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep.txt"), "safe").unwrap();
        symlink(&outside, skills_dir.join("evil")).unwrap();

        assert!(delete_installed_skill("evil", &skills_dir).is_err());
        assert!(outside.join("keep.txt").exists());
        assert!(get_installed_skill("evil", &skills_dir).is_err());

        assert!(delete_installed_skill("../outside", &skills_dir).is_err());
        assert!(outside.join("keep.txt").exists());

        delete_installed_skill("alpha", &skills_dir).unwrap();
        assert!(!s1.exists());
    }

    #[test]
    fn test_skillport_list_and_atomic_install() {
        let dir = TempDir::new().unwrap();
        let sp_dir = dir.path().join("skillport");
        let skills_dir = dir.path().join("active");
        fs::create_dir(&skills_dir).unwrap();

        let tdd = sp_dir.join("coding").join("tdd");
        fs::create_dir_all(&tdd).unwrap();
        fs::write(
            tdd.join("SKILL.md"),
            "---\nname: tdd\ndescription: Write tests first\n---\n# TDD v2\n",
        )
        .unwrap();
        fs::write(tdd.join("helper.txt"), "extra asset").unwrap();

        let dbg = sp_dir.join("coding").join("dbg");
        fs::create_dir_all(&dbg).unwrap();
        fs::write(
            dbg.join("SKILL.md"),
            "---\nname: dbg\ndescription: Debug systematically\n---\n",
        )
        .unwrap();

        let net = sp_dir.join("networking").join("nginx");
        fs::create_dir_all(&net).unwrap();
        fs::write(
            net.join("SKILL.md"),
            "---\nname: nginx\ndescription: Proxy config\n---\n",
        )
        .unwrap();

        fs::create_dir(sp_dir.join("empty_ns")).unwrap();

        // Pre-install stale tdd to test atomic replacement
        let stale = skills_dir.join("tdd");
        fs::create_dir(&stale).unwrap();
        fs::write(
            stale.join("SKILL.md"),
            "---\nname: tdd\ndescription: Old\n---\n# Old\n",
        )
        .unwrap();
        fs::write(stale.join("obsolete.txt"), "stale").unwrap();

        let ns = list_skillport_namespaces(&sp_dir).unwrap();
        assert_eq!(
            ns,
            vec![
                SkillPortNamespace {
                    name: "coding".to_string(),
                    count: 2
                },
                SkillPortNamespace {
                    name: "networking".to_string(),
                    count: 1
                },
            ]
        );

        let coding = list_skillport_skills(Some("coding"), None, &sp_dir, &skills_dir).unwrap();
        assert_eq!(
            coding
                .iter()
                .map(|s| (s.id.as_str(), s.installed))
                .collect::<Vec<_>>(),
            vec![("coding/dbg", false), ("coding/tdd", true)]
        );

        let hits = list_skillport_skills(None, Some("tests first"), &sp_dir, &skills_dir).unwrap();
        assert_eq!(hits.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), vec!["coding/tdd"]);

        install_skillport_skill("coding/tdd", &sp_dir, &skills_dir).unwrap();
        assert_eq!(
            fs::read_to_string(skills_dir.join("tdd").join("helper.txt")).unwrap(),
            "extra asset"
        );
        assert!(!skills_dir.join("tdd").join("obsolete.txt").exists());
        assert!(!fs::read_dir(&skills_dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with('.')));

        assert!(install_skillport_skill("coding/../../etc", &sp_dir, &skills_dir).is_err());

        // Bare unambiguous install works
        install_skillport_skill("nginx", &sp_dir, &skills_dir).unwrap();
        assert!(skills_dir.join("nginx").join("SKILL.md").is_file());

        // Bare ambiguous name across two namespaces fails cleanly
        for ns_name in ["coding", "networking"] {
            let shared = sp_dir.join(ns_name).join("shared");
            fs::create_dir_all(&shared).unwrap();
            fs::write(shared.join("SKILL.md"), "---\nname: shared\n---\n").unwrap();
        }
        assert!(install_skillport_skill("shared", &sp_dir, &skills_dir).is_err());

        // UTF-8 multi-byte frontmatter + literal block + inline/block lists
        let utf8_skill = skills_dir.join("utf8-skill");
        fs::create_dir_all(&utf8_skill).unwrap();
        let utf8_body = "آ".repeat(2100);
        fs::write(
            utf8_skill.join("SKILL.md"),
            format!(
                "\u{feff}---\r\nname: utf8-skill\r\ndescription: |-\r\n  Line one\r\n  Line two\r\ntags: [one, two]\r\nitems:\r\n  - first\r\n  - second\r\n---\r\n{utf8_body}"
            ),
        )
        .unwrap();
        let utf8_detail = get_installed_skill("utf8-skill", &skills_dir)
            .unwrap()
            .unwrap();
        assert_eq!(utf8_detail.description, "Line one\nLine two");
        assert_eq!(utf8_detail.preview.chars().count(), 2000);
        assert!(utf8_detail.preview.ends_with("..."));
    }

    #[tokio::test]
    async fn test_catalog_search_cache_and_install() {
        let dir = TempDir::new().unwrap();
        let skills_dir = dir.path().join("skills");
        fs::create_dir(&skills_dir).unwrap();
        fs::create_dir(skills_dir.join("pdf")).unwrap();
        fs::write(skills_dir.join("pdf").join("SKILL.md"), "---\nname: pdf\n---\n").unwrap();

        let cat_path = dir.path().join("catalog.json");
        let cat_v1 = json!({
            "domains": [
                {"id": "docs", "label": "Documents"},
                {"id": "sec", "label": "Security"}
            ],
            "skills": [
                {
                    "id": "repo/skills/pdf-ocr/SKILL.md",
                    "slug": "pdf-ocr",
                    "name": "pdf-ocr",
                    "description": "OCR helper for scans",
                    "tags": ["docs"],
                    "primaryTag": "docs",
                    "repo": "community"
                },
                {
                    "id": "repo/skills/pdf/SKILL.md",
                    "slug": "pdf",
                    "name": "pdf",
                    "description": "Extract PDF text",
                    "tags": ["docs"],
                    "primaryTag": "docs",
                    "repo": "official"
                },
                {
                    "id": "repo/skills/scanner/SKILL.md",
                    "slug": "scanner",
                    "name": "scanner",
                    "description": "Scan PDFs for security issues",
                    "tags": ["sec", "docs"],
                    "primaryTag": "sec",
                    "repo": "official"
                }
            ]
        });
        fs::write(&cat_path, serde_json::to_string(&cat_v1).unwrap()).unwrap();

        let domains = list_catalog_domains(&cat_path).unwrap();
        assert_eq!(
            domains,
            vec![
                CatalogDomain {
                    id: "docs".to_string(),
                    label: "Documents".to_string()
                },
                CatalogDomain {
                    id: "sec".to_string(),
                    label: "Security".to_string()
                }
            ]
        );

        let res = search_catalog_skills("pdf", Some("docs"), 5, &cat_path, &skills_dir).unwrap();
        assert_eq!(
            res.iter().map(|r| r.slug.as_str()).collect::<Vec<_>>(),
            vec!["pdf", "pdf-ocr", "scanner"]
        );
        assert!(res[0].installed);
        assert!(!res[1].installed);

        // Cache invalidation check when catalog.json is replaced
        let cat_v2 = json!({
            "domains": [{"id": "docs", "label": "Docs V2"}],
            "skills": []
        });
        atomic_write_text(&cat_path, &serde_json::to_string(&cat_v2).unwrap(), None).unwrap();
        let domains_v2 = list_catalog_domains(&cat_path).unwrap();
        assert_eq!(domains_v2[0].label, "Docs V2");

        // Mock catalog MCP server
        let cat_bin = write_mock_catalog_mcp(
            &dir,
            "fake_cat_mcp.py",
            r##"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        sid = msg["params"]["arguments"]["id"]
        if sid == "bad/nul/SKILL.md":
            txt = "---\nname: bad\n---\nhi\x00there"
        elif sid == "repo/skills/raw-skill/SKILL.md":
            txt = "---\nname: raw-skill\ndescription: Raw md\n---\n# Raw\n"
        else:
            txt = "# pdf-ocr\nSource: Community (https://example.com)\nPath: skills/pdf-ocr/SKILL.md\nRaw URL: https://raw.example/SKILL.md\n\n---\n\n---\nname: pdf-ocr\ndescription: OCR helper\n---\n# Body\n"
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": txt}]}}), flush=True)
        break
"##,
        );

        install_catalog_skill(
            "repo/skills/pdf-ocr/SKILL.md",
            None,
            &skills_dir,
            &cat_bin,
            5.0,
        )
        .await
        .unwrap();
        let installed_md = fs::read_to_string(skills_dir.join("pdf-ocr").join("SKILL.md")).unwrap();
        assert!(installed_md.starts_with("---\nname: pdf-ocr\n"));

        install_catalog_skill(
            "repo/skills/raw-skill/SKILL.md",
            None,
            &skills_dir,
            &cat_bin,
            5.0,
        )
        .await
        .unwrap();
        assert!(fs::read_to_string(skills_dir.join("raw-skill").join("SKILL.md"))
            .unwrap()
            .starts_with("---\nname: raw-skill\n"));

        let nul_err = install_catalog_skill("bad/nul/SKILL.md", None, &skills_dir, &cat_bin, 5.0)
            .await
            .unwrap_err()
            .to_string();
        assert!(nul_err.contains("NUL"));

        assert!(
            install_catalog_skill("repo/../../evil/SKILL.md", None, &skills_dir, &cat_bin, 5.0)
                .await
                .is_err()
        );
    }
}
