//! Convert code files, directories, or `.zip` archives into a single structured `.md` bundle
//! with directory tree, folder-to-file map, symbol map, and syntax-highlighted code blocks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::mcp_client::redact_secrets_in_text;

pub const DEFAULT_MAX_FILE_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

const DEFAULT_IGNORE_DIRS: &[&str] = &[
    ".git",
    ".agy_stage",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".cargo",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackOptions {
    pub input_path: PathBuf,
    pub output_path: Option<PathBuf>,
    #[serde(default)]
    pub include_extensions: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    #[serde(default = "default_max_total_bytes")]
    pub max_total_bytes: usize,
    #[serde(default = "default_true")]
    pub include_line_numbers: bool,
    #[serde(default = "default_true")]
    pub include_symbols: bool,
}

fn default_max_file_bytes() -> usize {
    DEFAULT_MAX_FILE_BYTES
}
fn default_max_total_bytes() -> usize {
    DEFAULT_MAX_TOTAL_BYTES
}
fn default_true() -> bool {
    true
}

impl PackOptions {
    pub fn new(input_path: PathBuf) -> Self {
        Self {
            input_path,
            output_path: None,
            include_extensions: Vec::new(),
            exclude_patterns: Vec::new(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            include_line_numbers: true,
            include_symbols: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PackResult {
    pub markdown: String,
    pub output_path: Option<PathBuf>,
    pub source_kind: String,
    pub total_folders: usize,
    pub total_files: usize,
    pub included_files: usize,
    pub skipped_files: usize,
    pub total_lines: usize,
    pub total_bytes: usize,
}

#[derive(Debug, Clone)]
struct FileEntry {
    rel_path: String,
    folder: String,
    name: String,
    lang: &'static str,
    bytes_len: usize,
    lines_len: usize,
    status: &'static str,
    content: Option<String>,
    symbols: Vec<String>,
}

fn is_zip_file(path: &Path) -> bool {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        return true;
    }
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut magic = [0u8; 4];
        if f.read_exact(&mut magic).is_ok() {
            return magic == [0x50, 0x4B, 0x03, 0x04];
        }
    }
    false
}

pub fn is_zip_archive(path: &Path) -> bool {
    is_zip_file(path)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipBatchHint {
    pub batch_id: usize,
    pub approx_bytes: usize,
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipRecursiveSummary {
    pub total_files: usize,
    pub code_files: usize,
    pub total_bytes: usize,
    pub nested_zips: Vec<String>,
    pub detected_stack: Vec<String>,
    pub tree_lines: Vec<String>,
    pub batches: Vec<ZipBatchHint>,
    pub markdown_overview: String,
}

/// Inspect a `.zip` archive recursively (up to `max_depth` nested `.zip` levels) in a single fast pass
/// with zero LLM tokens: builds tree overview, stack detection tags, and ~25 KiB reading batches.
pub async fn inspect_zip_recursive(
    zip_path: &Path,
    max_depth: usize,
) -> Result<ZipRecursiveSummary, String> {
    if !zip_path.is_file() {
        return Err(format!("zip file not found: {}", zip_path.display()));
    }
    let py = r#"
import io, json, os, stat, sys, zipfile

zip_path = sys.argv[1]
max_depth = max(1, min(3, int(sys.argv[2])))
IGNORE_PARTS = {'.git', '.agy_stage', 'node_modules', 'target', '__pycache__', '.venv', 'venv', '.next', '.cache', 'dist', 'build'}
CODE_EXTS = {'.py','.pyi','.php','.js','.mjs','.cjs','.ts','.tsx','.jsx','.rs','.go','.java','.kt','.c','.h','.cpp','.hpp','.cs','.sh','.bash','.sql','.json','.toml','.yaml','.yml','.html','.css'}
EXT_STACK = {
    '.py': 'python', '.pyi': 'python', '.php': 'php', '.js': 'javascript', '.mjs': 'javascript',
    '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.rs': 'rust', '.go': 'go',
    '.sh': 'bash', '.bash': 'bash', '.sql': 'sql', '.html': 'html', '.css': 'css'
}

entries = []
nested_zips = []
stack = set()

def walk_zip_bytes(raw_or_path, prefix, depth):
    ctx = zipfile.ZipFile(raw_or_path, 'r') if isinstance(raw_or_path, str) else zipfile.ZipFile(io.BytesIO(raw_or_path), 'r')
    with ctx as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                continue
            parts = [p for p in info.filename.replace('\\', '/').split('/') if p and p != '.']
            if any(p in IGNORE_PARTS or p == '..' for p in parts):
                continue
            rel = (prefix + '/' if prefix else '') + '/'.join(parts)
            ext = os.path.splitext(parts[-1])[1].lower()
            if ext == '.zip' and depth < max_depth and info.file_size <= 32 * 1024 * 1024:
                nested_zips.append(rel)
                try:
                    with zf.open(info, 'r') as f:
                        walk_zip_bytes(f.read(), rel + ' -> ', depth + 1)
                except Exception as exc:
                    entries.append({'path': rel, 'size': info.file_size, 'is_code': False, 'note': f'nested_zip_err:{exc}'})
                continue
            is_code = ext in CODE_EXTS
            if ext in EXT_STACK:
                stack.add(EXT_STACK[ext])
            if is_code and info.file_size <= 256 * 1024:
                try:
                    with zf.open(info, 'r') as f:
                        head = f.read(2048).decode('utf-8', errors='ignore').lower()
                    if 'wc_payment_gateway' in head or 'woocommerce' in head:
                        stack.add('woocommerce')
                    if 'aiogram' in head or 'telebot' in head or 'python-telegram-bot' in head or 'telethon' in head:
                        stack.add('telegram')
                    if 'fastapi' in head or 'flask' in head or 'django' in head:
                        stack.add('python-web')
                    if 'asyncio' in head or 'aiohttp' in head:
                        stack.add('async')
                except Exception:
                    pass
            entries.append({'path': rel.replace(' -> /', ' -> '), 'size': info.file_size, 'is_code': is_code})

walk_zip_bytes(zip_path, '', 1)

code_entries = [e for e in entries if e.get('is_code')]
total_bytes = sum(e.get('size', 0) for e in code_entries)
tree_lines = []
for e in entries[:80]:
    kb = e['size'] / 1024.0
    tree_lines.append(f"{e['path']} ({kb:.1f} KB)")
if len(entries) > 80:
    tree_lines.append(f"... (+{len(entries) - 80} more files)")

batches = []
cur_files, cur_bytes = [], 0
for e in code_entries:
    sz = max(256, min(e['size'], 64 * 1024))
    if cur_files and (cur_bytes + sz > 25 * 1024 or len(cur_files) >= 12):
        batches.append({'batch_id': len(batches) + 1, 'approx_bytes': cur_bytes, 'files': cur_files})
        cur_files, cur_bytes = [], 0
    cur_files.append(e['path'])
    cur_bytes += sz
if cur_files:
    batches.append({'batch_id': len(batches) + 1, 'approx_bytes': cur_bytes, 'files': cur_files})

out = {
    'total_files': len(entries),
    'code_files': len(code_entries),
    'total_bytes': total_bytes,
    'nested_zips': nested_zips[:20],
    'detected_stack': sorted(stack),
    'tree_lines': tree_lines,
    'batches': batches[:30],
}
print(json.dumps(out))
"#;
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::process::Command::new("python3")
            .arg("-c")
            .arg(py)
            .arg(zip_path)
            .arg(max_depth.clamp(1, 3).to_string())
            .output(),
    )
    .await
    .map_err(|_| "recursive zip inspect timed out".to_string())?
    .map_err(|e| format!("failed invoking python3 for recursive zip inspect: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("recursive zip inspect failed: {}", err.trim()));
    }
    #[derive(Deserialize)]
    struct RawSummary {
        total_files: usize,
        code_files: usize,
        total_bytes: usize,
        nested_zips: Vec<String>,
        detected_stack: Vec<String>,
        tree_lines: Vec<String>,
        batches: Vec<ZipBatchHint>,
    }
    let parsed: RawSummary = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("failed parsing recursive zip manifest JSON: {e}"))?;

    let mut md = format!(
        "Archive `{}` recursive summary: {} total file(s), {} code file(s), {} bytes uncompressed",
        zip_path.file_name().and_then(|s| s.to_str()).unwrap_or("archive.zip"),
        parsed.total_files,
        parsed.code_files,
        parsed.total_bytes
    );
    if !parsed.nested_zips.is_empty() {
        let _ = write!(md, "\nNested archives: {}", parsed.nested_zips.join(", "));
    }
    if !parsed.detected_stack.is_empty() {
        let _ = write!(md, "\nDetected stack: {}", parsed.detected_stack.join(", "));
    }
    if !parsed.tree_lines.is_empty() {
        let _ = write!(md, "\nEntries:\n- {}", parsed.tree_lines.join("\n- "));
    }
    if parsed.batches.len() > 1 {
        md.push_str("\nSuggested read batches (~25 KiB each):");
        for b in parsed.batches.iter().take(10) {
            let _ = write!(
                md,
                "\n  Batch {} ({} B): {}",
                b.batch_id,
                b.approx_bytes,
                b.files.join(", ")
            );
        }
    }

    Ok(ZipRecursiveSummary {
        total_files: parsed.total_files,
        code_files: parsed.code_files,
        total_bytes: parsed.total_bytes,
        nested_zips: parsed.nested_zips,
        detected_stack: parsed.detected_stack,
        tree_lines: parsed.tree_lines,
        batches: parsed.batches,
        markdown_overview: md,
    })
}

/// Verify an outbox `.zip` deliverable recursively (up to depth 2 nested `.zip`s):
/// checks zip CRC integrity, non-empty contents, inner code syntax (`python3` ast, `json`, `php -l`,
/// `node --check`, `bash -n`), and lazy omission placeholders. Returns `Some(issue)` on defect.
pub async fn verify_zip_outbox_archive(zip_path: &Path) -> Option<String> {
    if !zip_path.is_file() {
        return None;
    }
    let py = r#"
import ast, json, os, shutil, stat, subprocess, sys, tempfile, zipfile

zip_path = sys.argv[1]
PLACEHOLDERS = (
    '// ... existing', '// ... rest', '// rest of the code', '// rest of code unchanged',
    '// existing code unchanged', '/* ... rest', '# ... rest of', '# ... unchanged', '// todo: implement'
)

def safe_extract_rec(zpath, dest, depth):
    real_dest = os.path.realpath(dest)
    with zipfile.ZipFile(zpath, 'r') as zf:
        bad = zf.testzip()
        if bad is not None:
            raise RuntimeError(f"CRC corrupt entry in {os.path.basename(zpath)}: {bad}")
        for info in zf.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                continue
            target = os.path.realpath(os.path.join(real_dest, info.filename))
            if not (target == real_dest or target.startswith(real_dest + os.sep)):
                raise RuntimeError(f"Zip Slip entry rejected: {info.filename}")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info, 'r') as src, open(target, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                if target.lower().endswith('.zip') and depth < 2 and os.path.getsize(target) > 0:
                    nested_dir = target + '.__unpacked'
                    os.makedirs(nested_dir, exist_ok=True)
                    safe_extract_rec(target, nested_dir, depth + 1)

try:
    with tempfile.TemporaryDirectory() as td:
        safe_extract_rec(zip_path, td, 1)
        files = []
        for r, dirs, fns in os.walk(td):
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv'}]
            for fn in sorted(fns):
                fp = os.path.join(r, fn)
                if not fn.lower().endswith('.zip') and os.path.getsize(fp) > 0:
                    files.append(fp)
        if not files:
            print("Archive contains zero non-empty files.")
            sys.exit(2)
        has_php = shutil.which('php') is not None
        has_node = shutil.which('node') is not None
        has_bash = shutil.which('bash') is not None
        for fp in files:
            rel = os.path.relpath(fp, td).replace('.__unpacked', '')
            ext = os.path.splitext(fp)[1].lower()
            try:
                raw = open(fp, 'rb').read()
            except Exception as e:
                print(f"Cannot read `{rel}` inside zip: {e}")
                sys.exit(2)
            if ext in {'.py', '.php', '.js', '.mjs', '.cjs', '.sh', '.bash', '.ts', '.rs', '.go'}:
                text = raw.decode('utf-8', errors='replace')
                for line in text.splitlines():
                    low = line.strip().lower()
                    for m in PLACEHOLDERS:
                        if m in low:
                            print(f"Inner file `{rel}` contains lazy omission placeholder (`{m}`).")
                            sys.exit(2)
            if ext == '.py':
                try:
                    ast.parse(raw, filename=rel)
                except SyntaxError as e:
                    print(f"Python syntax error inside zip `{rel}` line {e.lineno}: {e.msg}")
                    sys.exit(2)
            elif ext == '.json':
                try:
                    json.loads(raw.decode('utf-8'))
                except Exception as e:
                    print(f"JSON syntax error inside zip `{rel}`: {e}")
                    sys.exit(2)
            elif ext == '.php' and has_php:
                p = subprocess.run(['php', '-l', fp], capture_output=True, text=True, timeout=5)
                if p.returncode != 0:
                    print(f"PHP syntax error inside zip `{rel}`: {(p.stderr or p.stdout).strip()[:240]}")
                    sys.exit(2)
            elif ext in {'.js', '.mjs', '.cjs'} and has_node:
                p = subprocess.run(['node', '--check', fp], capture_output=True, text=True, timeout=5)
                if p.returncode != 0:
                    print(f"JS syntax error inside zip `{rel}`: {(p.stderr or p.stdout).strip()[:240]}")
                    sys.exit(2)
            elif ext in {'.sh', '.bash'} and has_bash:
                p = subprocess.run(['bash', '-n', fp], capture_output=True, text=True, timeout=5)
                if p.returncode != 0:
                    print(f"Shell syntax error inside zip `{rel}`: {(p.stderr or p.stdout).strip()[:240]}")
                    sys.exit(2)
except Exception as exc:
    print(f"Invalid or unreadable `.zip` `{os.path.basename(zip_path)}`: {exc}")
    sys.exit(2)
sys.exit(0)
"#;
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::process::Command::new("python3")
            .arg("-c")
            .arg(py)
            .arg(zip_path)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if out.status.success() {
        None
    } else {
        let msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let fallback = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let final_msg = if !msg.is_empty() { msg } else { fallback };
        if final_msg.is_empty() {
            Some(format!("Invalid archive `{}`", zip_path.display()))
        } else {
            Some(final_msg)
        }
    }
}

/// Safely extract a `.zip` archive into a temporary directory (guards against Zip Slip & symlinks).
async fn extract_zip_safely(zip_path: &Path) -> Result<TempDir, String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("failed to create tempdir: {e}"))?;
    let py_script = r#"
import os, sys, zipfile, stat

zip_path, dest_dir = sys.argv[1], os.path.realpath(sys.argv[2])
with zipfile.ZipFile(zip_path, 'r') as zf:
    for info in zf.infolist():
        # Skip symlinks (unix external_attr)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            continue
        target = os.path.realpath(os.path.join(dest_dir, info.filename))
        if not (target == dest_dir or target.startswith(dest_dir + os.sep)):
            raise RuntimeError(f"Zip Slip blocked: {info.filename}")
        if info.is_dir():
            os.makedirs(target, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info, 'r') as src, open(target, 'wb') as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
"#;
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new("python3")
            .arg("-c")
            .arg(py_script)
            .arg(zip_path)
            .arg(tmp.path())
            .output(),
    )
    .await
    .map_err(|_| "zip extraction timed out after 30s".to_string())?
    .map_err(|e| format!("failed to invoke python3 for zip extraction: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("zip extraction failed: {}", err.trim()));
    }
    Ok(tmp)
}

fn lang_for_path(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name == "dockerfile" {
        return "dockerfile";
    }
    if name == "makefile" {
        return "makefile";
    }
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "rs" => "rust",
        "py" | "pyi" => "python",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "jsx" => "jsx",
        "go" => "go",
        "php" => "php",
        "rb" => "ruby",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" => "cpp",
        "cs" => "csharp",
        "sh" | "bash" | "zsh" => "bash",
        "sql" => "sql",
        "json" => "json",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        "xml" => "xml",
        "html" | "htm" => "html",
        "css" | "scss" => "css",
        "md" | "markdown" => "markdown",
        "txt" | "log" | "env" | "ini" | "cfg" | "conf" => "text",
        _ => "",
    }
}

fn symbol_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(fn|struct|enum|trait|impl|mod|def|class|interface|type|func|function|export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|interface|type))\s+([A-Za-z_][A-Za-z0-9_:<>,\s]*)",
        )
        .ok()
    })
    .as_ref()
}

fn extract_symbols(text: &str, max_syms: usize) -> Vec<String> {
    let Some(re) = symbol_regex() else {
        return Vec::new();
    };
    let mut syms = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if let Some(cap) = re.captures(line) {
            let kind = cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            let ident = cap
                .get(2)
                .map(|m| m.as_str().trim())
                .unwrap_or("")
                .split(['(', '{', '=', ';', ':'])
                .next()
                .unwrap_or("")
                .trim();
            if !ident.is_empty() {
                syms.push(format!("L{}: `{} {}`", idx + 1, kind, ident));
                if syms.len() >= max_syms {
                    break;
                }
            }
        }
    }
    syms
}

fn should_exclude(rel: &str, name: &str, excludes: &[String]) -> bool {
    if DEFAULT_IGNORE_DIRS.contains(&name) {
        return true;
    }
    excludes
        .iter()
        .any(|pat| !pat.is_empty() && (rel.contains(pat) || name == pat))
}

fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    opts: &PackOptions,
    folders: &mut BTreeSet<String>,
    files: &mut Vec<PathBuf>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|a| a.file_name());

    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if should_exclude(&rel, &name, &opts.exclude_patterns) {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            folders.insert(rel);
            collect_files_recursive(root, &path, opts, folders, files);
        } else if meta.is_file() {
            if !opts.include_extensions.is_empty() {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .trim_start_matches('.')
                    .to_ascii_lowercase();
                if !opts
                    .include_extensions
                    .iter()
                    .any(|x| x.trim_start_matches('.').eq_ignore_ascii_case(&ext))
                {
                    continue;
                }
            }
            files.push(path);
        }
    }
}

#[derive(Default)]
struct TreeNode {
    dirs: BTreeMap<String, TreeNode>,
    files: Vec<String>,
}

fn insert_tree_path(node: &mut TreeNode, parts: &[&str], is_dir: bool) {
    if parts.is_empty() {
        return;
    }
    if parts.len() == 1 {
        if is_dir {
            node.dirs.entry(parts[0].to_string()).or_default();
        } else {
            node.files.push(parts[0].to_string());
        }
        return;
    }
    let child = node.dirs.entry(parts[0].to_string()).or_default();
    insert_tree_path(child, &parts[1..], is_dir);
}

fn render_tree(node: &TreeNode, prefix: &str, out: &mut String) {
    let total = node.dirs.len() + node.files.len();
    let mut idx = 0;

    for (dname, child) in &node.dirs {
        idx += 1;
        let is_last = idx == total;
        let branch = if is_last { "└── " } else { "├── " };
        let _ = writeln!(out, "{prefix}{branch}{dname}/");
        let next_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
        render_tree(child, &next_prefix, out);
    }
    let mut sorted_files = node.files.clone();
    sorted_files.sort();
    for fname in sorted_files {
        idx += 1;
        let is_last = idx == total;
        let branch = if is_last { "└── " } else { "├── " };
        let _ = writeln!(out, "{prefix}{branch}{fname}");
    }
}

fn safe_fence(text: &str) -> &'static str {
    if text.contains("````") {
        "`````"
    } else if text.contains("```") {
        "````"
    } else {
        "```"
    }
}

/// Pack a file, directory, or `.zip` archive into a structured Markdown bundle.
pub async fn pack_to_markdown(opts: &PackOptions) -> Result<PackResult, String> {
    if !opts.input_path.exists() {
        return Err(format!("input path does not exist: {}", opts.input_path.display()));
    }

    let mut _tmp_guard: Option<TempDir> = None;
    let (scan_root, source_kind, display_name) = if opts.input_path.is_file() {
        if is_zip_file(&opts.input_path) {
            let tmp = extract_zip_safely(&opts.input_path).await?;
            let root = tmp.path().to_path_buf();
            _tmp_guard = Some(tmp);
            let name = opts
                .input_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "archive.zip".to_string());
            (root, "zip", name)
        } else {
            let name = opts
                .input_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());
            let parent = opts
                .input_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            (parent, "file", name)
        }
    } else if opts.input_path.is_dir() {
        let name = opts
            .input_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| opts.input_path.display().to_string());
        (opts.input_path.clone(), "directory", name)
    } else {
        return Err(format!(
            "unsupported input path type: {}",
            opts.input_path.display()
        ));
    };

    let mut folders = BTreeSet::new();
    let mut raw_files = Vec::new();
    if source_kind == "file" {
        raw_files.push(opts.input_path.clone());
    } else {
        collect_files_recursive(&scan_root, &scan_root, opts, &mut folders, &mut raw_files);
    }
    raw_files.sort();

    let mut entries = Vec::with_capacity(raw_files.len());
    let mut total_bytes = 0usize;
    let mut total_lines = 0usize;
    let mut included_files = 0usize;
    let mut skipped_files = 0usize;
    let mut content_budget = opts.max_total_bytes;

    for fpath in &raw_files {
        let rel = fpath
            .strip_prefix(&scan_root)
            .unwrap_or(fpath)
            .to_string_lossy()
            .replace('\\', "/");
        let (folder, name) = match rel.rsplit_once('/') {
            Some((d, f)) => (d.to_string(), f.to_string()),
            None => ("(root)".to_string(), rel.clone()),
        };
        let lang = lang_for_path(fpath);
        let bytes = match std::fs::read(fpath) {
            Ok(b) => b,
            Err(_) => {
                skipped_files += 1;
                entries.push(FileEntry {
                    rel_path: rel,
                    folder,
                    name,
                    lang,
                    bytes_len: 0,
                    lines_len: 0,
                    status: "unreadable",
                    content: None,
                    symbols: Vec::new(),
                });
                continue;
            }
        };
        let bytes_len = bytes.len();
        total_bytes += bytes_len;

        if bytes_len > opts.max_file_bytes {
            skipped_files += 1;
            entries.push(FileEntry {
                rel_path: rel,
                folder,
                name,
                lang,
                bytes_len,
                lines_len: 0,
                status: "skipped (exceeds max_file_bytes)",
                content: None,
                symbols: Vec::new(),
            });
            continue;
        }

        // Check for binary content (NUL bytes or invalid UTF-8)
        let is_binary = bytes.iter().take(8192).any(|&b| b == 0);
        let text = if is_binary {
            None
        } else {
            std::str::from_utf8(&bytes).ok().map(redact_secrets_in_text)
        };

        let Some(text) = text else {
            skipped_files += 1;
            entries.push(FileEntry {
                rel_path: rel,
                folder,
                name,
                lang,
                bytes_len,
                lines_len: 0,
                status: "binary",
                content: None,
                symbols: Vec::new(),
            });
            continue;
        };

        let lines_len = text.lines().count();
        total_lines += lines_len;
        let symbols = if opts.include_symbols {
            extract_symbols(&text, 40)
        } else {
            Vec::new()
        };

        if text.len() > content_budget {
            skipped_files += 1;
            entries.push(FileEntry {
                rel_path: rel,
                folder,
                name,
                lang,
                bytes_len,
                lines_len,
                status: "mapped only (total budget reached)",
                content: None,
                symbols,
            });
            continue;
        }

        content_budget = content_budget.saturating_sub(text.len());
        included_files += 1;
        entries.push(FileEntry {
            rel_path: rel,
            folder,
            name,
            lang,
            bytes_len,
            lines_len,
            status: "included",
            content: Some(text),
            symbols,
        });
    }

    // Build directory tree
    let mut tree = TreeNode::default();
    for d in &folders {
        let parts: Vec<&str> = d.split('/').filter(|s| !s.is_empty()).collect();
        insert_tree_path(&mut tree, &parts, true);
    }
    for e in &entries {
        let parts: Vec<&str> = e.rel_path.split('/').filter(|s| !s.is_empty()).collect();
        insert_tree_path(&mut tree, &parts, false);
    }

    let mut md = String::with_capacity(8192);
    let _ = writeln!(md, "# 📦 Code & Structure Bundle: `{display_name}`\n");
    let _ = writeln!(md, "- **Source Type:** `{source_kind}`");
    let _ = writeln!(md, "- **Total Folders:** {}", folders.len());
    let _ = writeln!(
        md,
        "- **Total Files:** {} ({} included, {} skipped/binary)",
        entries.len(),
        included_files,
        skipped_files
    );
    let _ = writeln!(md, "- **Total Lines:** {total_lines}");
    let _ = writeln!(md, "- **Total Raw Size:** {total_bytes} bytes\n");

    // 1. Tree
    let _ = writeln!(md, "## 📁 Directory & File Structure\n");
    let _ = writeln!(md, "```text");
    let _ = writeln!(md, "{display_name}/");
    render_tree(&tree, "", &mut md);
    let _ = writeln!(md, "```\n");

    // 2. Folder-by-folder map
    let _ = writeln!(md, "## 🗺️ Folder & File Map\n");
    let _ = writeln!(md, "| Folder | File | Language | Lines | Size (bytes) | Status |");
    let _ = writeln!(md, "|---|---|---|---:|---:|---|");
    for e in &entries {
        let lang_lbl = if e.lang.is_empty() { "-" } else { e.lang };
        let _ = writeln!(
            md,
            "| `{}` | `{}` | `{}` | {} | {} | {} |",
            e.folder, e.name, lang_lbl, e.lines_len, e.bytes_len, e.status
        );
    }
    let _ = writeln!(md);

    // 3. Symbol map
    if opts.include_symbols && entries.iter().any(|e| !e.symbols.is_empty()) {
        let _ = writeln!(md, "## 🧭 Code & Symbol Map\n");
        for e in &entries {
            if e.symbols.is_empty() {
                continue;
            }
            let _ = writeln!(md, "### `{}` (in `{}`)", e.rel_path, e.folder);
            for s in &e.symbols {
                let _ = writeln!(md, "- {s}");
            }
            let _ = writeln!(md);
        }
    }

    // 4. File contents
    let _ = writeln!(md, "## 📄 File Contents\n");
    for e in &entries {
        let Some(ref content) = e.content else {
            let _ = writeln!(
                md,
                "### `{}`\n\n> *Folder: `{}` · Status: {} ({} bytes)*\n",
                e.rel_path, e.folder, e.status, e.bytes_len
            );
            continue;
        };
        let fence = safe_fence(content);
        let _ = writeln!(
            md,
            "### `{}`\n\n- **Folder:** `{}`\n- **Lines:** {} · **Size:** {} bytes\n",
            e.rel_path, e.folder, e.lines_len, e.bytes_len
        );
        let _ = writeln!(md, "{fence}{}", e.lang);
        if opts.include_line_numbers {
            for (idx, line) in content.lines().enumerate() {
                let _ = writeln!(md, "{:>4} | {line}", idx + 1);
            }
        } else {
            md.push_str(content);
            if !content.ends_with('\n') {
                md.push('\n');
            }
        }
        let _ = writeln!(md, "{fence}\n");
    }

    if let Some(ref out_p) = opts.output_path {
        if let Some(parent) = out_p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(out_p, md.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", out_p.display()))?;
    }

    Ok(PackResult {
        markdown: md,
        output_path: opts.output_path.clone(),
        source_kind: source_kind.to_string(),
        total_folders: folders.len(),
        total_files: entries.len(),
        included_files,
        skipped_files,
        total_lines,
        total_bytes,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackOptions {
    pub target_dir: PathBuf,
    pub markdown: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnpackFileStatus {
    pub rel_path: String,
    pub action: String, // "created", "updated", "unchanged", "skipped"
    pub bytes: usize,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnpackResult {
    pub target_dir: PathBuf,
    pub dry_run: bool,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub files: Vec<UnpackFileStatus>,
}

fn validate_rel_unpack_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim().trim_matches('`').trim();
    if trimmed.is_empty() {
        return Err("empty path".to_string());
    }
    let normalized = trimmed.replace('\\', "/");
    let p = Path::new(&normalized);
    if p.is_absolute() {
        return Err(format!("absolute path rejected: {trimmed}"));
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s == ".git" {
                    return Err("writing inside .git is forbidden".to_string());
                }
                clean.push(seg);
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(format!("path traversal rejected: {trimmed}"));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("empty normalized path".to_string());
    }
    Ok(clean)
}

fn line_num_prefix_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s*\d+\s\|\s?(.*)$").ok())
        .as_ref()
}

fn maybe_strip_line_numbers(code: &str) -> String {
    let Some(re) = line_num_prefix_re() else {
        return code.to_string();
    };
    let lines: Vec<&str> = code.lines().collect();
    let non_empty: Vec<&&str> = lines.iter().filter(|l| !l.trim().is_empty()).collect();
    if non_empty.is_empty() || !non_empty.iter().all(|l| re.is_match(l)) {
        return code.to_string();
    }
    let mut out = String::with_capacity(code.len());
    for l in lines {
        if l.trim().is_empty() {
            out.push('\n');
        } else if let Some(cap) = re.captures(l) {
            out.push_str(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
            out.push('\n');
        }
    }
    if !code.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

fn heading_file_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^#{2,4}\s+`([^`]+)`(?:\s*\(.*\))?\s*$").ok())
        .as_ref()
}

/// Extract `(rel_path, file_content)` blocks from a Markdown bundle.
pub fn parse_markdown_files(markdown: &str) -> Vec<(String, String)> {
    let h_re = heading_file_re();
    let mut results = Vec::new();
    let mut pending_heading_path: Option<String> = None;

    let lines: Vec<&str> = markdown.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Check for file heading like: ### `src/main.rs`
        if let Some(re) = h_re {
            if let Some(cap) = re.captures(trimmed) {
                if let Some(m) = cap.get(1) {
                    let cand = m.as_str().trim();
                    if !cand.ends_with('/') {
                        pending_heading_path = Some(cand.to_string());
                    }
                }
                i += 1;
                continue;
            }
        }

        // Check for opening fence (3+ backticks)
        let backticks = trimmed.bytes().take_while(|&b| b == b'`').count();
        if backticks >= 3 {
            let info = trimmed[backticks..].trim();
            // Optional inline path in fence info, e.g. ```rust src/main.rs or ```python:app.py
            let inline_path = info
                .split_whitespace()
                .nth(1)
                .map(|s| s.trim_matches('`').to_string())
                .or_else(|| {
                    info.split_once(':')
                        .map(|(_, p)| p.trim().trim_matches('`').to_string())
                });

            let fence_end_prefix = "`".repeat(backticks);
            let mut body_lines = Vec::new();
            i += 1;
            while i < lines.len() {
                let cur = lines[i];
                let cur_trim = cur.trim();
                if cur_trim.len() >= backticks
                    && cur_trim.bytes().all(|b| b == b'`')
                    && cur_trim.starts_with(&fence_end_prefix)
                {
                    break;
                }
                body_lines.push(cur);
                i += 1;
            }

            let chosen_path = inline_path.or_else(|| pending_heading_path.take());
            if let Some(path) = chosen_path {
                // Skip non-file tree/error preview blocks
                if info != "text" || path.contains('.') || path.contains('/') {
                    let mut raw = body_lines.join("\n");
                    raw.push('\n');
                    results.push((path, maybe_strip_line_numbers(&raw)));
                }
            }
            pending_heading_path = None;
        } else if trimmed.starts_with("> *Folder:") || trimmed.starts_with("## ") || trimmed.starts_with("# ") {
            pending_heading_path = None;
        }

        i += 1;
    }

    results
}

async fn atomic_write_unpack(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| format!("failed creating parent dir for {}: {e}", dest.display()))?;
    }
    let tmp_name = format!(
        ".{}.tmp.{}",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        uuid::Uuid::new_v4().simple()
    );
    let tmp_path = dest.with_file_name(tmp_name);
    tokio::fs::write(&tmp_path, bytes)
        .await
        .map_err(|e| format!("failed writing temp file {}: {e}", tmp_path.display()))?;
    if let Err(e) = tokio::fs::rename(&tmp_path, dest).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("failed renaming {} -> {}: {e}", tmp_path.display(), dest.display()));
    }
    Ok(())
}

/// Unpack file blocks from a `.md` bundle back onto disk safely (only modifying files present in the `.md`).
pub async fn unpack_from_markdown(opts: &UnpackOptions) -> Result<UnpackResult, String> {
    let parsed = parse_markdown_files(&opts.markdown);
    if parsed.is_empty() {
        return Err("no file code blocks found in markdown (expected ### `path/to/file` followed by fenced code)".to_string());
    }

    if !opts.dry_run {
        tokio::fs::create_dir_all(&opts.target_dir)
            .await
            .map_err(|e| format!("failed to create target_dir: {e}"))?;
    }

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    let mut skipped = 0usize;
    let mut files = Vec::with_capacity(parsed.len());

    for (raw_path, content) in parsed {
        let rel = match validate_rel_unpack_path(&raw_path) {
            Ok(p) => p,
            Err(reason) => {
                skipped += 1;
                files.push(UnpackFileStatus {
                    rel_path: raw_path,
                    action: "skipped".to_string(),
                    bytes: content.len(),
                    reason: Some(reason),
                });
                continue;
            }
        };

        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let dest = opts.target_dir.join(&rel);

        // Guard against symlink overwrites (including symlinked parent components inside target_dir)
        if let Ok(meta) = tokio::fs::symlink_metadata(&dest).await {
            if meta.file_type().is_symlink() {
                skipped += 1;
                files.push(UnpackFileStatus {
                    rel_path: rel_str,
                    action: "skipped".to_string(),
                    bytes: content.len(),
                    reason: Some("refusing to overwrite symlink".to_string()),
                });
                continue;
            }
        }

        if let Ok(existing) = tokio::fs::read(&dest).await {
            if existing == content.as_bytes() {
                unchanged += 1;
                files.push(UnpackFileStatus {
                    rel_path: rel_str,
                    action: "unchanged".to_string(),
                    bytes: content.len(),
                    reason: None,
                });
                continue;
            }
            if !opts.dry_run {
                atomic_write_unpack(&dest, content.as_bytes()).await?;
            }
            updated += 1;
            files.push(UnpackFileStatus {
                rel_path: rel_str,
                action: "updated".to_string(),
                bytes: content.len(),
                reason: None,
            });
        } else {
            if !opts.dry_run {
                atomic_write_unpack(&dest, content.as_bytes()).await?;
            }
            created += 1;
            files.push(UnpackFileStatus {
                rel_path: rel_str,
                action: "created".to_string(),
                bytes: content.len(),
                reason: None,
            });
        }
    }

    Ok(UnpackResult {
        target_dir: opts.target_dir.clone(),
        dry_run: opts.dry_run,
        created,
        updated,
        unchanged,
        skipped,
        files,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOptions {
    pub project_dir: PathBuf,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub run_tests: bool,
    #[serde(default = "default_verify_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub errors_md_path: Option<PathBuf>,
}

fn default_verify_timeout() -> u64 {
    45
}

impl VerifyOptions {
    pub fn new(project_dir: PathBuf) -> Self {
        Self {
            project_dir,
            commands: Vec::new(),
            run_tests: false,
            timeout_secs: default_verify_timeout(),
            errors_md_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyCheckOutput {
    pub command: String,
    pub exit_code: i32,
    pub passed: bool,
    pub duration_ms: u128,
    pub output: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub passed: bool,
    pub checks: Vec<VerifyCheckOutput>,
    pub errors_md: String,
    pub errors_md_path: Option<PathBuf>,
}

fn detect_project_checks(dir: &Path, run_tests: bool) -> Vec<String> {
    let mut cmds = Vec::new();
    if dir.join("Cargo.toml").is_file() {
        cmds.push("cargo check --message-format=short".to_string());
        if run_tests {
            cmds.push("cargo test --no-fail-fast".to_string());
        }
    }
    if dir.join("tsconfig.json").is_file() {
        cmds.push("npx --no-install tsc --noEmit".to_string());
    }
    if dir.join("go.mod").is_file() {
        cmds.push("go vet ./...".to_string());
        cmds.push("go build ./...".to_string());
        if run_tests {
            cmds.push("go test ./...".to_string());
        }
    }
    let has_py = dir.join("pyproject.toml").is_file()
        || dir.join("requirements.txt").is_file()
        || std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("py"));
    if has_py {
        cmds.push("python3 -m compileall -q -x '(^|/)(\\.git|\\.venv|venv|__pycache__|node_modules|target)(/|$)' .".to_string());
        if run_tests && (dir.join("tests").is_dir() || dir.join("pytest.ini").is_file()) {
            cmds.push("python3 -m pytest -q".to_string());
        }
    }
    let has_php = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("php"));
    if has_php {
        cmds.push("find . -maxdepth 4 \\( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' -o -path '*/.venv' -o -path '*/venv' \\) -prune -o -name '*.php' -print0 | xargs -0 -r -n1 php -l".to_string());
    }
    let has_sh = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sh"));
    if has_sh {
        cmds.push("find . -maxdepth 4 \\( -path '*/.git' -o -path '*/node_modules' -o -path '*/target' -o -path '*/.venv' -o -path '*/venv' \\) -prune -o -name '*.sh' -print0 | xargs -0 -r -n1 bash -n".to_string());
    }
    cmds
}

fn error_loc_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?m)(?:File "([^"]+)", line (\d+)|([A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+):(\d+)(?::\d+)?)"#).ok()
    })
    .as_ref()
}

fn extract_error_snippets(project_dir: &Path, output: &str, max_snippets: usize) -> String {
    let Some(re) = error_loc_re() else {
        return String::new();
    };
    let mut seen = BTreeSet::new();
    let mut out = String::new();
    for cap in re.captures_iter(output) {
        let (file_raw, line_str) = if let (Some(f), Some(l)) = (cap.get(1), cap.get(2)) {
            (f.as_str(), l.as_str())
        } else if let (Some(f), Some(l)) = (cap.get(3), cap.get(4)) {
            (f.as_str(), l.as_str())
        } else {
            continue;
        };
        let Ok(line_no) = line_str.parse::<usize>() else {
            continue;
        };
        if line_no == 0 {
            continue;
        }
        let key = format!("{file_raw}:{line_no}");
        if !seen.insert(key) {
            continue;
        }
        let candidate = {
            let p = Path::new(file_raw);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                project_dir.join(p)
            }
        };
        let Ok(src) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        let start = line_no.saturating_sub(5).max(1);
        let end = (line_no + 4).min(lines.len());
        let lang = lang_for_path(&candidate);
        let _ = writeln!(out, "#### `{file_raw}:{line_no}`\n```{lang}");
        for ln in start..=end {
            let marker = if ln == line_no { ">>>" } else { "   " };
            let _ = writeln!(out, "{marker} {:>4} | {}", ln, lines[ln - 1]);
        }
        let _ = writeln!(out, "```\n");
        if seen.len() >= max_snippets {
            break;
        }
    }
    out
}

/// Run auto-detected or explicit verification commands on a project and produce a structured `errors.md`.
pub async fn verify_project(opts: &VerifyOptions) -> Result<VerifyResult, String> {
    if !opts.project_dir.is_dir() {
        return Err(format!("project_dir is not a directory: {}", opts.project_dir.display()));
    }
    let cmds = if opts.commands.is_empty() {
        detect_project_checks(&opts.project_dir, opts.run_tests)
    } else {
        opts.commands.clone()
    };
    if cmds.is_empty() {
        return Err("no verification commands detected or provided for this project".to_string());
    }

    let timeout = std::time::Duration::from_secs(opts.timeout_secs.clamp(5, 300));
    let mut checks = Vec::with_capacity(cmds.len());
    let mut all_passed = true;

    for cmd in &cmds {
        let start = std::time::Instant::now();
        let mut child = tokio::process::Command::new("bash");
        child
            .arg("-c")
            .arg(cmd)
            .current_dir(&opts.project_dir)
            .env("PATH", format!("/root/.cargo/bin:{}", std::env::var("PATH").unwrap_or_default()));

        let out = tokio::time::timeout(timeout, child.output()).await;
        let duration_ms = start.elapsed().as_millis();

        match out {
            Ok(Ok(res)) => {
                let code = res.status.code().unwrap_or(-1);
                let passed = res.status.success();
                if !passed {
                    all_passed = false;
                }
                let mut combined = String::new();
                let stdout = String::from_utf8_lossy(&res.stdout);
                let stderr = String::from_utf8_lossy(&res.stderr);
                if !stdout.trim().is_empty() {
                    combined.push_str(stdout.trim());
                    combined.push('\n');
                }
                if !stderr.trim().is_empty() {
                    combined.push_str(stderr.trim());
                }
                checks.push(VerifyCheckOutput {
                    command: cmd.clone(),
                    exit_code: code,
                    passed,
                    duration_ms,
                    output: redact_secrets_in_text(&combined),
                });
            }
            Ok(Err(e)) => {
                all_passed = false;
                checks.push(VerifyCheckOutput {
                    command: cmd.clone(),
                    exit_code: -1,
                    passed: false,
                    duration_ms,
                    output: format!("Failed to spawn command: {e}"),
                });
            }
            Err(_) => {
                all_passed = false;
                checks.push(VerifyCheckOutput {
                    command: cmd.clone(),
                    exit_code: 124,
                    passed: false,
                    duration_ms,
                    output: format!("Command timed out after {}s", timeout.as_secs()),
                });
            }
        }
    }

    let mut md = String::with_capacity(4096);
    if all_passed {
        let _ = writeln!(md, "# ✅ Verification Passed: `{}`\n", opts.project_dir.display());
    } else {
        let _ = writeln!(md, "# ❌ Verification Errors (`errors.md`): `{}`\n", opts.project_dir.display());
    }
    let _ = writeln!(md, "| Command | Status | Exit | Duration |");
    let _ = writeln!(md, "|---|---|---:|---:|");
    for c in &checks {
        let st = if c.passed { "✅ PASS" } else { "❌ FAIL" };
        let _ = writeln!(md, "| `{}` | {} | {} | {} ms |", c.command, st, c.exit_code, c.duration_ms);
    }
    let _ = writeln!(md);

    if !all_passed {
        for c in checks.iter().filter(|c| !c.passed) {
            let _ = writeln!(md, "## ❌ Failed Command: `{}` (exit {})\n", c.command, c.exit_code);
            let _ = writeln!(md, "```text\n{}\n```\n", c.output.chars().take(12000).collect::<String>());
            let snippets = extract_error_snippets(&opts.project_dir, &c.output, 10);
            if !snippets.is_empty() {
                let _ = writeln!(md, "### 🔍 Source Context Around Errors\n{snippets}");
            }
        }
    }

    if let Some(ref err_p) = opts.errors_md_path {
        if let Some(parent) = err_p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(err_p, md.as_bytes())
            .map_err(|e| format!("failed writing {}: {e}", err_p.display()))?;
    }

    Ok(VerifyResult {
        passed: all_passed,
        checks,
        errors_md: md,
        errors_md_path: opts.errors_md_path.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packs_directory_with_tree_map_and_symbols() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Demo\n").unwrap();
        std::fs::write(
            src.join("lib.rs"),
            "pub struct Engine {\n    pub id: u32,\n}\npub fn run_task() -> bool {\n    true\n}\n",
        )
        .unwrap();

        let out_md = tmp.path().join("bundle.md");
        let mut opts = PackOptions::new(tmp.path().to_path_buf());
        opts.output_path = Some(out_md.clone());
        let res = pack_to_markdown(&opts).await.unwrap();

        assert_eq!(res.source_kind, "directory");
        assert_eq!(res.total_folders, 1);
        assert_eq!(res.included_files, 2);
        assert!(res.markdown.contains("├── src/"));
        assert!(res.markdown.contains("└── README.md"));
        assert!(res.markdown.contains("`src` | `lib.rs` | `rust`"));
        assert!(res.markdown.contains("`struct Engine`"));
        assert!(res.markdown.contains("`fn run_task`"));
        assert!(out_md.exists());
    }

    #[tokio::test]
    async fn packs_zip_preserving_folders_and_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let zip_path = tmp.path().join("sample.zip");
        let py = r#"
import zipfile, sys
with zipfile.ZipFile(sys.argv[1], 'w') as zf:
    zf.writestr('app/main.py', 'def greet(name):\n    return f"hi {name}"\n')
    zf.writestr('app/utils/helper.py', 'class Helper:\n    pass\n')
"#;
        let status = std::process::Command::new("python3")
            .arg("-c")
            .arg(py)
            .arg(&zip_path)
            .status()
            .unwrap();
        assert!(status.success());

        let opts = PackOptions::new(zip_path);
        let res = pack_to_markdown(&opts).await.unwrap();

        assert_eq!(res.source_kind, "zip");
        assert_eq!(res.included_files, 2);
        assert!(res.markdown.contains("app/"));
        assert!(res.markdown.contains("utils/"));
        assert!(res.markdown.contains("`app/utils` | `helper.py` | `python`"));
        assert!(res.markdown.contains("`def greet`"));
        assert!(res.markdown.contains("`class Helper`"));
    }

    #[tokio::test]
    async fn roundtrip_pack_unpack_and_blocks_traversal() {
        let src_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(src_dir.path().join("pkg")).unwrap();
        std::fs::write(src_dir.path().join("pkg/mod.py"), "x = 1 | 2\ny = 3\n").unwrap();

        let opts = PackOptions::new(src_dir.path().to_path_buf());
        let packed = pack_to_markdown(&opts).await.unwrap();

        let dst_dir = tempfile::tempdir().unwrap();
        let md_with_evil = format!("{}\n\n### `../evil.txt`\n```text\npwned\n```\n", packed.markdown);
        let ures = unpack_from_markdown(&UnpackOptions {
            target_dir: dst_dir.path().to_path_buf(),
            markdown: md_with_evil,
            dry_run: false,
        })
        .await
        .unwrap();

        assert_eq!(ures.created, 1);
        assert_eq!(ures.skipped, 1);
        let written = std::fs::read_to_string(dst_dir.path().join("pkg/mod.py")).unwrap();
        assert_eq!(written, "x = 1 | 2\ny = 3\n");
        assert!(!dst_dir.path().join("../evil.txt").exists());

        #[cfg(unix)]
        {
            let outside = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(outside.path(), "original").unwrap();
            std::os::unix::fs::symlink(outside.path(), dst_dir.path().join("sym.txt")).unwrap();
            let sres = unpack_from_markdown(&UnpackOptions {
                target_dir: dst_dir.path().to_path_buf(),
                markdown: "### `sym.txt`\n```text\noverwritten\n```\n".to_string(),
                dry_run: false,
            })
            .await
            .unwrap();
            assert_eq!(sres.skipped, 1);
            assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "original");
        }
    }

    #[tokio::test]
    async fn verify_project_generates_errors_md_then_passes() {
        let dir = tempfile::tempdir().unwrap();
        let py_file = dir.path().join("broken.py");
        std::fs::write(&py_file, "def ok():\n    return 1\n\ndef bad(:\n    pass\n").unwrap();

        let err_md = dir.path().join("errors.md");
        let mut vopts = VerifyOptions::new(dir.path().to_path_buf());
        vopts.errors_md_path = Some(err_md.clone());
        let res1 = verify_project(&vopts).await.unwrap();
        assert!(!res1.passed);
        assert!(res1.errors_md.contains("Verification Errors"));
        assert!(err_md.exists());

        std::fs::write(&py_file, "def ok():\n    return 1\n\ndef fixed():\n    return 2\n").unwrap();
        let res2 = verify_project(&vopts).await.unwrap();
        assert!(res2.passed);
        assert!(res2.errors_md.contains("Verification Passed"));
    }

    #[tokio::test]
    async fn inspect_zip_recursive_and_verify_zip_outbox_archive() {
        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("outer.zip");
        let py_create = r#"
import io, zipfile, sys
inner_buf = io.BytesIO()
with zipfile.ZipFile(inner_buf, 'w') as z2:
    z2.writestr('sub/service.py', 'def calc(x):\n    return x * 2\n')
    z2.writestr('sub/helper.js', 'function ok() { return 1; }\n')
with zipfile.ZipFile(sys.argv[1], 'w') as z1:
    z1.writestr('api.py', 'import json\ndef parse(s):\n    return json.loads(s)\n')
    z1.writestr('sub_service.zip', inner_buf.getvalue())
"#;
        let st = std::process::Command::new("python3")
            .arg("-c")
            .arg(py_create)
            .arg(&outer)
            .status()
            .unwrap();
        assert!(st.success());

        let summary = inspect_zip_recursive(&outer, 2).await.unwrap();
        assert_eq!(summary.code_files, 3, "got: {summary:?}");
        assert!(summary.nested_zips.contains(&"sub_service.zip".to_string()));
        assert!(summary.detected_stack.contains(&"python".to_string()));
        assert!(summary.detected_stack.contains(&"javascript".to_string()));
        assert!(summary.markdown_overview.contains("sub_service.zip -> sub/service.py"));
        assert!(verify_zip_outbox_archive(&outer).await.is_none());

        // Broken syntax inside nested zip must be caught!
        let bad_outer = dir.path().join("bad_outer.zip");
        let py_bad = r#"
import io, zipfile, sys
inner_buf = io.BytesIO()
with zipfile.ZipFile(inner_buf, 'w') as z2:
    z2.writestr('sub/broken.py', 'def oops(:\n    pass\n')
with zipfile.ZipFile(sys.argv[1], 'w') as z1:
    z1.writestr('sub_service.zip', inner_buf.getvalue())
"#;
        let st2 = std::process::Command::new("python3")
            .arg("-c")
            .arg(py_bad)
            .arg(&bad_outer)
            .status()
            .unwrap();
        assert!(st2.success());
        let err = verify_zip_outbox_archive(&bad_outer)
            .await
            .expect("broken nested python file must be flagged");
        assert!(err.contains("broken.py") && err.contains("syntax error"), "got: {err}");
    }
}
