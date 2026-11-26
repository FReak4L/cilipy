//! `skill_index`: compact, fast, pure-Rust search over skill/agent/command/rule/prompt markdown.
//!
//! * Tokenizer: Unicode lowercase, split on non-alphanumerics and camelCase boundaries
//!   (`HTMLParser` → `html`,`parser`). At index time compounds joined by `-`/`_`/camelCase
//!   additionally emit their concatenation (`test-driven` → `test`,`driven`,`testdriven`),
//!   so both `testdriven` and `test driven` find it, without inflating field lengths.
//! * BM25F over 5 fields (name 4.0, description 2.5, tags 2.0, `#` headings 1.5, body 1.0)
//!   with field-specific `b_f` saturation, unified quantized `ALLF` combined index with
//!   128-doc Block-Max metadata, O(1) open-addressed vocabulary lookup, generation-stamped
//!   zero-allocation sparse workspace, and DisMax expansion scoring.
//! * Byte trigram index over a per-char case fold of name/description/tags/body (hybrid
//!   sorted-list / bitset postings, word-level bitset intersection, filter pushdown) used
//!   as a *necessary-condition* prefilter for phrases and regexes, with an ASCII literal
//!   fast path for verified ASCII documents.
//! * Myers/Hyyrö bit-parallel fuzzy matching with `[u64; 128]` ASCII direct lookup and
//!   32-bit character-set bitmask lower-bound pruning.
use regex::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DocKind {
    Skill,
    Agent,
    Command,
    Rule,
    Prompt,
    Doc,
}

impl DocKind {
    const ALL: [DocKind; 6] = [
        Self::Skill,
        Self::Agent,
        Self::Command,
        Self::Rule,
        Self::Prompt,
        Self::Doc,
    ];
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Agent => "agent",
            Self::Command => "command",
            Self::Rule => "rule",
            Self::Prompt => "prompt",
            Self::Doc => "doc",
        }
    }
    /// Case-insensitive; accepts plural forms (`skills`).
    pub fn parse(s: &str) -> Option<Self> {
        let l = s.trim().to_ascii_lowercase();
        let l = l.strip_suffix('s').unwrap_or(&l);
        Self::ALL.into_iter().find(|k| k.as_str() == l)
    }
}

#[derive(Debug, Clone)]
pub struct DocInput {
    pub id: String,
    pub source: String,
    pub kind: DocKind,
    pub name: String,
    pub description: String,
    pub path: String,
    pub tags: Vec<String>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub source: String,
    pub kind: DocKind,
    pub name: String,
    pub description: String,
    pub path: String,
    pub score: f32,
    pub lines: u32,
    pub chars: u32,
    pub words: u32,
    pub snippets: Vec<(u32, String)>,
    pub duplicates: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub total: usize,
    pub elapsed_us: u64,
    pub plan: String,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DocView<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub kind: DocKind,
    pub name: &'a str,
    pub description: &'a str,
    pub path: &'a str,
    pub tags: &'a [String],
    pub body: &'a str,
    pub lines: u32,
    pub chars: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexStats {
    pub docs: usize,
    pub terms: usize,
    pub trigrams: usize,
    pub postings: usize,
    pub dedup_groups: usize,
    pub big_docs: usize,
    pub per_source: BTreeMap<String, usize>,
    pub per_kind: BTreeMap<String, usize>,
    pub build_ms: u64,
    pub approx_bytes: usize,
}

// ---------------------------------------------------------------- constants & helpers
const NF: usize = 5; // name, desc, tags, headings, body
const FW: [f32; NF] = [4.0, 2.5, 2.0, 1.5, 1.0];
const B_F: [f32; NF] = [0.25, 0.45, 0.25, 0.50, 0.75];
const ALLF: u8 = 0b11111;
const K1: f32 = 1.2;
const MAX_EXP: usize = 32;
const MAX_SET: usize = 16;
const BLK_SIZE: usize = 128;
const BIG_DOC: usize = 64 * 1024; // larger docs are always trigram candidates (memory)
const METRICS: [&str; 4] = ["lines", "chars", "words", "tokens"];

fn is_stop(s: &str) -> bool {
    matches!(
        s,
        "an" | "and"
            | "are"
            | "as"
            | "at"
            | "be"
            | "but"
            | "by"
            | "can"
            | "do"
            | "doe"
            | "for"
            | "from"
            | "has"
            | "have"
            | "if"
            | "in"
            | "into"
            | "is"
            | "it"
            | "its"
            | "not"
            | "of"
            | "on"
            | "or"
            | "so"
            | "such"
            | "than"
            | "that"
            | "the"
            | "their"
            | "then"
            | "there"
            | "these"
            | "they"
            | "this"
            | "to"
            | "your"
            | "was"
            | "we"
            | "were"
            | "will"
            | "with"
            | "you"
    )
}

#[derive(Default, Clone, Copy)]
struct Fx(u64);
impl Fx {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
}
impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut b = [0u8; 8];
            b[..c.len()].copy_from_slice(c);
            self.add(u64::from_le_bytes(b));
        }
    }
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
}
type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

#[inline]
fn fx_bytes(bytes: &[u8]) -> u64 {
    let mut h = Fx::default();
    h.write(bytes);
    h.finish()
}

fn stem(w: &mut String) {
    if w.len() < 4 || !w.bytes().all(|b| b.is_ascii_lowercase()) {
        return;
    }
    let n = w.len();
    let ends = |s: &str, keep: usize| w.ends_with(s) && n - s.len() >= keep;
    let (cut, add) = if ends("ies", 3) {
        (3, "y")
    } else if ends("sses", 3)
        || ends("xes", 2)
        || ends("ches", 3)
        || ends("shes", 3)
        || ends("zes", 3)
    {
        (2, "")
    } else if ends("ing", 4) {
        (3, "")
    } else if (ends("ed", 3) && !w.ends_with("eed")) || ends("ly", 4) {
        (2, "")
    } else if w.ends_with('s') && !(w.ends_with("ss") || w.ends_with("us") || w.ends_with("is")) {
        (1, "")
    } else {
        (0, "")
    };
    w.truncate(n - cut);
    w.push_str(add);
}

fn emit_tok(s: &mut String, is_joined: bool, emit: &mut dyn FnMut(&str, bool)) {
    stem(s);
    if s.chars().nth(1).is_some() && !is_stop(s) {
        emit(s, is_joined);
    }
}

/// Tokenize `text`. `joined` also emits compound concatenations with `is_joined = true`.
fn tokenize(text: &str, joined: bool, emit: &mut dyn FnMut(&str, bool)) {
    let (mut part, mut join, mut nparts) = (String::new(), String::new(), 0usize);
    fn end_part(part: &mut String, nparts: &mut usize, emit: &mut dyn FnMut(&str, bool)) {
        if !part.is_empty() {
            *nparts += 1;
            emit_tok(part, false, emit);
            part.clear();
        }
    }
    let mut it = text.chars().peekable();
    let mut prev = ' ';
    while let Some(c) = it.next() {
        let next = it.peek().copied().unwrap_or(' ');
        if c.is_alphanumeric() {
            let camel = (prev.is_lowercase() && c.is_uppercase())
                || (prev.is_uppercase() && c.is_uppercase() && next.is_lowercase());
            if camel && !part.is_empty() {
                end_part(&mut part, &mut nparts, emit);
            }
            if c.is_ascii() {
                part.push(c.to_ascii_lowercase());
            } else {
                part.extend(c.to_lowercase());
            }
            if joined && c.is_ascii() {
                join.push(c.to_ascii_lowercase());
            } else if joined {
                join.extend(c.to_lowercase());
            }
        } else {
            end_part(&mut part, &mut nparts, emit);
            if !((c == '-' || c == '_') && prev.is_alphanumeric() && next.is_alphanumeric()) {
                if joined && nparts >= 2 {
                    emit_tok(&mut join, true, emit);
                }
                join.clear();
                nparts = 0;
            }
        }
        prev = c;
    }
    end_part(&mut part, &mut nparts, emit);
    if joined && nparts >= 2 {
        emit_tok(&mut join, true, emit);
    }
}

/// Normalize a name/query phrase for exact-name matching: lowercase, collapse separators to single space.
fn norm_name_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = true;
    for c in s.chars() {
        if c.is_alphanumeric() {
            if c.is_ascii() {
                out.push(c.to_ascii_lowercase());
            } else {
                out.extend(c.to_lowercase());
            }
            space = false;
        } else if !space {
            out.push(' ');
            space = true;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Return `(byte_offset, line_offset)` past a leading YAML frontmatter block (`---\n...\n---\n`).
/// Returns `(0, 0)` if no valid closing delimiter exists.
fn frontmatter_body_start(text: &str) -> (usize, usize) {
    let bom = usize::from(text.starts_with('\u{feff}')) * 3;
    let rest = &text[bom..];
    let after_open = if let Some(s) = rest.strip_prefix("---\r\n") {
        s
    } else if let Some(s) = rest.strip_prefix("---\n") {
        s
    } else {
        return (0, 0);
    };
    let mut pos = text.len() - after_open.len();
    for (line_no, raw) in (1usize..).zip(after_open.split_inclusive('\n')) {
        let trimmed = raw.trim_end_matches(['\r', '\n']);
        if trimmed == "---" {
            return (pos + raw.len(), line_no + 1);
        }
        pos += raw.len();
    }
    (0, 0)
}

/// Compute canonical representative priority for dedup tie-breaking.
fn canonical_rank(doc: &DocInput) -> u8 {
    let p = doc.path.to_ascii_lowercase().replace('\\', "/");
    let mut r: i32 = 100;
    if p.contains("/pi/core/") || p.starts_with("pi/core/") {
        r -= 40;
    }
    if p.contains("/.kiro/")
        || p.contains("/.cursor/")
        || p.contains("/.agents/")
        || p.contains("/.trae/")
    {
        r -= 35;
    }
    if p.contains("legacy-command-shims") {
        r -= 35;
    }
    if p.contains("/template/") || p.ends_with("/template/skill.md") {
        r -= 25;
    }
    if p.contains("/skills/") && !p.contains("/pi/core/") {
        r += 10;
    }
    r += match doc.source.as_str() {
        "superpowers" => 8,
        "anthropic-skills" => 7,
        "claude-code" => 6,
        "ecc" => 5,
        "mattpocock-skills" => 4,
        _ => 0,
    };
    r.clamp(0, 255) as u8
}

/// Per-char fold used by the trigram index: ASCII lowercase, single-char Unicode lowercase,
/// `ſ`→`s`. Any char of a regex class whose members all fold to one char can be indexed.
fn fold_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    if c == 'ſ' {
        return 's';
    }
    let mut l = c.to_lowercase();
    match (l.next(), l.next()) {
        (Some(x), None) => x,
        _ => c,
    }
}
fn fold_into(s: &str, out: &mut Vec<u8>) {
    for c in s.chars() {
        if c.is_ascii() {
            out.push((c as u8).to_ascii_lowercase());
        } else {
            out.extend_from_slice(fold_char(c).encode_utf8(&mut [0u8; 4]).as_bytes());
        }
    }
}
#[inline]
fn pack(w: &[u8]) -> u32 {
    ((w[0] as u32) << 16) | ((w[1] as u32) << 8) | w[2] as u32
}

/// Fast ASCII case-insensitive substring check. Sound when both haystack and needle are pure ASCII.
#[inline]
fn ascii_contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let m = needle.len();
    if m == 0 {
        return true;
    }
    if haystack.len() < m {
        return false;
    }
    let first_lo = needle[0].to_ascii_lowercase();
    let first_hi = needle[0].to_ascii_uppercase();
    let limit = haystack.len() - m;
    let mut i = 0usize;
    if first_lo == first_hi {
        while i <= limit {
            if haystack[i] == first_lo && haystack[i..i + m].eq_ignore_ascii_case(needle) {
                return true;
            }
            i += 1;
        }
    } else {
        while i <= limit {
            let b = haystack[i];
            if (b == first_lo || b == first_hi)
                && haystack[i..i + m].eq_ignore_ascii_case(needle)
            {
                return true;
            }
            i += 1;
        }
    }
    false
}

#[derive(Clone)]
struct Bits(Vec<u64>);
impl Bits {
    fn new(n: usize, full: bool) -> Self {
        let mut v = vec![if full { !0u64 } else { 0 }; n.div_ceil(64)];
        if full && !n.is_multiple_of(64) {
            *v.last_mut().unwrap() = (1u64 << (n % 64)) - 1;
        }
        Bits(v)
    }
    #[inline]
    fn get(&self, i: u32) -> bool {
        (self.0[(i >> 6) as usize] >> (i & 63)) & 1 == 1
    }
    #[inline]
    fn set(&mut self, i: u32) {
        self.0[(i >> 6) as usize] |= 1 << (i & 63);
    }
    fn and(&mut self, o: &Bits, negate: bool) {
        for (a, b) in self.0.iter_mut().zip(&o.0) {
            *a &= if negate { !b } else { *b };
        }
    }
    /// Compute `(min_doc, max_doc, popcount)` in `O(N/64)` word operations.
    fn bounds(&self) -> (u32, u32, usize) {
        let mut count = 0usize;
        let mut min_doc = u32::MAX;
        let mut max_doc = 0u32;
        for (wi, &w) in self.0.iter().enumerate() {
            if w != 0 {
                let base = (wi as u32) * 64;
                if min_doc == u32::MAX {
                    min_doc = base + w.trailing_zeros();
                }
                max_doc = base + (63 - w.leading_zeros());
                count += w.count_ones() as usize;
            }
        }
        (min_doc, max_doc, count)
    }
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().enumerate().flat_map(|(w, &x)| {
            let mut x = x;
            std::iter::from_fn(move || {
                (x != 0).then(|| {
                    let t = x.trailing_zeros();
                    x &= x - 1;
                    w as u32 * 64 + t
                })
            })
        })
    }
}

/// Adaptive intersection of two sorted lists: linear merge when balanced, galloping when skewed.
fn intersect(a: &[u32], b: &[u32]) -> Vec<u32> {
    let (a, b) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if a.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(a.len());
    if b.len() < a.len() * 8 {
        let (mut i, mut j) = (0usize, 0usize);
        while i < a.len() && j < b.len() {
            let (va, vb) = (a[i], b[j]);
            if va == vb {
                out.push(va);
                i += 1;
                j += 1;
            } else if va < vb {
                i += 1;
            } else {
                j += 1;
            }
        }
        return out;
    }
    let mut lo = 0usize;
    for &x in a {
        let (mut prev, mut hi, mut step) = (lo, lo, 1);
        while hi < b.len() && b[hi] < x {
            prev = hi + 1;
            hi += step;
            step <<= 1;
        }
        lo = prev + b[prev..hi.min(b.len())].partition_point(|&v| v < x);
        if lo == b.len() {
            break;
        }
        if b[lo] == x {
            out.push(x);
            lo += 1;
        }
    }
    out
}

#[inline]
fn char_mask(s: &str) -> u32 {
    let mut m = 0u32;
    for c in s.chars() {
        let bit = if c.is_ascii_lowercase() {
            (c as u8 - b'a') as u32
        } else if c.is_ascii() {
            26 + ((c as u32) % 5)
        } else {
            31
        };
        m |= 1u32 << bit;
    }
    m
}

/// Myers/Hyyrö bit-parallel Levenshtein + adjacent transposition (OSA) with ASCII `[u64; 128]` fast table.
struct Myers {
    p: Vec<char>,
    peq: Vec<(char, u64)>,
    peq_ascii: [u64; 128],
    ascii: bool,
}
impl Myers {
    fn new(p: &str) -> Self {
        let p_chars: Vec<char> = p.chars().collect();
        let ascii = p.is_ascii() && p_chars.len() <= 64;
        let mut peq_ascii = [0u64; 128];
        let mut peq: Vec<(char, u64)> = Vec::new();
        for (i, &c) in p_chars.iter().enumerate().take(64) {
            if c.is_ascii() {
                peq_ascii[c as usize] |= 1u64 << i;
            }
            match peq.iter_mut().find(|e| e.0 == c) {
                Some(e) => e.1 |= 1u64 << i,
                None => peq.push((c, 1u64 << i)),
            }
        }
        Myers {
            p: p_chars,
            peq,
            peq_ascii,
            ascii,
        }
    }
    /// Optimal-string-alignment distance (Levenshtein + adjacent transposition, so `tset`~`test` = 1).
    fn dist(&self, t: &str) -> usize {
        let m = self.p.len();
        if m == 0 || m > 64 {
            return osa_dp(&self.p, &t.chars().collect::<Vec<_>>());
        }
        let last = 1u64 << (m - 1);
        let (mut vp, mut vn, mut score, mut d0p, mut eqp) = (!0u64, 0u64, m, 0u64, 0u64);
        if self.ascii && t.is_ascii() {
            for &b in t.as_bytes() {
                let eq = self.peq_ascii[(b & 0x7f) as usize];
                let tr = ((!d0p & eq) << 1) & eqp;
                let d0 = ((eq & vp).wrapping_add(vp) ^ vp) | eq | vn | tr;
                let hp = vn | !(d0 | vp);
                let hn = d0 & vp;
                if hp & last != 0 {
                    score += 1;
                } else if hn & last != 0 {
                    score -= 1;
                }
                let x = (hp << 1) | 1;
                vn = x & d0;
                vp = (hn << 1) | !(x | d0);
                (d0p, eqp) = (d0, eq);
            }
            return score;
        }
        for c in t.chars() {
            let eq = self.peq.iter().find(|e| e.0 == c).map_or(0, |e| e.1);
            let tr = ((!d0p & eq) << 1) & eqp;
            let d0 = ((eq & vp).wrapping_add(vp) ^ vp) | eq | vn | tr;
            let hp = vn | !(d0 | vp);
            let hn = d0 & vp;
            if hp & last != 0 {
                score += 1;
            } else if hn & last != 0 {
                score -= 1;
            }
            let x = (hp << 1) | 1;
            vn = x & d0;
            vp = (hn << 1) | !(x | d0);
            (d0p, eqp) = (d0, eq);
        }
        score
    }
}
fn osa_dp(a: &[char], b: &[char]) -> usize {
    let mut d: Vec<Vec<usize>> = (0..=a.len())
        .map(|i| (0..=b.len()).map(|j| if i == 0 { j } else { i }).collect())
        .collect();
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let mut v = (d[i - 1][j - 1] + usize::from(a[i - 1] != b[j - 1]))
                .min(d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[a.len()][b.len()]
}

// ---------------------------------------------------------------- regex literal analysis
#[derive(Debug, Clone)]
enum Tq {
    All,
    Lit(Vec<u8>),
    And(Vec<Tq>),
    Or(Vec<Tq>),
}
impl Tq {
    fn and(v: Vec<Tq>) -> Tq {
        let mut o = Vec::new();
        for q in v {
            match q {
                Tq::All => {}
                Tq::And(x) => o.extend(x),
                q => o.push(q),
            }
        }
        if o.len() <= 1 {
            o.pop().unwrap_or(Tq::All)
        } else {
            Tq::And(o)
        }
    }
    fn or(mut v: Vec<Tq>) -> Tq {
        if v.iter().any(|q| matches!(q, Tq::All)) {
            Tq::All
        } else if v.len() == 1 {
            v.pop().unwrap()
        } else {
            Tq::Or(v)
        }
    }
    fn set(s: &[Vec<u8>]) -> Tq {
        Tq::or(
            s.iter()
                .map(|x| {
                    if x.len() >= 3 {
                        Tq::Lit(x.clone())
                    } else {
                        Tq::All
                    }
                })
                .collect(),
        )
    }
}
struct Info {
    exact: Option<Vec<Vec<u8>>>,
    q: Tq,
}
impl Info {
    fn ex(s: Vec<Vec<u8>>) -> Self {
        Info {
            exact: Some(s),
            q: Tq::All,
        }
    }
    fn any() -> Self {
        Info {
            exact: None,
            q: Tq::All,
        }
    }
    fn full(self) -> Tq {
        match self.exact {
            Some(s) => Tq::set(&s),
            None => self.q,
        }
    }
}
fn class_set(chars: impl Iterator<Item = char>) -> Info {
    let mut set: Vec<char> = Vec::new();
    for c in chars.map(fold_char) {
        if !set.contains(&c) {
            if set.len() == 4 {
                return Info::any();
            }
            set.push(c);
        }
    }
    Info::ex(
        set.into_iter()
            .map(|c| c.to_string().into_bytes())
            .collect(),
    )
}
fn analyze(h: &Hir) -> Info {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => Info::ex(vec![vec![]]),
        HirKind::Literal(l) => match std::str::from_utf8(&l.0) {
            Ok(s) => {
                let mut b = Vec::new();
                fold_into(s, &mut b);
                Info::ex(vec![b])
            }
            Err(_) => Info::any(),
        },
        HirKind::Class(Class::Unicode(c)) => {
            let n: u32 = c
                .ranges()
                .iter()
                .map(|r| r.end() as u32 - r.start() as u32 + 1)
                .sum();
            if n > 64 {
                Info::any()
            } else {
                class_set(c.ranges().iter().flat_map(|r| r.start()..=r.end()))
            }
        }
        HirKind::Class(Class::Bytes(c)) => {
            let n: u32 = c
                .ranges()
                .iter()
                .map(|r| r.end() as u32 - r.start() as u32 + 1)
                .sum();
            if n > 64 || c.ranges().iter().any(|r| r.end() >= 0x80) {
                Info::any()
            } else {
                class_set(
                    c.ranges()
                        .iter()
                        .flat_map(|r| r.start()..=r.end())
                        .map(char::from),
                )
            }
        }
        HirKind::Capture(c) => analyze(&c.sub),
        HirKind::Repetition(r) if r.min == 0 => Info::any(),
        HirKind::Repetition(r) if r.max == Some(1) => analyze(&r.sub),
        HirKind::Repetition(r) => Info {
            exact: None,
            q: analyze(&r.sub).full(),
        },
        HirKind::Concat(hs) => {
            let (mut acc, mut cur, mut exact) = (Vec::new(), Some(vec![Vec::new()]), true);
            for h in hs {
                let i = analyze(h);
                match (i.exact, cur.take()) {
                    (Some(e), Some(c)) if c.len() * e.len() <= MAX_SET => {
                        cur = Some(
                            c.iter()
                                .flat_map(|a| e.iter().map(move |b| [a.as_slice(), b].concat()))
                                .collect(),
                        )
                    }
                    (Some(e), c) => {
                        acc.extend(c.map(|c| Tq::set(&c)));
                        exact = false;
                        cur = Some(e);
                    }
                    (None, c) => {
                        acc.extend(c.map(|c| Tq::set(&c)));
                        exact = false;
                        acc.push(i.q);
                    }
                }
            }
            if exact {
                Info::ex(cur.unwrap_or_default())
            } else {
                acc.extend(cur.map(|c| Tq::set(&c)));
                Info {
                    exact: None,
                    q: Tq::and(acc),
                }
            }
        }
        HirKind::Alternation(hs) => {
            let infos: Vec<Info> = hs.iter().map(analyze).collect();
            if infos.iter().all(|i| i.exact.is_some()) {
                let mut u: Vec<Vec<u8>> = Vec::new();
                for s in infos.iter().flat_map(|i| i.exact.iter().flatten()) {
                    if !u.contains(s) {
                        u.push(s.clone());
                    }
                }
                if u.len() <= MAX_SET {
                    return Info::ex(u);
                }
            }
            Info {
                exact: None,
                q: Tq::or(infos.into_iter().map(Info::full).collect()),
            }
        }
    }
}
fn compile(p: &str, ci: bool, literal: bool) -> Result<(Regex, Tq), String> {
    let src = if literal {
        regex::escape(p)
    } else {
        p.to_string()
    };
    let re = RegexBuilder::new(&src)
        .case_insensitive(ci)
        .multi_line(true)
        .size_limit(1 << 20)
        .build()
        .map_err(|e| {
            e.to_string()
                .lines()
                .last()
                .unwrap_or("")
                .trim()
                .to_string()
        })?;
    let tq = regex_syntax::ParserBuilder::new()
        .case_insensitive(ci)
        .multi_line(true)
        .build()
        .parse(&src)
        .map_or(Tq::All, |h| analyze(&h).full());
    Ok((re, tq))
}

// ---------------------------------------------------------------- query parsing
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Occur {
    Should,
    Must,
    Not,
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Exact,
    Prefix,
    Fuzzy(u8),
}
struct TermQ {
    occur: Occur,
    text: String,
    mode: Mode,
    mask: u8,
}
struct PatQ {
    occur: Occur,
    mask: u8,
    re: Regex,
    tq: Tq,
    label: String,
    ascii_lit: Option<Vec<u8>>,
}
enum Val {
    Word(String),
    Phrase(String),
    Re(String, bool),
}
struct Raw {
    occur: Occur,
    field: Option<String>,
    val: Val,
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum SortKey {
    Score,
    Metric(usize),
    Name,
    KindName,
}
const FIELDS: [&str; 15] = [
    "name",
    "desc",
    "description",
    "tag",
    "tags",
    "body",
    "source",
    "kind",
    "path",
    "lines",
    "chars",
    "words",
    "tokens",
    "sort",
    "dedup",
];

fn lex(q: &str) -> Vec<Raw> {
    let cs: Vec<char> = q.chars().collect();
    let (n, mut i, mut out) = (cs.len(), 0usize, Vec::new());
    let s = |a: usize, b: usize| cs[a.min(n)..b.min(n)].iter().collect::<String>();
    while i < n {
        if cs[i].is_whitespace() {
            i += 1;
            continue;
        }
        let occur = match cs[i] {
            '+' => Occur::Must,
            '-' => Occur::Not,
            _ => Occur::Should,
        };
        i += usize::from(occur != Occur::Should);
        if i >= n || cs[i].is_whitespace() {
            continue;
        }
        let mut j = i;
        while j < n && cs[j].is_ascii_alphabetic() {
            j += 1;
        }
        let mut field = None;
        if j > i && j + 1 < n && cs[j] == ':' && !cs[j + 1].is_whitespace() {
            let f = s(i, j).to_ascii_lowercase();
            if FIELDS.contains(&f.as_str()) {
                field = Some(f);
                i = j + 1;
            }
        }
        if cs[i] == '"' {
            let mut k = i + 1;
            while k < n && cs[k] != '"' {
                k += 1;
            }
            out.push(Raw {
                occur,
                field,
                val: Val::Phrase(s(i + 1, k)),
            });
            i = k + 1;
            continue;
        }
        if cs[i] == '/' {
            let end = (|| {
                let mut k = i + 1;
                while k < n {
                    if cs[k] == '\\' {
                        k += 2;
                        continue;
                    }
                    let ci = k + 1 < n && cs[k + 1] == 'i';
                    let e = k + 1 + usize::from(ci);
                    if cs[k] == '/' && k > i + 1 && (e >= n || cs[e].is_whitespace()) {
                        return Some((k, ci, e));
                    }
                    k += 1;
                }
                None
            })();
            if let Some((k, ci, e)) = end {
                out.push(Raw {
                    occur,
                    field,
                    val: Val::Re(s(i + 1, k), ci),
                });
                i = e;
                continue;
            }
        }
        let mut k = i;
        while k < n && !cs[k].is_whitespace() {
            k += 1;
        }
        out.push(Raw {
            occur,
            field,
            val: Val::Word(s(i, k)),
        });
        i = k;
    }
    out
}

fn word_terms(w: &str, occur: Occur, mask: u8, out: &mut Vec<TermQ>) {
    let (base, mode) = if let Some(b) = w.strip_suffix('*') {
        (b, Mode::Prefix)
    } else if let Some(b) = w.strip_suffix("~2") {
        (b, Mode::Fuzzy(2))
    } else if let Some(b) = w.strip_suffix("~1").or_else(|| w.strip_suffix('~')) {
        (b, Mode::Fuzzy(1))
    } else {
        (w, Mode::Exact)
    };
    let mut push = |t: &str, _joined: bool| {
        out.push(TermQ {
            occur,
            text: t.to_string(),
            mode,
            mask,
        })
    };
    if mode == Mode::Prefix {
        let p: String = base
            .chars()
            .flat_map(char::to_lowercase)
            .filter(|c| c.is_alphanumeric())
            .collect();
        if !p.is_empty() {
            push(&p, false);
        }
    } else {
        tokenize(base, false, &mut push);
    }
}

fn parse_range(v: &str) -> Option<(u32, u32)> {
    let num = |s: &str| {
        s.trim()
            .parse::<u64>()
            .ok()
            .map(|x| x.min(u32::MAX as u64) as u32)
    };
    if let Some((a, b)) = v.split_once("..") {
        let lo = if a.is_empty() { 0 } else { num(a)? };
        let hi = if b.is_empty() { u32::MAX } else { num(b)? };
        return Some((lo, hi));
    }
    if let Some(r) = v.strip_prefix("<=") {
        return Some((0, num(r)?));
    }
    if let Some(r) = v.strip_prefix(">=") {
        return Some((num(r)?, u32::MAX));
    }
    if let Some(r) = v.strip_prefix('<') {
        return Some(num(r)?.checked_sub(1).map_or((1, 0), |x| (0, x)));
    }
    if let Some(r) = v.strip_prefix('>') {
        return Some(num(r)?.checked_add(1).map_or((1, 0), |x| (x, u32::MAX)));
    }
    let x = num(v.strip_prefix('=').unwrap_or(v))?;
    Some((x, x))
}

fn clip(s: &str) -> String {
    let t = s.trim();
    t.char_indices()
        .nth(200)
        .map_or(t, |(i, _)| &t[..i])
        .to_string()
}

// ---------------------------------------------------------------- scratch workspace
struct SearchScratch {
    stamp: Vec<u32>,
    cur_stamp: u32,
    score: Vec<f32>,
    hits: Vec<u16>,
    clause_stamp: Vec<u32>,
    clause_max: Vec<f32>,
    cur_clause_stamp: u32,
    touched: Vec<u32>,
    grp_stamp: Vec<u32>,
    grp_best: Vec<u32>,
    grp_cnt: Vec<u32>,
    cur_grp_stamp: u32,
    touched_groups: Vec<usize>,
}

impl SearchScratch {
    fn new() -> Self {
        Self {
            stamp: Vec::new(),
            cur_stamp: 0,
            score: Vec::new(),
            hits: Vec::new(),
            clause_stamp: Vec::new(),
            clause_max: Vec::new(),
            cur_clause_stamp: 0,
            touched: Vec::new(),
            grp_stamp: Vec::new(),
            grp_best: Vec::new(),
            grp_cnt: Vec::new(),
            cur_grp_stamp: 0,
            touched_groups: Vec::new(),
        }
    }

    fn prepare(&mut self, n: usize, ngroups: usize) {
        if self.stamp.len() < n {
            self.stamp.resize(n, 0);
            self.score.resize(n, 0.0);
            self.hits.resize(n, 0);
            self.clause_stamp.resize(n, 0);
            self.clause_max.resize(n, 0.0);
        }
        self.cur_stamp = self.cur_stamp.wrapping_add(1);
        if self.cur_stamp == 0 {
            self.stamp.fill(0);
            self.cur_stamp = 1;
        }
        if self.grp_stamp.len() < ngroups {
            self.grp_stamp.resize(ngroups, 0);
            self.grp_best.resize(ngroups, 0);
            self.grp_cnt.resize(ngroups, 0);
        }
        self.cur_grp_stamp = self.cur_grp_stamp.wrapping_add(1);
        if self.cur_grp_stamp == 0 {
            self.grp_stamp.fill(0);
            self.cur_grp_stamp = 1;
        }
        self.touched.clear();
        self.touched_groups.clear();
    }

    #[inline]
    fn ensure_doc(&mut self, du: usize) {
        if self.stamp[du] != self.cur_stamp {
            self.stamp[du] = self.cur_stamp;
            self.score[du] = 0.0;
            self.hits[du] = 0;
            self.touched.push(du as u32);
        }
    }

    #[inline]
    fn next_clause(&mut self) {
        self.cur_clause_stamp = self.cur_clause_stamp.wrapping_add(1);
        if self.cur_clause_stamp == 0 {
            self.clause_stamp.fill(0);
            self.cur_clause_stamp = 1;
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<SearchScratch> = RefCell::new(SearchScratch::new());
}

// ---------------------------------------------------------------- index
struct FieldIndex {
    off: Vec<u32>,
    docs: Vec<u32>,
    tfs: Vec<u16>,
    inv_norm: Vec<f32>,
}
impl FieldIndex {
    #[inline]
    fn postings(&self, t: u32) -> (&[u32], &[u16]) {
        let (a, b) = (
            self.off[t as usize] as usize,
            self.off[t as usize + 1] as usize,
        );
        (&self.docs[a..b], &self.tfs[a..b])
    }
}

struct CombinedIndex {
    off: Vec<u32>,
    docs: Vec<u32>,
    impacts: Vec<u16>,
    max_score: Vec<f32>,
    blk_off: Vec<u32>,
    blk_last_doc: Vec<u32>,
    blk_max_q: Vec<u16>,
}
impl CombinedIndex {
    #[inline]
    fn postings(&self, t: u32) -> (&[u32], &[u16]) {
        let (a, b) = (
            self.off[t as usize] as usize,
            self.off[t as usize + 1] as usize,
        );
        (&self.docs[a..b], &self.impacts[a..b])
    }
    #[inline]
    fn blocks(&self, t: u32) -> (&[u32], &[u16]) {
        let (a, b) = (
            self.blk_off[t as usize] as usize,
            self.blk_off[t as usize + 1] as usize,
        );
        (&self.blk_last_doc[a..b], &self.blk_max_q[a..b])
    }
}

enum TriPost {
    List(Box<[u32]>),
    Bits(Box<[u64]>),
}

struct TermPass {
    terms: Vec<String>,
    df: Vec<u32>,
    raw: [Vec<(u32, u32, u16)>; NF],
    lens: [Vec<u32>; NF],
    body_start: Vec<(u32, u32)>,
}

/// Tokenize all fields, intern terms, collect (term, doc, tf) per field.
/// Skips YAML frontmatter when indexing headings/body so frontmatter is not double-counted.
fn term_pass(docs: &[DocInput]) -> TermPass {
    let mut interner: FxMap<String, u32> = FxMap::default();
    let mut p = TermPass {
        terms: Vec::new(),
        df: Vec::new(),
        raw: Default::default(),
        lens: Default::default(),
        body_start: Vec::with_capacity(docs.len()),
    };
    let mut toks = Vec::<(u32, u8)>::new();
    for (d, doc) in docs.iter().enumerate() {
        toks.clear();
        let mut flen = [0u32; NF];
        let mut add = |f: usize, text: &str| {
            tokenize(text, true, &mut |t: &str, is_joined: bool| {
                let id = match interner.get(t) {
                    Some(&id) => id,
                    None => {
                        interner.insert(t.to_owned(), p.terms.len() as u32);
                        p.terms.push(t.to_owned());
                        p.df.push(0);
                        p.terms.len() as u32 - 1
                    }
                };
                toks.push((id, f as u8));
                if !is_joined {
                    flen[f] += 1;
                }
            })
        };
        add(0, &doc.name);
        add(1, &doc.description);
        doc.tags.iter().for_each(|t| add(2, t));
        let (boff, bline) = frontmatter_body_start(&doc.body);
        p.body_start.push((boff as u32, bline as u32));
        for line in doc.body[boff..].lines() {
            add(
                if line.trim_start().starts_with('#') {
                    3
                } else {
                    4
                },
                line,
            );
        }
        toks.sort_unstable();
        let (mut i, mut last) = (0, u32::MAX);
        while i < toks.len() {
            let j = i + toks[i..].iter().take_while(|&&x| x == toks[i]).count();
            let (t, f) = toks[i];
            p.raw[f as usize].push((t, d as u32, (j - i).min(u16::MAX as usize) as u16));
            if t != last {
                p.df[t as usize] += 1;
                last = t;
            }
            i = j;
        }
        p.lens.iter_mut().zip(flen).for_each(|(l, x)| l.push(x));
    }
    p
}

struct GramPass {
    tri: FxMap<u32, TriPost>,
    big: Vec<u32>,
    body_hash: Vec<Option<u64>>,
    cols: [Vec<u32>; 4],
    doc_ascii: Bits,
}

/// Parallel trigram indexing (no 64 MB upfront zero-fill), numeric columns, ASCII flags, and
/// dedup hashes over the body past YAML frontmatter.
fn gram_pass(docs: &[DocInput]) -> GramPass {
    let n = docs.len();
    let n_threads = std::thread::available_parallelism()
        .map_or(4, |p| p.get().clamp(1, 8))
        .min((n / 128).max(1));
    let chunk_size = n.div_ceil(n_threads).max(1);

    struct ChunkOut {
        gkey: Vec<u32>,
        gpost: Vec<Vec<u32>>,
        big: Vec<u32>,
        body_hash: Vec<Option<u64>>,
        cols: [Vec<u32>; 4],
        ascii_ids: Vec<u32>,
    }

    let chunks: Vec<ChunkOut> = std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(n_threads);
        for (ci, slice) in docs.chunks(chunk_size).enumerate() {
            let base = ci * chunk_size;
            handles.push(s.spawn(move || {
                // 2-level 24-bit direct page table (4096 * 4096): O(1) per window, zero hashing, ~2-4 MB active.
                let mut pages: Vec<Option<Box<[u32; 4096]>>> = vec![None; 4096];
                let mut gkey = Vec::new();
                let mut gpost: Vec<Vec<u32>> = Vec::new();
                let mut gseen: Vec<u32> = Vec::new();
                let mut big = Vec::new();
                let mut body_hash = Vec::with_capacity(slice.len());
                let mut cols: [Vec<u32>; 4] = Default::default();
                let mut ascii_ids = Vec::new();
                let mut buf = Vec::new();
                for (off, doc) in slice.iter().enumerate() {
                    let d = (base + off) as u32;
                    let d_mark = (off + 1) as u32;
                    let size = doc.name.len() + doc.description.len() + doc.body.len();
                    let is_big = size > BIG_DOC;
                    if is_big {
                        big.push(d);
                    }
                    let all_ascii = doc.name.is_ascii()
                        && doc.description.is_ascii()
                        && doc.body.is_ascii()
                        && doc.tags.iter().all(|t| t.is_ascii());
                    if all_ascii {
                        ascii_ids.push(d);
                    }
                    if !is_big {
                        for text in [&doc.name, &doc.description, &doc.body]
                            .into_iter()
                            .map(String::as_str)
                            .chain(doc.tags.iter().map(String::as_str))
                        {
                            buf.clear();
                            fold_into(text, &mut buf);
                            for w in buf.windows(3) {
                                let g = pack(w);
                                let hi = (g >> 12) as usize;
                                let lo = (g & 0xfff) as usize;
                                let page = pages[hi]
                                    .get_or_insert_with(|| Box::new([0u32; 4096]));
                                let slot = page[lo];
                                let id = if slot == 0 {
                                    gkey.push(g);
                                    gpost.push(Vec::new());
                                    gseen.push(0);
                                    let nid = gpost.len() as u32;
                                    page[lo] = nid;
                                    nid as usize - 1
                                } else {
                                    slot as usize - 1
                                };
                                if gseen[id] != d_mark {
                                    gseen[id] = d_mark;
                                    gpost[id].push(d);
                                }
                            }
                        }
                    }
                    let (boff, _) = frontmatter_body_start(&doc.body);
                    buf.clear();
                    fold_into(&doc.body[boff..], &mut buf);
                    let mut h = std::hash::DefaultHasher::new();
                    let mut any = false;
                    for w in buf
                        .split(|b| b.is_ascii_whitespace())
                        .filter(|w| !w.is_empty())
                    {
                        any = true;
                        h.write(w);
                        h.write_u8(b' ');
                    }
                    body_hash.push(any.then(|| h.finish()));
                    let chars = doc.body.chars().count() as u32;
                    let m = [
                        doc.body.lines().count() as u32,
                        chars,
                        doc.body.split_whitespace().count() as u32,
                        chars.div_ceil(4),
                    ];
                    cols.iter_mut().zip(m).for_each(|(c, x)| c.push(x));
                }
                ChunkOut {
                    gkey,
                    gpost,
                    big,
                    body_hash,
                    cols,
                    ascii_ids,
                }
            }));
        }
        handles.into_iter().map(|h| h.join().expect("gram worker")).collect()
    });

    let mut merged_grams: FxMap<u32, Vec<u32>> = FxMap::default();
    let mut big = Vec::new();
    let mut body_hash = Vec::with_capacity(n);
    let mut cols: [Vec<u32>; 4] = Default::default();
    let mut doc_ascii = Bits::new(n, false);
    for ch in chunks {
        big.extend(ch.big);
        body_hash.extend(ch.body_hash);
        for (dst, src) in cols.iter_mut().zip(ch.cols) {
            dst.extend(src);
        }
        for d in ch.ascii_ids {
            doc_ascii.set(d);
        }
        for (g, list) in ch.gkey.into_iter().zip(ch.gpost) {
            merged_grams.entry(g).or_default().extend(list);
        }
    }

    let words = n.div_ceil(64);
    let tri: FxMap<u32, TriPost> = merged_grams
        .into_iter()
        .map(|(k, l)| {
            let p = if l.len() * 32 > n.max(64) {
                let mut b = vec![0u64; words];
                l.iter().for_each(|&d| b[d as usize >> 6] |= 1 << (d & 63));
                TriPost::Bits(b.into())
            } else {
                TriPost::List(l.into())
            };
            (k, p)
        })
        .collect();

    GramPass {
        tri,
        big,
        body_hash,
        cols,
        doc_ascii,
    }
}

pub struct SkillIndex {
    docs: Vec<DocInput>,
    groups: Vec<u32>,
    ngroups: usize,
    terms: Vec<String>,
    term_ht: Vec<u32>,
    ht_mask: usize,
    by_len: Vec<Vec<(u32, u32)>>,
    df: Vec<u32>,
    idf: Vec<f32>,
    fields: [FieldIndex; NF],
    combined: CombinedIndex,
    kind_prior: Vec<f32>,
    canonical_rank: Vec<u8>,
    body_start: Vec<(u32, u32)>,
    tri: FxMap<u32, TriPost>,
    big: Vec<u32>,
    doc_ascii: Bits,
    cols: [Vec<u32>; 4],
    perms: [Vec<u32>; 4],
    name_rank: Vec<u32>,
    ids: HashMap<String, u32>,
    names: HashMap<String, Vec<u32>>,
    norm_names: HashMap<String, Vec<u32>>,
    known_sources: Vec<String>,
    build_ms: u64,
}

impl SkillIndex {
    pub fn build(inputs: Vec<DocInput>) -> Self {
        let t0 = Instant::now();
        let n = inputs.len();
        let (
            TermPass {
                terms: raw_terms,
                df: raw_df,
                raw,
                lens,
                body_start,
            },
            GramPass {
                tri,
                big,
                body_hash,
                cols,
                doc_ascii,
            },
        ) = std::thread::scope(|s| {
            let grams = s.spawn(|| gram_pass(&inputs));
            let terms = term_pass(&inputs);
            (terms, grams.join().expect("trigram pass panicked"))
        });

        let v = raw_terms.len();
        // Stage 1: Sort terms lexicographically and remap term IDs so term_id == vocab rank.
        let mut order: Vec<u32> = (0..v as u32).collect();
        order.sort_unstable_by(|&a, &b| raw_terms[a as usize].cmp(&raw_terms[b as usize]));
        let mut remap = vec![0u32; v];
        for (new_id, &old_id) in order.iter().enumerate() {
            remap[old_id as usize] = new_id as u32;
        }
        let mut terms: Vec<String> = Vec::with_capacity(v);
        let mut df: Vec<u32> = Vec::with_capacity(v);
        let mut idf: Vec<f32> = Vec::with_capacity(v);
        for &old_id in &order {
            terms.push(raw_terms[old_id as usize].clone());
            let d = raw_df[old_id as usize];
            df.push(d);
            let dff = d as f32;
            idf.push((1.0 + (n as f32 - dff + 0.5) / (dff + 0.5)).ln());
        }
        drop(raw_terms);
        drop(raw_df);
        drop(order);

        // Open-addressed linear-probing hash table for O(1) exact term lookup.
        let ht_size = (v * 2).max(16).next_power_of_two();
        let ht_mask = ht_size - 1;
        let mut term_ht = vec![u32::MAX; ht_size];
        for (id, t) in terms.iter().enumerate() {
            let mut slot = fx_bytes(t.as_bytes()) as usize & ht_mask;
            while term_ht[slot] != u32::MAX {
                slot = (slot + 1) & ht_mask;
            }
            term_ht[slot] = id as u32;
        }

        // by_len with 32-bit character-set mask for fast fuzzy pruning.
        let mut by_len: Vec<Vec<(u32, u32)>> = Vec::new();
        for (id, t) in terms.iter().enumerate() {
            let l = t.chars().count();
            if by_len.len() <= l {
                by_len.resize(l + 1, Vec::new());
            }
            by_len[l].push((id as u32, char_mask(t)));
        }

        // Build per-field CSRs (remapping term IDs) and precompute lambda_{f,d} = FW[f] / norm_{f,d}.
        let fields: [FieldIndex; NF] = {
            fn build_one(
                f: usize,
                r: Vec<(u32, u32, u16)>,
                flens: &[u32],
                remap: &[u32],
                v: usize,
            ) -> FieldIndex {
                let mut off = vec![0u32; v + 1];
                for &(old_t, _, _) in &r {
                    off[remap[old_t as usize] as usize + 1] += 1;
                }
                let mut acc = 0u32;
                for o in &mut off {
                    acc += *o;
                    *o = acc;
                }
                let mut pos = off.clone();
                let (mut docs, mut tfs) = (vec![0u32; r.len()], vec![0u16; r.len()]);
                for (old_t, d, tf) in r {
                    let nt = remap[old_t as usize] as usize;
                    let p = &mut pos[nt];
                    docs[*p as usize] = d;
                    tfs[*p as usize] = tf;
                    *p += 1;
                }
                let nz_sum: f64 = flens.iter().filter(|&&x| x > 0).map(|&x| x as f64).sum();
                let nz_cnt = flens.iter().filter(|&&x| x > 0).count().max(1);
                let avg = (nz_sum / nz_cnt as f64).max(1.0) as f32;
                let bf = B_F[f];
                let fw = FW[f];
                let inv_norm: Vec<f32> = flens
                    .iter()
                    .map(|&len| {
                        let norm = (1.0 - bf + bf * (len as f32 / avg)).max(0.1);
                        fw / norm
                    })
                    .collect();
                FieldIndex {
                    off,
                    docs,
                    tfs,
                    inv_norm,
                }
            }
            let [r0, r1, r2, r3, r4] = raw;
            let [l0, l1, l2, l3, l4] = &lens;
            let remap_ref = &remap;
            std::thread::scope(|s| {
                let h0 = s.spawn(move || build_one(0, r0, l0, remap_ref, v));
                let h1 = s.spawn(move || build_one(1, r1, l1, remap_ref, v));
                let h2 = s.spawn(move || build_one(2, r2, l2, remap_ref, v));
                let h3 = s.spawn(move || build_one(3, r3, l3, remap_ref, v));
                let f4 = build_one(4, r4, l4, remap_ref, v);
                [
                    h0.join().expect("f0"),
                    h1.join().expect("f1"),
                    h2.join().expect("f2"),
                    h3.join().expect("f3"),
                    f4,
                ]
            })
        };

        // Stage 2: Build unified quantized CombinedIndex (for mask == ALLF) + 128-doc blocks in parallel,
        // and build numeric sort permutations concurrently.
        let (combined, perms) = std::thread::scope(|s| {
            let perm_handle = s.spawn(|| -> [Vec<u32>; 4] {
                std::array::from_fn(|m| {
                    let mut p: Vec<u32> = (0..n as u32).collect();
                    p.sort_by_key(|&d| cols[m][d as usize]);
                    p
                })
            });

            struct CombChunk {
                docs: Vec<u32>,
                impacts: Vec<u16>,
                max_score: Vec<f32>,
                blk_last_doc: Vec<u32>,
                blk_max_q: Vec<u16>,
                term_lens: Vec<u32>,
                blk_lens: Vec<u32>,
            }
            let n_threads = std::thread::available_parallelism()
                .map_or(4, |p| p.get().clamp(1, 8))
                .min((v / 512).max(1));
            let t_chunk = v.div_ceil(n_threads).max(1);
            let fields_ref = &fields;
            let idf_ref = &idf;
            let mut c_handles = Vec::with_capacity(n_threads);
            for t_start in (0..v).step_by(t_chunk) {
                let t_end = (t_start + t_chunk).min(v);
                c_handles.push(s.spawn(move || {
                    let span = t_end - t_start;
                    let mut docs = Vec::new();
                    let mut impacts = Vec::new();
                    let mut max_score = Vec::with_capacity(span);
                    let mut blk_last_doc = Vec::new();
                    let mut blk_max_q = Vec::new();
                    let mut term_lens = Vec::with_capacity(span);
                    let mut blk_lens = Vec::with_capacity(span);
                    let mut merged: Vec<(u32, f32)> = Vec::new();

                    for (t_off, &idft) in idf_ref[t_start..t_end].iter().enumerate() {
                        let t = t_start + t_off;
                        let slices = [
                            fields_ref[0].postings(t as u32),
                            fields_ref[1].postings(t as u32),
                            fields_ref[2].postings(t as u32),
                            fields_ref[3].postings(t as u32),
                            fields_ref[4].postings(t as u32),
                        ];
                        let mut active = 0usize;
                        let mut only_f = 0usize;
                        for (f, sl) in slices.iter().enumerate() {
                            if !sl.0.is_empty() {
                                active += 1;
                                only_f = f;
                            }
                        }
                        merged.clear();
                        if active == 1 {
                            let (ds, tfs) = slices[only_f];
                            let inv = &fields_ref[only_f].inv_norm;
                            merged.reserve(ds.len());
                            for (&d, &tf) in ds.iter().zip(tfs) {
                                let tf_sum = tf as f32 * inv[d as usize];
                                merged.push((d, idft * tf_sum / (K1 + tf_sum)));
                            }
                        } else if active > 1 {
                            let mut cur_idx = [0usize; NF];
                            loop {
                                let mut min_d = u32::MAX;
                                for f in 0..NF {
                                    if cur_idx[f] < slices[f].0.len() {
                                        min_d = min_d.min(slices[f].0[cur_idx[f]]);
                                    }
                                }
                                if min_d == u32::MAX {
                                    break;
                                }
                                let mut tf_sum = 0f32;
                                for f in 0..NF {
                                    if cur_idx[f] < slices[f].0.len()
                                        && slices[f].0[cur_idx[f]] == min_d
                                    {
                                        let tf = slices[f].1[cur_idx[f]] as f32;
                                        tf_sum += tf * fields_ref[f].inv_norm[min_d as usize];
                                        cur_idx[f] += 1;
                                    }
                                }
                                merged.push((min_d, idft * tf_sum / (K1 + tf_sum)));
                            }
                        }
                        let max_s = merged.iter().fold(0f32, |m, &(_, sc)| m.max(sc));
                        max_score.push(max_s);
                        let inv_max = if max_s > 0.0 { 65535.0 / max_s } else { 0.0 };
                        let start_pos = docs.len();
                        for &(d, sc) in &merged {
                            docs.push(d);
                            let q = if max_s > 0.0 {
                                (sc * inv_max).round().clamp(1.0, 65535.0) as u16
                            } else {
                                1
                            };
                            impacts.push(q);
                        }
                        term_lens.push(merged.len() as u32);
                        let q_slice = &impacts[start_pos..];
                        let d_slice = &docs[start_pos..];
                        let b_before = blk_last_doc.len();
                        for (bi, d_blk) in d_slice.chunks(BLK_SIZE).enumerate() {
                            let q_blk = &q_slice[bi * BLK_SIZE..bi * BLK_SIZE + d_blk.len()];
                            blk_last_doc.push(*d_blk.last().unwrap());
                            blk_max_q.push(q_blk.iter().copied().max().unwrap_or(0));
                        }
                        blk_lens.push((blk_last_doc.len() - b_before) as u32);
                    }
                    CombChunk {
                        docs,
                        impacts,
                        max_score,
                        blk_last_doc,
                        blk_max_q,
                        term_lens,
                        blk_lens,
                    }
                }));
            }

            let chunks: Vec<CombChunk> = c_handles
                .into_iter()
                .map(|h| h.join().expect("comb worker"))
                .collect();
            let total_docs: usize = chunks.iter().map(|c| c.docs.len()).sum();
            let total_blks: usize = chunks.iter().map(|c| c.blk_last_doc.len()).sum();
            let mut c_off = Vec::with_capacity(v + 1);
            c_off.push(0);
            let mut blk_off = Vec::with_capacity(v + 1);
            blk_off.push(0);
            let mut c_docs = Vec::with_capacity(total_docs);
            let mut c_impacts = Vec::with_capacity(total_docs);
            let mut c_max_score = Vec::with_capacity(v);
            let mut blk_last_doc = Vec::with_capacity(total_blks);
            let mut blk_max_q = Vec::with_capacity(total_blks);
            let (mut d_acc, mut b_acc) = (0u32, 0u32);
            for ch in chunks {
                c_docs.extend(ch.docs);
                c_impacts.extend(ch.impacts);
                c_max_score.extend(ch.max_score);
                blk_last_doc.extend(ch.blk_last_doc);
                blk_max_q.extend(ch.blk_max_q);
                for l in ch.term_lens {
                    d_acc += l;
                    c_off.push(d_acc);
                }
                for l in ch.blk_lens {
                    b_acc += l;
                    blk_off.push(b_acc);
                }
            }
            let combined = CombinedIndex {
                off: c_off,
                docs: c_docs,
                impacts: c_impacts,
                max_score: c_max_score,
                blk_off,
                blk_last_doc,
                blk_max_q,
            };
            (combined, perm_handle.join().expect("perms"))
        });

        let kind_prior: Vec<f32> = inputs
            .iter()
            .map(|d| match d.kind {
                DocKind::Doc => 0.7,
                DocKind::Prompt => 0.9,
                _ => 1.0,
            })
            .collect();
        let canonical_rank: Vec<u8> = inputs.iter().map(canonical_rank).collect();

        let mut name_order: Vec<u32> = (0..n as u32).collect();
        name_order.sort_by_cached_key(|&d| (inputs[d as usize].name.to_lowercase(), d));
        let mut name_rank = vec![0u32; n];
        name_order
            .iter()
            .enumerate()
            .for_each(|(r, &d)| name_rank[d as usize] = r as u32);

        let (mut ids, mut names, mut norm_names) = (
            HashMap::with_capacity(n),
            HashMap::<String, Vec<u32>>::new(),
            HashMap::<String, Vec<u32>>::new(),
        );
        let mut known_sources: Vec<String> = Vec::new();
        for (d, doc) in inputs.iter().enumerate() {
            ids.entry(doc.id.clone()).or_insert(d as u32);
            names
                .entry(doc.name.trim().to_lowercase())
                .or_default()
                .push(d as u32);
            let nk = norm_name_key(&doc.name);
            if !nk.is_empty() {
                norm_names.entry(nk).or_default().push(d as u32);
            }
            let src_low = doc.source.trim().to_lowercase();
            if !src_low.is_empty() && !known_sources.contains(&src_low) {
                known_sources.push(src_low);
            }
        }
        known_sources.sort();

        // dedup groups: identical normalised body (past frontmatter) OR same kind+name across >= 2 sources
        let mut parent: Vec<u32> = (0..n as u32).collect();
        fn find(p: &mut [u32], mut x: u32) -> u32 {
            while p[x as usize] != x {
                p[x as usize] = p[p[x as usize] as usize];
                x = p[x as usize];
            }
            x
        }
        let unite = |p: &mut Vec<u32>, a: u32, b: u32| {
            let (ra, rb) = (find(p, a), find(p, b));
            p[ra.max(rb) as usize] = ra.min(rb);
        };
        let mut by_body: HashMap<u64, u32> = HashMap::new();
        let mut by_name: HashMap<(DocKind, String), Vec<u32>> = HashMap::new();
        for (d, doc) in inputs.iter().enumerate() {
            if let Some(h) = body_hash[d] {
                let first = *by_body.entry(h).or_insert(d as u32);
                unite(&mut parent, first, d as u32);
            }
            if doc.kind != DocKind::Doc && !doc.name.trim().is_empty() {
                by_name
                    .entry((doc.kind, doc.name.trim().to_lowercase()))
                    .or_default()
                    .push(d as u32);
            }
        }
        for g in by_name.values() {
            if g.iter()
                .any(|&d| inputs[d as usize].source != inputs[g[0] as usize].source)
            {
                g.iter().for_each(|&d| unite(&mut parent, g[0], d));
            }
        }
        let (mut groups, mut gid) = (vec![0u32; n], HashMap::new());
        for d in 0..n as u32 {
            let r = find(&mut parent, d);
            let len = gid.len() as u32;
            groups[d as usize] = *gid.entry(r).or_insert(len);
        }
        terms.shrink_to_fit();

        SkillIndex {
            docs: inputs,
            groups,
            ngroups: gid.len(),
            terms,
            term_ht,
            ht_mask,
            by_len,
            df,
            idf,
            fields,
            combined,
            kind_prior,
            canonical_rank,
            body_start,
            tri,
            big,
            doc_ascii,
            cols,
            perms,
            name_rank,
            ids,
            names,
            norm_names,
            known_sources,
            build_ms: t0.elapsed().as_millis() as u64,
        }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }
    pub fn known_sources(&self) -> &[String] {
        &self.known_sources
    }

    fn doc_view(&self, d: usize) -> DocView<'_> {
        let x = &self.docs[d];
        DocView {
            id: &x.id,
            source: &x.source,
            kind: x.kind,
            name: &x.name,
            description: &x.description,
            path: &x.path,
            tags: &x.tags,
            body: &x.body,
            lines: self.cols[0][d],
            chars: self.cols[1][d],
        }
    }

    /// Exact id, else case-insensitive exact name (prefer kind Skill, then canonical rank).
    pub fn get(&self, id_or_name: &str) -> Option<DocView<'_>> {
        let d = self.ids.get(id_or_name).copied().or_else(|| {
            let v = self.names.get(&id_or_name.trim().to_lowercase())?;
            v.iter()
                .copied()
                .max_by_key(|&d| {
                    (
                        self.docs[d as usize].kind == DocKind::Skill,
                        self.canonical_rank[d as usize],
                        Reverse(self.name_rank[d as usize]),
                    )
                })
        })? as usize;
        Some(self.doc_view(d))
    }

    /// O(1) exact name lookup returning all matching document IDs (optionally filtered by kind).
    pub fn ids_by_name(&self, name: &str, kind: Option<DocKind>) -> Vec<&str> {
        self.names
            .get(&name.trim().to_lowercase())
            .map(|v| {
                v.iter()
                    .copied()
                    .filter(|&d| kind.is_none_or(|k| self.docs[d as usize].kind == k))
                    .map(|d| self.docs[d as usize].id.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Alphabetical catalog browse by optional source and/or kind, with optional deduplication.
    pub fn catalog(
        &self,
        source: Option<&str>,
        kind: Option<DocKind>,
        dedup: bool,
        offset: usize,
        limit: usize,
    ) -> (usize, Vec<DocView<'_>>) {
        let src_low = source.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
        let mut matched: Vec<u32> = self
            .docs
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                src_low
                    .as_deref()
                    .is_none_or(|s| d.source.eq_ignore_ascii_case(s))
                    && kind.is_none_or(|k| d.kind == k)
            })
            .map(|(i, _)| i as u32)
            .collect();

        if dedup && !matched.is_empty() {
            let mut best: HashMap<u32, u32> = HashMap::new();
            for d in matched {
                let g = self.groups[d as usize];
                best.entry(g)
                    .and_modify(|cur| {
                        let c_key = (
                            self.canonical_rank[*cur as usize],
                            Reverse(self.name_rank[*cur as usize]),
                        );
                        let d_key = (
                            self.canonical_rank[d as usize],
                            Reverse(self.name_rank[d as usize]),
                        );
                        if d_key > c_key {
                            *cur = d;
                        }
                    })
                    .or_insert(d);
            }
            matched = best.into_values().collect();
        }

        matched.sort_unstable_by_key(|&d| {
            (
                self.docs[d as usize].kind as u8,
                self.name_rank[d as usize],
                d,
            )
        });
        let total = matched.len();
        let views = matched
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|d| self.doc_view(d as usize))
            .collect();
        (total, views)
    }

    /// Rough heap usage of the index including stored documents.
    pub fn memory_bytes(&self) -> usize {
        let s = |x: &String| x.capacity() + 24;
        let docs: usize = self
            .docs
            .iter()
            .map(|d| {
                s(&d.id)
                    + s(&d.source)
                    + s(&d.name)
                    + s(&d.description)
                    + s(&d.path)
                    + s(&d.body)
                    + d.tags.iter().map(s).sum::<usize>()
                    + 64
            })
            .sum();
        let fields: usize = self
            .fields
            .iter()
            .map(|f| f.off.len() * 4 + f.docs.len() * 6 + f.inv_norm.len() * 4)
            .sum();
        let comb = self.combined.off.len() * 4
            + self.combined.docs.len() * 4
            + self.combined.impacts.len() * 2
            + self.combined.max_score.len() * 4
            + self.combined.blk_off.len() * 4
            + self.combined.blk_last_doc.len() * 4
            + self.combined.blk_max_q.len() * 2;
        let tri: usize = self
            .tri
            .values()
            .map(|p| {
                24 + match p {
                    TriPost::List(l) => l.len() * 4,
                    TriPost::Bits(b) => b.len() * 8,
                }
            })
            .sum();
        let terms: usize = self.terms.iter().map(|t| s(t) + 16).sum();
        let n = self.docs.len();
        docs + fields
            + comb
            + tri
            + terms
            + self.term_ht.len() * 4
            + n * (4 * 8 + 16)
            + (self.ids.len() + self.names.len() + self.norm_names.len()) * 64
    }

    pub fn stats(&self) -> IndexStats {
        let (mut per_source, mut per_kind) = (BTreeMap::new(), BTreeMap::new());
        for d in &self.docs {
            *per_source.entry(d.source.clone()).or_insert(0) += 1;
            *per_kind.entry(d.kind.as_str().to_string()).or_insert(0) += 1;
        }
        IndexStats {
            docs: self.docs.len(),
            terms: self.terms.len(),
            trigrams: self.tri.len(),
            postings: self.fields.iter().map(|f| f.docs.len()).sum(),
            dedup_groups: self.ngroups,
            big_docs: self.big.len(),
            per_source,
            per_kind,
            build_ms: self.build_ms,
            approx_bytes: self.memory_bytes(),
        }
    }

    /// O(1) open-addressed lookup in `term_ht`.
    #[inline]
    fn lookup(&self, s: &str) -> Option<u32> {
        if self.terms.is_empty() {
            return None;
        }
        let mut slot = fx_bytes(s.as_bytes()) as usize & self.ht_mask;
        loop {
            let id = self.term_ht[slot];
            if id == u32::MAX {
                return None;
            }
            if self.terms[id as usize] == s {
                return Some(id);
            }
            slot = (slot + 1) & self.ht_mask;
        }
    }

    fn fuzzy(&self, q: &str, k: usize) -> Vec<(u32, usize)> {
        let m = Myers::new(q);
        let ql = m.p.len();
        let qm = char_mask(q);
        let mut out = Vec::new();
        for ids in self
            .by_len
            .iter()
            .take(ql + k + 1)
            .skip(ql.saturating_sub(k))
        {
            for &(id, wm) in ids {
                if (qm & !wm).count_ones() as usize > k || (wm & !qm).count_ones() as usize > k {
                    continue;
                }
                let d = m.dist(&self.terms[id as usize]);
                if d <= k {
                    out.push((id, d));
                }
            }
        }
        out
    }

    fn expand(&self, t: &TermQ) -> Vec<(u32, f32)> {
        match t.mode {
            Mode::Exact => self
                .lookup(&t.text)
                .map(|id| vec![(id, 1.0)])
                .unwrap_or_default(),
            Mode::Prefix => {
                let lo = self.terms.partition_point(|w| w.as_str() < t.text.as_str());
                let mut v: Vec<u32> = (lo..self.terms.len())
                    .take_while(|&id| self.terms[id].starts_with(&t.text))
                    .map(|id| id as u32)
                    .collect();
                if v.len() > MAX_EXP {
                    v.sort_by_key(|&id| Reverse(self.df[id as usize]));
                    v.truncate(MAX_EXP);
                }
                v.into_iter().map(|id| (id, 1.0)).collect()
            }
            Mode::Fuzzy(k) => {
                let mut v = self.fuzzy(&t.text, k as usize);
                v.sort_by_key(|&(id, d)| (d, Reverse(self.df[id as usize])));
                v.truncate(MAX_EXP);
                v.into_iter()
                    .map(|(id, d)| (id, 1.0 / (1.0 + d as f32)))
                    .collect()
            }
        }
    }

    fn term_bits(&self, exp: &[(u32, f32)], mask: u8) -> Bits {
        let mut b = Bits::new(self.docs.len(), false);
        for &(id, _) in exp {
            if mask == ALLF {
                self.combined.postings(id).0.iter().for_each(|&d| b.set(d));
            } else {
                for (_, fi) in self
                    .fields
                    .iter()
                    .enumerate()
                    .filter(|(f, _)| (mask >> f) & 1 == 1)
                {
                    fi.postings(id).0.iter().for_each(|&d| b.set(d));
                }
            }
        }
        b
    }

    fn bits_where(&self, f: impl Fn(&DocInput) -> bool) -> Bits {
        let mut b = Bits::new(self.docs.len(), false);
        self.docs
            .iter()
            .enumerate()
            .filter(|(_, d)| f(d))
            .for_each(|(i, _)| b.set(i as u32));
        b
    }

    fn range_bits(&self, m: usize, lo: u32, hi: u32) -> Bits {
        let (col, perm) = (&self.cols[m], &self.perms[m]);
        let a = perm.partition_point(|&d| col[d as usize] < lo);
        let b = perm.partition_point(|&d| col[d as usize] <= hi);
        let mut bits = Bits::new(self.docs.len(), false);
        perm[a..b.max(a)].iter().for_each(|&d| bits.set(d));
        bits
    }

    /// Candidate docs for a trigram condition (`None` = all docs), with optional filter pushdown.
    fn eval(&self, q: &Tq, filter: Option<&Bits>) -> Option<Vec<u32>> {
        match q {
            Tq::All => None,
            Tq::Lit(s) => {
                let mut grams: Vec<u32> = s.windows(3).map(pack).collect();
                grams.sort_unstable();
                grams.dedup();
                let (mut lists, mut bits) = (Vec::<&[u32]>::new(), Vec::<&[u64]>::new());
                let mut acc = 'lit: {
                    for g in grams {
                        match self.tri.get(&g) {
                            None => break 'lit Vec::new(),
                            Some(TriPost::List(l)) => lists.push(l),
                            Some(TriPost::Bits(b)) => bits.push(b),
                        }
                    }
                    if lists.is_empty() {
                        let words = self.docs.len().div_ceil(64);
                        if let Some(first_b) = bits.first() {
                            let mut combined = match filter {
                                Some(f) => f.0.clone(),
                                None => first_b.to_vec(),
                            };
                            let start_idx = usize::from(filter.is_none());
                            for b in &bits[start_idx..] {
                                for (dst, &src) in combined.iter_mut().zip(b.iter()) {
                                    *dst &= src;
                                }
                            }
                            let mut out = Vec::new();
                            for (wi, &w) in combined.iter().enumerate() {
                                let mut x = w;
                                let base = (wi as u32) * 64;
                                while x != 0 {
                                    let t = x.trailing_zeros();
                                    x &= x - 1;
                                    out.push(base + t);
                                }
                            }
                            out
                        } else if let Some(f) = filter {
                            let _ = words;
                            f.iter().collect()
                        } else {
                            (0..self.docs.len() as u32).collect()
                        }
                    } else {
                        lists.sort_by_key(|l| l.len());
                        let mut acc: Vec<u32> = if let Some(f) = filter {
                            lists[0].iter().copied().filter(|&d| f.get(d)).collect()
                        } else {
                            lists[0].to_vec()
                        };
                        for l in &lists[1..] {
                            if acc.is_empty() {
                                break;
                            }
                            acc = intersect(&acc, l);
                        }
                        if !bits.is_empty() && !acc.is_empty() {
                            acc.retain(|&d| {
                                bits.iter()
                                    .all(|b| (b[d as usize >> 6] >> (d & 63)) & 1 == 1)
                            });
                        }
                        acc
                    }
                };
                if !self.big.is_empty() {
                    let prev_len = acc.len();
                    match filter {
                        Some(f) => acc.extend(self.big.iter().copied().filter(|&d| f.get(d))),
                        None => acc.extend_from_slice(&self.big),
                    }
                    if acc.len() > prev_len {
                        acc.sort_unstable();
                        acc.dedup();
                    }
                }
                Some(acc)
            }
            Tq::And(v) => {
                let mut lists: Vec<Vec<u32>> =
                    v.iter().filter_map(|q| self.eval(q, filter)).collect();
                lists.sort_by_key(Vec::len);
                let mut it = lists.into_iter();
                let first = it.next()?;
                Some(it.fold(first, |a, l| {
                    if a.is_empty() {
                        a
                    } else {
                        intersect(&a, &l)
                    }
                }))
            }
            Tq::Or(v) => {
                let mut out = Vec::new();
                for q in v {
                    out.extend(self.eval(q, filter)?);
                }
                out.sort_unstable();
                out.dedup();
                Some(out)
            }
        }
    }

    #[inline]
    fn pat_match(&self, p: &PatQ, d: u32) -> bool {
        let x = &self.docs[d as usize];
        let ascii_lit = p.ascii_lit.as_deref().filter(|_| self.doc_ascii.get(d));
        let check = |s: &str| -> bool {
            if let Some(needle) = ascii_lit {
                ascii_contains_ci(s.as_bytes(), needle)
            } else {
                p.re.is_match(s)
            }
        };
        ((p.mask & 1) != 0 && check(&x.name))
            || ((p.mask & 2) != 0 && check(&x.description))
            || ((p.mask & 4) != 0 && x.tags.iter().any(|t| check(t)))
            || ((p.mask & 24) != 0 && check(&x.body))
    }

    fn score_into_scratch(
        &self,
        clauses: &[(u8, &[(u32, f32)])],
        filter: Option<&Bits>,
        filter_bounds: Option<(u32, u32, usize)>,
        sc: &mut SearchScratch,
    ) {
        let mut acc: Vec<f32> = Vec::new();
        let mut acc_touched: Vec<u32> = Vec::new();
        let n = self.docs.len();
        let need_acc = clauses.iter().any(|&(mask, _)| mask != ALLF);
        if need_acc {
            acc.resize(n, 0.0);
        }

        for &(mask, exp) in clauses {
            if exp.is_empty() {
                continue;
            }
            let dismax = exp.len() > 1;
            if dismax {
                sc.next_clause();
            }

            if mask == ALLF {
                for &(id, w) in exp {
                    let max_s = self.combined.max_score[id as usize];
                    if max_s <= 0.0 {
                        continue;
                    }
                    let (ds, qs) = self.combined.postings(id);
                    if ds.is_empty() {
                        continue;
                    }
                    let scale = w * (max_s / 65535.0);

                    let (lo, hi) = if let Some((min_d, max_d, fcnt)) = filter_bounds {
                        if min_d > max_d || ds[0] > max_d || *ds.last().unwrap() < min_d {
                            continue;
                        }
                        if fcnt * 8 < ds.len() && ds.len() >= 64 {
                            let f = filter.unwrap();
                            let mut pos = 0usize;
                            for d in f.iter() {
                                if d > *ds.last().unwrap() {
                                    break;
                                }
                                let rel = ds[pos..].partition_point(|&v| v < d);
                                pos += rel;
                                if pos >= ds.len() {
                                    break;
                                }
                                if ds[pos] == d {
                                    let contrib = qs[pos] as f32 * scale;
                                    let du = d as usize;
                                    sc.ensure_doc(du);
                                    if !dismax {
                                        sc.score[du] += contrib;
                                        sc.hits[du] = sc.hits[du].saturating_add(1);
                                    } else if sc.clause_stamp[du] != sc.cur_clause_stamp {
                                        sc.clause_stamp[du] = sc.cur_clause_stamp;
                                        sc.clause_max[du] = contrib;
                                        sc.score[du] += contrib;
                                        sc.hits[du] = sc.hits[du].saturating_add(1);
                                    } else {
                                        sc.score[du] += contrib * 0.15;
                                        if contrib > sc.clause_max[du] {
                                            sc.score[du] += (contrib - sc.clause_max[du]) * 0.85;
                                            sc.clause_max[du] = contrib;
                                        }
                                    }
                                    pos += 1;
                                }
                            }
                            continue;
                        }
                        let (blk_last, _) = self.combined.blocks(id);
                        let start_blk = blk_last.partition_point(|&last| last < min_d);
                        let end_blk = blk_last.partition_point(|&last| last < max_d);
                        let start_idx = (start_blk * BLK_SIZE).min(ds.len());
                        let lo = start_idx + ds[start_idx..].partition_point(|&v| v < min_d);
                        let end_limit = ((end_blk + 1) * BLK_SIZE).min(ds.len());
                        let hi = lo + ds[lo..end_limit].partition_point(|&v| v <= max_d);
                        (lo, hi)
                    } else {
                        (0, ds.len())
                    };

                    for (&d, &q) in ds[lo..hi].iter().zip(&qs[lo..hi]) {
                        if filter.is_some_and(|f| !f.get(d)) {
                            continue;
                        }
                        let contrib = q as f32 * scale;
                        let du = d as usize;
                        sc.ensure_doc(du);
                        if !dismax {
                            sc.score[du] += contrib;
                            sc.hits[du] = sc.hits[du].saturating_add(1);
                        } else if sc.clause_stamp[du] != sc.cur_clause_stamp {
                            sc.clause_stamp[du] = sc.cur_clause_stamp;
                            sc.clause_max[du] = contrib;
                            sc.score[du] += contrib;
                            sc.hits[du] = sc.hits[du].saturating_add(1);
                        } else {
                            sc.score[du] += contrib * 0.15;
                            if contrib > sc.clause_max[du] {
                                sc.score[du] += (contrib - sc.clause_max[du]) * 0.85;
                                sc.clause_max[du] = contrib;
                            }
                        }
                    }
                }
            } else {
                // Field-masked scoring (e.g. name:, desc:, tag:, body:).
                if !dismax {
                    sc.next_clause();
                }
                for &(id, w) in exp {
                    let idf = self.idf[id as usize];
                    for (_f, fi) in self
                        .fields
                        .iter()
                        .enumerate()
                        .filter(|(f, _)| (mask >> f) & 1 == 1)
                    {
                        let (ds, tfs) = fi.postings(id);
                        for (&d, &tf) in ds.iter().zip(tfs) {
                            if filter.is_some_and(|fl| !fl.get(d)) {
                                continue;
                            }
                            let du = d as usize;
                            if acc[du] == 0.0 {
                                acc_touched.push(d);
                            }
                            acc[du] += tf as f32 * fi.inv_norm[du];
                        }
                    }
                    for &d in &acc_touched {
                        let du = d as usize;
                        let t = std::mem::take(&mut acc[du]);
                        let contrib = w * idf * t / (K1 + t);
                        sc.ensure_doc(du);
                        if !dismax {
                            sc.score[du] += contrib;
                            if sc.clause_stamp[du] != sc.cur_clause_stamp {
                                sc.clause_stamp[du] = sc.cur_clause_stamp;
                                sc.hits[du] = sc.hits[du].saturating_add(1);
                            }
                        } else if sc.clause_stamp[du] != sc.cur_clause_stamp {
                            sc.clause_stamp[du] = sc.cur_clause_stamp;
                            sc.clause_max[du] = contrib;
                            sc.score[du] += contrib;
                            sc.hits[du] = sc.hits[du].saturating_add(1);
                        } else {
                            sc.score[du] += contrib * 0.15;
                            if contrib > sc.clause_max[du] {
                                sc.score[du] += (contrib - sc.clause_max[du]) * 0.85;
                                sc.clause_max[du] = contrib;
                            }
                        }
                    }
                    acc_touched.clear();
                }
            }
        }
    }

    pub fn search(&self, query: &str, limit: usize) -> SearchResponse {
        let t0 = Instant::now();
        let n = self.docs.len();
        let mut filter: Option<Bits> = None;
        let apply_filter = |filter: &mut Option<Bits>, b: Bits, negate: bool| match filter {
            Some(f) => f.and(&b, negate),
            None => {
                let mut base = Bits::new(n, true);
                base.and(&b, negate);
                *filter = Some(base);
            }
        };

        let (mut terms, mut pats, mut notes, mut filt) = (
            Vec::<TermQ>::new(),
            Vec::<PatQ>::new(),
            Vec::new(),
            Vec::new(),
        );
        let (mut sort, mut dedup) = (None, true);
        let mut raw_name_parts: Vec<String> = Vec::new();
        let mut bad_sources: Vec<String> = Vec::new();

        for Raw { occur, field, val } in lex(query) {
            let text = match &val {
                Val::Word(s) | Val::Phrase(s) | Val::Re(s, _) => s.clone(),
            };
            let neg = occur == Occur::Not;
            match field.as_deref() {
                Some("sort") => {
                    let (flip, k) = text
                        .strip_prefix('-')
                        .map_or((false, text.as_str()), |k| (true, k));
                    let key = match k.to_ascii_lowercase().as_str() {
                        "score" | "relevance" => Some((SortKey::Score, true)),
                        "name" => Some((SortKey::Name, false)),
                        "kind" => Some((SortKey::KindName, false)),
                        m => METRICS
                            .iter()
                            .position(|x| *x == m)
                            .map(|i| (SortKey::Metric(i), false)),
                    };
                    match key {
                        Some((k, d)) => sort = Some((k, d ^ flip)),
                        None => notes.push(format!("unknown sort '{text}' ignored")),
                    }
                }
                Some("dedup") => {
                    dedup = !matches!(
                        text.to_ascii_lowercase().as_str(),
                        "off" | "no" | "false" | "0"
                    )
                }
                Some("kind") => {
                    let mut ks: Vec<DocKind> = Vec::new();
                    for part in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        match DocKind::parse(part) {
                            Some(k) => ks.push(k),
                            None => notes.push(format!(
                                "unknown kind '{part}' (valid: skill, agent, command, rule, prompt, doc)"
                            )),
                        }
                    }
                    apply_filter(
                        &mut filter,
                        self.bits_where(|d| ks.contains(&d.kind)),
                        neg,
                    );
                    filt.push(format!("{}kind={text}", if neg { "-" } else { "" }));
                }
                Some("source") => {
                    let ss: Vec<&str> = text
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect();
                    for &s in &ss {
                        let sl = s.to_ascii_lowercase();
                        if !self.known_sources.is_empty() && !self.known_sources.contains(&sl) {
                            notes.push(format!(
                                "unknown source '{s}' (valid: {})",
                                self.known_sources.join(", ")
                            ));
                            bad_sources.push(sl);
                        }
                    }
                    apply_filter(
                        &mut filter,
                        self.bits_where(|d| ss.iter().any(|s| s.eq_ignore_ascii_case(&d.source))),
                        neg,
                    );
                    filt.push(format!("{}source={text}", if neg { "-" } else { "" }));
                }
                Some("path") => match val {
                    Val::Re(p, ci) => match RegexBuilder::new(&p).case_insensitive(ci).build() {
                        Ok(re) => {
                            apply_filter(
                                &mut filter,
                                self.bits_where(|d| re.is_match(&d.path)),
                                neg,
                            );
                            filt.push(format!(
                                "{}path~/{p}/{}",
                                if neg { "-" } else { "" },
                                if ci { "i" } else { "" }
                            ));
                        }
                        Err(e) => {
                            notes.push(format!(
                                "invalid path regex /{p}/ ({e}): treated as substring"
                            ));
                            let low = p.to_lowercase();
                            apply_filter(
                                &mut filter,
                                self.bits_where(|d| d.path.to_lowercase().contains(&low)),
                                neg,
                            );
                            filt.push(format!("{}path~{p}", if neg { "-" } else { "" }));
                        }
                    },
                    _ => {
                        let p = text.to_lowercase();
                        apply_filter(
                            &mut filter,
                            self.bits_where(|d| d.path.to_lowercase().contains(&p)),
                            neg,
                        );
                        filt.push(format!("{}path~{text}", if neg { "-" } else { "" }));
                    }
                },
                Some(m @ ("lines" | "chars" | "words" | "tokens")) => match parse_range(&text) {
                    Some((lo, hi)) => {
                        let mi = METRICS.iter().position(|x| *x == m).unwrap_or(0);
                        apply_filter(&mut filter, self.range_bits(mi, lo, hi), neg);
                        filt.push(format!("{}{m}:{text}", if neg { "-" } else { "" }));
                    }
                    None => notes.push(format!("bad filter {m}:{text} ignored")),
                },
                Some(f) => {
                    let mask = match f {
                        "name" => 1,
                        "desc" | "description" => 2,
                        "tag" | "tags" => 4,
                        _ => 8 | 16,
                    };
                    if mask == 1 && !neg {
                        raw_name_parts.push(text.clone());
                    }
                    match val {
                        Val::Word(w) => word_terms(&w, occur, mask, &mut terms),
                        Val::Phrase(p) | Val::Re(p, _) if p.trim().is_empty() => {}
                        Val::Phrase(p) => {
                            self.add_pat(&p, None, occur, mask, &mut pats, &mut terms, &mut notes)
                        }
                        Val::Re(p, ci) => self.add_pat(
                            &p,
                            Some(ci),
                            occur,
                            mask,
                            &mut pats,
                            &mut terms,
                            &mut notes,
                        ),
                    }
                }
                None => match val {
                    Val::Word(w) => {
                        if !neg && !w.ends_with('*') && !w.contains('~') {
                            raw_name_parts.push(w.clone());
                        }
                        word_terms(&w, occur, ALLF, &mut terms);
                    }
                    Val::Phrase(p) | Val::Re(p, _) if p.trim().is_empty() => {}
                    Val::Phrase(p) => {
                        self.add_pat(&p, None, occur, ALLF, &mut pats, &mut terms, &mut notes)
                    }
                    Val::Re(p, ci) => self.add_pat(
                        &p,
                        Some(ci),
                        occur,
                        ALLF,
                        &mut pats,
                        &mut terms,
                        &mut notes,
                    ),
                },
            }
        }

        let exps: Vec<Vec<(u32, f32)>> = terms.iter().map(|t| self.expand(t)).collect();
        for (t, e) in terms
            .iter()
            .zip(&exps)
            .filter(|(t, _)| t.occur != Occur::Should)
        {
            apply_filter(&mut filter, self.term_bits(e, t.mask), t.occur == Occur::Not);
        }
        for p in &pats {
            let cand = self.eval(&p.tq, filter.as_ref());
            let (mut hit, mut checked) = (Bits::new(n, false), 0usize);
            let mut check = |d: u32| {
                checked += 1;
                if self.pat_match(p, d) {
                    hit.set(d);
                }
            };
            match (&cand, &filter) {
                (Some(l), Some(f)) => l.iter().copied().filter(|&d| f.get(d)).for_each(&mut check),
                (Some(l), None) => l.iter().copied().for_each(&mut check),
                (None, Some(f)) => f.iter().for_each(&mut check),
                (None, None) => (0..n as u32).for_each(&mut check),
            }
            let how = cand
                .as_ref()
                .map_or(format!("full scan, {checked} verified"), |l| {
                    format!("trigram prefilter {} cand, {checked} verified", l.len())
                });
            notes.push(format!(
                "{}{} [{how}]",
                if p.occur == Occur::Not { "-" } else { "" },
                p.label
            ));
            if p.occur == Occur::Not {
                apply_filter(&mut filter, hit, true);
            } else {
                filter = Some(hit);
            }
        }

        let clauses: Vec<(u8, &[(u32, f32)])> = terms
            .iter()
            .zip(&exps)
            .filter(|(t, _)| t.occur != Occur::Not)
            .map(|(t, e)| (t.mask, e.as_slice()))
            .collect();
        let has_must = terms.iter().any(|t| t.occur == Occur::Must)
            || pats.iter().any(|p| p.occur == Occur::Must);
        let empty = query.trim().is_empty();
        let (skey, desc) = sort.unwrap_or(if !clauses.is_empty() {
            (SortKey::Score, true)
        } else if empty {
            (SortKey::KindName, false)
        } else {
            (SortKey::Name, false)
        });

        // Exact/normalized name boost docs
        let boost_docs: &[u32] = if !raw_name_parts.is_empty() {
            let key = norm_name_key(&raw_name_parts.join(" "));
            self.norm_names.get(&key).map_or(&[], Vec::as_slice)
        } else {
            &[]
        };

        let mut needles: Vec<&str> = clauses
            .iter()
            .flat_map(|c| c.1.iter().map(|&(id, _)| self.terms[id as usize].as_str()))
            .collect();
        needles.sort_unstable();
        needles.dedup();
        let must_pats: Vec<&PatQ> = pats.iter().filter(|p| p.occur == Occur::Must).collect();

        // Fast-path: single exact ALLF term, no filter, no dedup, score desc, no name boost -> Block-Max top-k.
        if clauses.len() == 1
            && clauses[0].0 == ALLF
            && clauses[0].1.len() == 1
            && filter.is_none()
            && !dedup
            && skey == SortKey::Score
            && desc
            && boost_docs.is_empty()
            && limit > 0
        {
            let (tid, w) = clauses[0].1[0];
            let (ds, qs) = self.combined.postings(tid);
            let total = ds.len();
            let max_s = self.combined.max_score[tid as usize];
            let scale = w * (max_s / 65535.0);
            let (blk_last, blk_max_q) = self.combined.blocks(tid);
            let mut heap = BinaryHeap::with_capacity(limit + 1);
            let mut min_score = 0.0f32;
            for (bi, _) in blk_last.iter().enumerate() {
                let bmax = blk_max_q[bi] as f32 * scale; // kind_prior <= 1.0
                if heap.len() == limit && bmax < min_score {
                    continue;
                }
                let start = bi * BLK_SIZE;
                let end = ((bi + 1) * BLK_SIZE).min(total);
                for (&d, &q) in ds[start..end].iter().zip(&qs[start..end]) {
                    let sc = q as f32 * scale * self.kind_prior[d as usize];
                    let item = (
                        (
                            sc.max(0.0).to_bits() as u64,
                            self.canonical_rank[d as usize],
                            Reverse(self.name_rank[d as usize]),
                        ),
                        d,
                    );
                    if heap.len() < limit {
                        heap.push(Reverse(item));
                        if heap.len() == limit {
                            min_score = f32::from_bits(heap.peek().unwrap().0 .0 .0 as u32);
                        }
                    } else if item.0 > heap.peek().unwrap().0 .0 {
                        heap.pop();
                        heap.push(Reverse(item));
                        min_score = f32::from_bits(heap.peek().unwrap().0 .0 .0 as u32);
                    }
                }
            }
            let mut top: Vec<_> = heap.into_iter().map(|Reverse(x)| x).collect();
            top.sort_unstable_by_key(|a| Reverse(a.0));
            let hits_out: Vec<SearchHit> = top
                .into_iter()
                .map(|(k, d)| {
                    let sc = f32::from_bits(k.0 as u32);
                    let (du, x) = (d as usize, &self.docs[d as usize]);
                    SearchHit {
                        id: x.id.clone(),
                        source: x.source.clone(),
                        kind: x.kind,
                        name: x.name.clone(),
                        description: x.description.clone(),
                        path: x.path.clone(),
                        score: sc,
                        lines: self.cols[0][du],
                        chars: self.cols[1][du],
                        words: self.cols[2][du],
                        snippets: self.snippets(du, &needles, &must_pats),
                        duplicates: 0,
                    }
                })
                .collect();
            let suggestions = self.compute_suggestions(&terms, &exps, &bad_sources, hits_out.len());
            let plan = self.build_plan(
                empty,
                &terms,
                &exps,
                &notes,
                &filt,
                skey,
                desc,
                dedup,
            );
            return SearchResponse {
                hits: hits_out,
                total,
                elapsed_us: t0.elapsed().as_micros() as u64,
                plan,
                suggestions,
            };
        }

        let filter_bounds = filter.as_ref().map(Bits::bounds);

        let (total, top_docs, top_scores): (usize, Vec<(u32, u32)>, Vec<f32>) =
            SCRATCH.with(|cell| {
                let mut sc = cell.borrow_mut();
                sc.prepare(n, self.ngroups);

                if !clauses.is_empty() {
                    self.score_into_scratch(&clauses, filter.as_ref(), filter_bounds, &mut sc);
                    let k = clauses.len() as f32;
                    for idx in 0..sc.touched.len() {
                        let du = sc.touched[idx] as usize;
                        sc.score[du] *= (sc.hits[du] as f32 / k) * self.kind_prior[du];
                    }
                    for &d in boost_docs {
                        let du = d as usize;
                        if sc.stamp[du] == sc.cur_stamp && sc.score[du] > 0.0 {
                            sc.score[du] = sc.score[du] * 1.45 + 2.5;
                        }
                    }
                }

                let doc_score = |sc: &SearchScratch, du: usize| -> f32 {
                    if sc.stamp[du] == sc.cur_stamp {
                        sc.score[du]
                    } else {
                        0.0
                    }
                };
                let key = |sc: &SearchScratch, d: u32| -> (u64, u8, Reverse<u32>) {
                    let du = d as usize;
                    let v = match skey {
                        SortKey::Score => doc_score(sc, du).max(0.0).to_bits() as u64,
                        SortKey::Metric(m) => self.cols[m][du] as u64,
                        SortKey::Name => self.name_rank[du] as u64,
                        SortKey::KindName => {
                            ((self.docs[du].kind as u64) << 32) | self.name_rank[du] as u64
                        }
                    };
                    let canon_tie = if skey == SortKey::Score {
                        self.canonical_rank[du]
                    } else {
                        0
                    };
                    (
                        if desc { v } else { u64::MAX - v },
                        canon_tie,
                        Reverse(self.name_rank[du]),
                    )
                };
                let dedup_key = |sc: &SearchScratch, d: u32| -> (u64, u8, Reverse<u32>) {
                    let du = d as usize;
                    (key(sc, d).0, self.canonical_rank[du], Reverse(self.name_rank[du]))
                };

                // Determine matching docs cleanly:
                // - When !clauses.is_empty() && !has_must: only docs with hits > 0 (i.e. `sc.touched`) can match!
                // - Otherwise: iterate `filter` (or `0..n` when filter is None).
                let use_touched_only = !clauses.is_empty() && !has_must;
                let mut heap = BinaryHeap::with_capacity(limit.min(n).saturating_add(1));
                let total: usize;

                if dedup {
                    let cur_gs = sc.cur_grp_stamp;
                    if use_touched_only {
                        let touched_len = sc.touched.len();
                        for idx in 0..touched_len {
                            let d = sc.touched[idx];
                            let g = self.groups[d as usize] as usize;
                            if sc.grp_stamp[g] != cur_gs {
                                sc.grp_stamp[g] = cur_gs;
                                sc.grp_best[g] = d;
                                sc.grp_cnt[g] = 1;
                                sc.touched_groups.push(g);
                            } else {
                                if dedup_key(&sc, d) > dedup_key(&sc, sc.grp_best[g]) {
                                    sc.grp_best[g] = d;
                                }
                                sc.grp_cnt[g] += 1;
                            }
                        }
                    } else if let Some(f) = filter.as_ref() {
                        for d in f.iter() {
                            let g = self.groups[d as usize] as usize;
                            if sc.grp_stamp[g] != cur_gs {
                                sc.grp_stamp[g] = cur_gs;
                                sc.grp_best[g] = d;
                                sc.grp_cnt[g] = 1;
                                sc.touched_groups.push(g);
                            } else {
                                if dedup_key(&sc, d) > dedup_key(&sc, sc.grp_best[g]) {
                                    sc.grp_best[g] = d;
                                }
                                sc.grp_cnt[g] += 1;
                            }
                        }
                    } else {
                        for d in 0..n as u32 {
                            let g = self.groups[d as usize] as usize;
                            if sc.grp_stamp[g] != cur_gs {
                                sc.grp_stamp[g] = cur_gs;
                                sc.grp_best[g] = d;
                                sc.grp_cnt[g] = 1;
                                sc.touched_groups.push(g);
                            } else {
                                if dedup_key(&sc, d) > dedup_key(&sc, sc.grp_best[g]) {
                                    sc.grp_best[g] = d;
                                }
                                sc.grp_cnt[g] += 1;
                            }
                        }
                    }
                    total = sc.touched_groups.len();
                    if limit > 0 {
                        for &g in &sc.touched_groups {
                            let (d, dups) = (sc.grp_best[g], sc.grp_cnt[g] - 1);
                            let item = (key(&sc, d), d, dups);
                            if heap.len() < limit {
                                heap.push(Reverse(item));
                            } else if heap.peek().is_some_and(|Reverse(w)| item > *w) {
                                heap.pop();
                                heap.push(Reverse(item));
                            }
                        }
                    }
                } else if use_touched_only {
                    total = sc.touched.len();
                    if limit > 0 {
                        for &d in &sc.touched {
                            let item = (key(&sc, d), d, 0u32);
                            if heap.len() < limit {
                                heap.push(Reverse(item));
                            } else if heap.peek().is_some_and(|Reverse(w)| item > *w) {
                                heap.pop();
                                heap.push(Reverse(item));
                            }
                        }
                    }
                } else if let Some(f) = filter.as_ref() {
                    let mut cnt = 0usize;
                    for d in f.iter() {
                        cnt += 1;
                        if limit > 0 {
                            let item = (key(&sc, d), d, 0u32);
                            if heap.len() < limit {
                                heap.push(Reverse(item));
                            } else if heap.peek().is_some_and(|Reverse(w)| item > *w) {
                                heap.pop();
                                heap.push(Reverse(item));
                            }
                        }
                    }
                    total = cnt;
                } else {
                    total = n;
                    if limit > 0 {
                        for d in 0..n as u32 {
                            let item = (key(&sc, d), d, 0u32);
                            if heap.len() < limit {
                                heap.push(Reverse(item));
                            } else if heap.peek().is_some_and(|Reverse(w)| item > *w) {
                                heap.pop();
                                heap.push(Reverse(item));
                            }
                        }
                    }
                }

                let mut top: Vec<_> = heap.into_iter().map(|Reverse(x)| x).collect();
                top.sort_unstable_by(|a, b| b.cmp(a));
                let scores: Vec<f32> = top.iter().map(|&(_, d, _)| doc_score(&sc, d as usize)).collect();
                let docs: Vec<(u32, u32)> = top.into_iter().map(|(_, d, dups)| (d, dups)).collect();
                (total, docs, scores)
            });

        let hits_out: Vec<SearchHit> = top_docs
            .into_iter()
            .zip(top_scores)
            .map(|((d, dups), sc_val)| {
                let (du, x) = (d as usize, &self.docs[d as usize]);
                SearchHit {
                    id: x.id.clone(),
                    source: x.source.clone(),
                    kind: x.kind,
                    name: x.name.clone(),
                    description: x.description.clone(),
                    path: x.path.clone(),
                    score: sc_val,
                    lines: self.cols[0][du],
                    chars: self.cols[1][du],
                    words: self.cols[2][du],
                    snippets: self.snippets(du, &needles, &must_pats),
                    duplicates: dups,
                }
            })
            .collect();

        let suggestions = self.compute_suggestions(&terms, &exps, &bad_sources, hits_out.len());
        let plan = self.build_plan(empty, &terms, &exps, &notes, &filt, skey, desc, dedup);
        SearchResponse {
            hits: hits_out,
            total,
            elapsed_us: t0.elapsed().as_micros() as u64,
            plan,
            suggestions,
        }
    }

    fn compute_suggestions(
        &self,
        terms: &[TermQ],
        exps: &[Vec<(u32, f32)>],
        bad_sources: &[String],
        hits_len: usize,
    ) -> Vec<String> {
        let mut suggestions: Vec<(usize, Reverse<u32>, String)> = Vec::new();
        if hits_len < 3 {
            for (t, exp) in terms.iter().zip(exps) {
                if t.occur != Occur::Not
                    && t.mode == Mode::Exact
                    && (exp.is_empty() || (exp.len() == 1 && self.df[exp[0].0 as usize] <= 1))
                {
                    for (id, dist) in self.fuzzy(&t.text, 2) {
                        let s = &self.terms[id as usize];
                        if *s != t.text && !suggestions.iter().any(|x| x.2 == *s) {
                            suggestions.push((dist, Reverse(self.df[id as usize]), s.clone()));
                        }
                    }
                }
            }
            for bs in bad_sources {
                let m = Myers::new(bs);
                for ks in &self.known_sources {
                    let dist = m.dist(ks);
                    if dist <= 4 && !suggestions.iter().any(|x| x.2 == *ks) {
                        suggestions.push((dist, Reverse(u32::MAX), ks.clone()));
                    }
                }
            }
            suggestions.sort();
            suggestions.truncate(5);
        }
        suggestions.into_iter().map(|x| x.2).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_plan(
        &self,
        empty: bool,
        terms: &[TermQ],
        exps: &[Vec<(u32, f32)>],
        notes: &[String],
        filt: &[String],
        skey: SortKey,
        desc: bool,
        dedup: bool,
    ) -> String {
        let mut plan = Vec::new();
        if empty {
            plan.push("overview: all docs by kind then name".to_string());
        }
        if !terms.is_empty() {
            let ts: Vec<String> = terms
                .iter()
                .zip(exps)
                .map(|(t, e)| {
                    let o = match t.occur {
                        Occur::Should => "",
                        Occur::Must => "+",
                        Occur::Not => "-",
                    };
                    let f = match t.mask {
                        1 => "name:",
                        2 => "desc:",
                        4 => "tag:",
                        24 => "body:",
                        _ => "",
                    };
                    let m = match t.mode {
                        Mode::Exact => String::new(),
                        Mode::Prefix => "*".into(),
                        Mode::Fuzzy(k) => format!("~{k}"),
                    };
                    format!("{o}{f}{}{m}({})", t.text, e.len())
                })
                .collect();
            plan.push(format!("terms[bm25f]: {}", ts.join(" ")));
        }
        plan.extend(notes.iter().cloned());
        if !filt.is_empty() {
            plan.push(format!("filters: {}", filt.join(" ")));
        }
        let sk = match skey {
            SortKey::Score => "score",
            SortKey::Metric(m) => METRICS[m],
            SortKey::Name => "name",
            SortKey::KindName => "kind,name",
        };
        plan.push(format!("sort: {sk} {}", if desc { "desc" } else { "asc" }));
        plan.push(format!("dedup: {}", if dedup { "on" } else { "off" }));
        plan.join("; ")
    }

    #[allow(clippy::too_many_arguments)]
    fn add_pat(
        &self,
        p: &str,
        re: Option<bool>,
        occur: Occur,
        mask: u8,
        pats: &mut Vec<PatQ>,
        terms: &mut Vec<TermQ>,
        notes: &mut Vec<String>,
    ) {
        let occur = if occur == Occur::Not {
            Occur::Not
        } else {
            Occur::Must
        };
        let (mut label, mut literal) = match re {
            Some(ci) => (format!("/{p}/{}", if ci { "i" } else { "" }), false),
            None => (format!("\"{p}\""), true),
        };
        let (rx, tq) = match compile(p, re.unwrap_or(true), literal) {
            Ok(x) => x,
            Err(e) => {
                notes.push(format!(
                    "invalid regex {label} ({e}): treated as literal phrase"
                ));
                (label, literal) = (format!("\"{p}\""), true);
                match compile(p, true, true) {
                    Ok(x) => x,
                    Err(_) => return,
                }
            }
        };
        if literal && occur == Occur::Must {
            tokenize(p, false, &mut |t: &str, _joined: bool| {
                terms.push(TermQ {
                    occur: Occur::Should,
                    text: t.into(),
                    mode: Mode::Exact,
                    mask,
                })
            });
        }
        let ascii_lit = (literal && p.is_ascii()).then(|| p.as_bytes().to_vec());
        pats.push(PatQ {
            occur,
            mask,
            re: rx,
            tq,
            label,
            ascii_lit,
        });
    }

    /// Up to 3 body lines (skipping YAML frontmatter): phrase/regex matches if any, else lines
    /// containing a query term. Falls back to all lines if matches exist only in frontmatter.
    fn snippets(&self, d: usize, needles: &[&str], pats: &[&PatQ]) -> Vec<(u32, String)> {
        let body = &self.docs[d].body;
        let skip = self.body_start[d].1 as usize;
        let pick = |start_line: usize, f: &dyn Fn(&str) -> bool| -> Vec<(u32, String)> {
            body.lines()
                .enumerate()
                .skip(start_line)
                .filter(|(_, l)| !l.trim().is_empty() && f(l))
                .take(3)
                .map(|(i, l)| (i as u32 + 1, clip(l)))
                .collect()
        };
        if !pats.is_empty() {
            let out = pick(skip, &|l| pats.iter().any(|p| p.re.is_match(l)));
            if !out.is_empty() {
                return out;
            }
            if skip > 0 {
                let fb = pick(0, &|l| pats.iter().any(|p| p.re.is_match(l)));
                if !fb.is_empty() {
                    return fb;
                }
            }
        }
        if needles.is_empty() {
            return Vec::new();
        }
        let match_needles = |l: &str| {
            let low = l.to_lowercase();
            needles.iter().any(|n| low.contains(n))
        };
        let out = pick(skip, &match_needles);
        if !out.is_empty() || skip == 0 {
            out
        } else {
            pick(0, &match_needles)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }
    fn mk(
        id: &str,
        source: &str,
        kind: DocKind,
        name: &str,
        desc: &str,
        tags: &[&str],
        body: &str,
    ) -> DocInput {
        DocInput {
            id: id.into(),
            source: source.into(),
            kind,
            name: name.into(),
            description: desc.into(),
            path: format!("/repo/{id}"),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            body: body.into(),
        }
    }
    fn toks(s: &str, joined: bool) -> Vec<String> {
        let mut v = Vec::new();
        tokenize(s, joined, &mut |t: &str, _| v.push(t.to_string()));
        v
    }
    fn names(r: &SearchResponse) -> Vec<String> {
        r.hits.iter().map(|h| h.name.clone()).collect()
    }
    fn words(rng: &mut Rng, n: usize) -> Vec<String> {
        const SYL: [&str; 16] = [
            "ka", "lo", "mi", "te", "st", "ru", "an", "de", "qu", "ix", "ver", "sk", "ill", "ag",
            "ent", "or",
        ];
        (0..n)
            .map(|_| (0..2 + rng.below(3)).map(|_| SYL[rng.below(16)]).collect())
            .collect()
    }
    const SPECIAL: [&str; 22] = [
        "\u{212A}ey",
        "ſtatus",
        "ÉCOLE",
        "école",
        "CamelCase",
        "test-driven",
        "README.md",
        "colour",
        "color",
        "xx",
        "xxx",
        "a1b2",
        "123",
        "4567",
        "Straße",
        "STRASSE",
        "naïve",
        "ΟΔΟΣ",
        "key",
        "Key",
        "KEY",
        "status",
    ];
    fn corpus(
        rng: &mut Rng,
        n: usize,
        vocab: &[String],
        lines: usize,
        per_line: usize,
    ) -> Vec<DocInput> {
        let kinds = DocKind::ALL;
        (0..n)
            .map(|i| {
                let mut body = String::new();
                for _ in 0..lines / 2 + rng.below(lines) {
                    if rng.below(10) < 2 {
                        body.push_str("## ");
                    }
                    for _ in 0..per_line / 2 + rng.below(per_line) {
                        let w = if rng.below(12) == 0 {
                            SPECIAL[rng.below(SPECIAL.len())].to_string()
                        } else {
                            vocab[rng.below(vocab.len())].clone()
                        };
                        let w = match rng.below(10) {
                            0 => w.to_uppercase(),
                            1 => w
                                .chars()
                                .take(1)
                                .flat_map(char::to_uppercase)
                                .chain(w.chars().skip(1))
                                .collect(),
                            _ => w,
                        };
                        body.push_str(&w);
                        body.push(' ');
                    }
                    body.push('\n');
                }
                let name = format!("{}-{i}", vocab[rng.below(vocab.len())]);
                let desc = format!(
                    "{} {}",
                    vocab[rng.below(vocab.len())],
                    vocab[rng.below(vocab.len())]
                );
                let src = format!("src{}", i % 5);
                mk(
                    &format!("{src}:{i}"),
                    &src,
                    kinds[i % 6],
                    &name,
                    &desc,
                    &[],
                    &body,
                )
            })
            .collect()
    }

    #[test]
    fn tokenizer_and_stemmer() {
        assert_eq!(
            toks("Test-Driven Development", true),
            ["test", "driven", "testdriven", "development"]
        );
        assert_eq!(
            toks("Test-Driven Development", false),
            ["test", "driven", "development"]
        );
        assert_eq!(
            toks("parseHTMLDocument", true),
            ["parse", "html", "document", "parsehtmldocument"]
        );
        assert_eq!(
            toks("snake_case_name", true),
            ["snake", "case", "name", "snakecasename"]
        );
        assert_eq!(
            toks(
                "testing tests quickly classes policies added boxes files apply",
                false
            ),
            ["test", "test", "quick", "class", "policy", "add", "box", "file", "apply"]
        );
        assert_eq!(toks("the a x of skill is IT", false), ["skill"]);
        assert_eq!(toks("Über Straße v2", false), ["über", "straße", "v2"]);
        let mut rng = Rng(7);
        for _ in 0..300 {
            let a: String = (0..rng.below(9))
                .map(|_| (b'a' + rng.below(4) as u8) as char)
                .collect();
            let b: String = (0..rng.below(9))
                .map(|_| (b'a' + rng.below(4) as u8) as char)
                .collect();
            let m = Myers::new(&a);
            let (ac, bc): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
            assert_eq!(m.dist(&b), osa_dp(&ac, &bc), "{a} vs {b}");
        }
        let long = "x".repeat(70);
        assert_eq!(Myers::new(&long).dist(&"x".repeat(68)), 2);
        assert_eq!(
            (
                Myers::new("tset").dist("test"),
                Myers::new("kitten").dist("sitting")
            ),
            (1, 3)
        );
    }

    #[test]
    fn bm25f_ranking() {
        let ix = SkillIndex::build(vec![
            mk(
                "a",
                "s",
                DocKind::Skill,
                "deploy helper",
                "",
                &[],
                "nothing here about it",
            ),
            mk(
                "b",
                "s",
                DocKind::Skill,
                "other",
                "",
                &[],
                "this mentions deploy once among many other words here",
            ),
            mk("c", "s", DocKind::Skill, "c", "", &[], "alpha beta gamma"),
            mk("d", "s", DocKind::Skill, "d", "", &[], "alpha alpha words"),
        ]);
        assert_eq!(names(&ix.search("deploy", 10)), ["deploy helper", "other"]);
        let r = ix.search("alpha beta gamma", 10);
        assert_eq!(names(&r), ["c", "d"]);
        assert!(r.hits[0].score > r.hits[1].score * 2.0);
    }

    #[test]
    fn phrase_and_regex_match_brute_force() {
        let mut rng = Rng(0x9e3779b97f4a7c15);
        let vocab = words(&mut rng, 150);
        let docs = corpus(&mut rng, 300, &vocab, 10, 8);
        let ix = SkillIndex::build(docs.clone());
        let brute = |pat: &str, ci: bool| -> BTreeSet<String> {
            let re = RegexBuilder::new(pat)
                .case_insensitive(ci)
                .multi_line(true)
                .build()
                .unwrap();
            docs.iter()
                .filter(|d| {
                    re.is_match(&d.name) || re.is_match(&d.description) || re.is_match(&d.body)
                })
                .map(|d| d.id.clone())
                .collect()
        };
        let engine = |q: &str| -> (BTreeSet<String>, usize, String) {
            let r = ix.search(&format!("{q} dedup:off"), 100_000);
            (
                r.hits.iter().map(|h| h.id.clone()).collect(),
                r.total,
                r.plan,
            )
        };
        let (mut cases, mut prefiltered, mut nonempty) = (0, 0, 0);
        let mut check = |q: String, pat: String, ci: bool| {
            let want = brute(&pat, ci);
            let (got, total, plan) = engine(&q);
            assert_eq!(got, want, "query {q} plan {plan}");
            assert_eq!(total, want.len());
            cases += 1;
            prefiltered += usize::from(plan.contains("prefilter"));
            nonempty += usize::from(!want.is_empty());
        };
        for _ in 0..40 {
            let d = &docs[rng.below(docs.len())];
            let cs: Vec<char> = d.body.chars().collect();
            let start = rng.below(cs.len().saturating_sub(16).max(1));
            let mut p: String = cs[start..(start + 3 + rng.below(12)).min(cs.len())]
                .iter()
                .collect();
            if p.trim().is_empty() || p.contains('\n') {
                p = vocab[rng.below(vocab.len())].clone();
            }
            let p: String = p
                .chars()
                .map(|c| {
                    if rng.below(3) == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            check(format!("\"{p}\""), regex::escape(&p), true);
        }
        for round in 0..3 {
            let (w1, w2) = (&vocab[rng.below(150)], &vocab[rng.below(150)]);
            let ws: Vec<&str> = docs[round * 7].body.split_whitespace().collect();
            let adj = format!("{} {}", ws[0], ws[1]);
            let pats: Vec<(String, bool)> = vec![
                (w1.clone(), false),
                (w1.to_uppercase(), true),
                (format!("{w1}|{w2}"), false),
                (format!("(?:{w1}|{w2})\\s+\\w+"), true),
                (format!("{w1}.*{w2}"), false),
                (format!("{}[a-z]+", &w1[..2]), false),
                (format!("^{w1}"), false),
                (format!("{w1}\\s*$"), true),
                (format!("{w1}(?:{w2})+"), false),
                (format!("[{}]{}", &w1[..1], &w1[1..]), true),
                (regex::escape(&adj), false),
                ("k.y".into(), true),
                ("\\bst".into(), false),
                ("^## ".into(), false),
                ("(?i)KEY".into(), false),
                ("[Kk]ey".into(), false),
                ("ſtat".into(), true),
                ("STATUS".into(), true),
                ("colou?r".into(), false),
                ("x{2,}".into(), false),
                ("\\d{3}".into(), false),
                ("[aeiou]{3}".into(), true),
                ("école|ΟΔΟΣ".into(), true),
                ("STRASSE|straße".into(), true),
            ];
            for (p, ci) in pats {
                check(format!("/{p}/{}", if ci { "i" } else { "" }), p, ci);
            }
        }
        assert!(
            cases >= 100 && prefiltered >= 60 && nonempty >= 60,
            "{cases} {prefiltered} {nonempty}"
        );
        let all: BTreeSet<String> = docs.iter().map(|d| d.id.clone()).collect();
        let w = &vocab[3];
        let inv: BTreeSet<String> = all
            .difference(&brute(&regex::escape(w), true))
            .cloned()
            .collect();
        assert_eq!(engine(&format!("-\"{w}\"")).0, inv);
        assert_eq!(engine(&format!("-/{w}/i")).0, inv);
    }

    fn fixture() -> SkillIndex {
        let review: String = (0..50)
            .map(|i| format!("review line {i} checking code quality\n"))
            .collect();
        let long: String = (0..300).map(|i| format!("summary line {i}\n")).collect();
        SkillIndex::build(vec![
            mk(
                "ecc:skills/tdd/SKILL.md",
                "ecc",
                DocKind::Skill,
                "tdd-workflow",
                "Test driven development workflow",
                &["testing"],
                "# TDD\nWrite tests first.\nRed green refactor.\n",
            ),
            mk(
                "ecc:agents/code-reviewer.md",
                "ecc",
                DocKind::Agent,
                "code-reviewer",
                "Reviews code",
                &[],
                &review,
            ),
            mk(
                "other:skills/tdd.md",
                "other",
                DocKind::Skill,
                "TDD-Workflow",
                "Test driven development workflow",
                &[],
                "# TDD\nAnother take on it.\n",
            ),
            mk(
                "other:commands/deploy.md",
                "other",
                DocKind::Command,
                "deploy",
                "Deploy things",
                &[],
                &review,
            ),
            mk(
                "ecc:rules/python.md",
                "ecc",
                DocKind::Rule,
                "python-style",
                "Python style",
                &[],
                "Use black formatting.\n",
            ),
            mk(
                "x:prompts/sum.md",
                "x",
                DocKind::Prompt,
                "summarize",
                "Summaries",
                &[],
                &long,
            ),
            mk(
                "z:skills/deploy/SKILL.md",
                "z",
                DocKind::Skill,
                "Deploy",
                "Deploy skill",
                &[],
                "deploy skill steps\n",
            ),
        ])
    }

    #[test]
    fn query_features() {
        let ix = fixture();
        let q = |s: &str| ix.search(s, 10);
        assert!(names(&q("tset~")).contains(&"tdd-workflow".to_string()));
        assert!(q("tset~").plan.contains("tset~1"));
        assert_eq!(names(&q("refact*")), ["tdd-workflow"]);
        assert_eq!(names(&q("name:deploy kind:command")), ["deploy"]);
        assert_eq!(names(&q("desc:reviews")), ["code-reviewer"]);
        assert_eq!(names(&q("tag:testing")), ["tdd-workflow"]);
        assert_eq!(names(&q("body:refactor")), ["tdd-workflow"]);
        assert!(q("name:refactor").hits.is_empty());
        assert_eq!(names(&q("kind:agent")), ["code-reviewer"]);
        assert_eq!(
            names(&q("kind:skills,rule source:ecc")),
            ["python-style", "tdd-workflow"]
        );
        assert_eq!(
            names(&q("-kind:skill,agent,command source:ecc,x")),
            ["python-style", "summarize"]
        );
        assert_eq!(
            names(&q("lines:<5 kind:skill dedup:off")),
            ["Deploy", "tdd-workflow", "TDD-Workflow"]
        );
        assert_eq!(
            names(&q("lines:50..300 dedup:off")),
            ["code-reviewer", "deploy", "summarize"]
        );
        assert_eq!(names(&q("lines:>=300")), ["summarize"]);
        assert_eq!(
            names(&q("chars:>1000 words:>200")),
            ["code-reviewer", "summarize"]
        );
        assert_eq!(
            names(&q("tokens:<=10")),
            ["Deploy", "python-style", "TDD-Workflow"]
        );
        assert_eq!(q("sort:-lines").hits[0].name, "summarize");
        assert_eq!(
            names(&q("sort:lines kind:skill,rule,prompt dedup:off"))[0],
            "Deploy"
        );
        assert_eq!(
            names(&q("sort:-name kind:rule,prompt")),
            ["summarize", "python-style"]
        );
        assert_eq!(names(&q("workflow -refactor dedup:off")), ["TDD-Workflow"]);
        assert_eq!(
            names(&q("workflow -/refactor/ dedup:off")),
            ["TDD-Workflow"]
        );
        assert_eq!(names(&q("+deploy -kind:command")), ["Deploy"]);
        assert!(q("+nonexistentword deploy").hits.is_empty());
        let r = q("\"test driven\"");
        assert_eq!((r.total, r.hits[0].duplicates), (1, 1));
        assert_eq!(q("\"test driven\" dedup:off").total, 2);
        assert_eq!(q("kind:agent,command").total, 1);
        assert_eq!(q("kind:agent,command dedup:off").total, 2);
        let all = ix.search("", 100);
        assert_eq!(all.total, 5);
        assert_eq!(all.hits[0].kind, DocKind::Skill);
        assert_eq!(all.hits.last().unwrap().kind, DocKind::Prompt);
        assert!(all.plan.starts_with("overview"));
        assert!(q("refactr").suggestions.contains(&"refactor".to_string()));
        let bad = q("/foo(/");
        assert!(bad.plan.contains("invalid regex"), "{}", bad.plan);
        assert_eq!(
            q("refactor").hits[0].snippets,
            vec![(3, "Red green refactor.".to_string())]
        );
        assert_eq!(
            q("/line 4[0-9] checking/ dedup:off kind:agent").hits[0]
                .snippets
                .len(),
            3
        );
        assert_eq!(q("/^# TDD$/ dedup:off").total, 2);
        assert_eq!(q("testdrivendevelopment dedup:off").total, 0);
        assert_eq!(q("\"line 299\"").hits[0].snippets[0].0, 300);
        assert_eq!(names(&q("path:prompts")), ["summarize"]);
        assert_eq!(q("deploy").hits[0].kind, DocKind::Skill);
        let st = ix.stats();
        assert_eq!(
            (st.docs, st.per_kind["skill"], st.per_source["ecc"]),
            (7, 3, 3)
        );
        assert!(st.approx_bytes > 0 && st.terms > 10 && st.trigrams > 10);
        fn send_sync<T: Send + Sync>() {}
        send_sync::<SkillIndex>();
    }

    #[test]
    fn get_by_id_and_name() {
        let ix = fixture();
        assert_eq!(
            ix.get("ecc:agents/code-reviewer.md").unwrap().name,
            "code-reviewer"
        );
        let d = ix.get("DEPLOY").unwrap();
        assert_eq!((d.kind, d.id), (DocKind::Skill, "z:skills/deploy/SKILL.md"));
        assert_eq!(ix.get("summarize").unwrap().lines, 300);
        assert!(ix.get("nope").is_none());
        assert_eq!((ix.len(), ix.is_empty()), (7, false));
        assert_eq!(DocKind::parse("Agents"), Some(DocKind::Agent));
        assert_eq!(
            serde_json::to_string(&DocKind::Prompt).unwrap(),
            "\"prompt\""
        );
    }

    #[test]
    fn field_scoped_patterns_and_diagnostics() {
        let ix = fixture();
        assert_eq!(names(&ix.search("name:\"tdd-workflow\"", 10)), ["tdd-workflow"]);
        assert!(ix.search("name:\"Red green\"", 10).hits.is_empty());
        assert_eq!(names(&ix.search("desc:\"Reviews code\"", 10)), ["code-reviewer"]);
        assert_eq!(names(&ix.search("tag:\"testing\"", 10)), ["tdd-workflow"]);
        assert_eq!(names(&ix.search("name:/^dep/i kind:skill", 10)), ["Deploy"]);
        assert_eq!(names(&ix.search("path:/agents\\//", 10)), ["code-reviewer"]);

        let bad_k = ix.search("kind:bogus deploy", 10);
        assert!(bad_k.hits.is_empty());
        assert!(bad_k.plan.contains("unknown kind 'bogus'"), "{}", bad_k.plan);

        let bad_s = ix.search("source:ecxx tdd", 10);
        assert!(bad_s.hits.is_empty());
        assert!(bad_s.plan.contains("unknown source 'ecxx'"), "{}", bad_s.plan);
        assert!(bad_s.suggestions.contains(&"ecc".to_string()));
    }

    #[test]
    fn frontmatter_dedup_canonical_ranking_and_snippets() {
        let ix = SkillIndex::build(vec![
            DocInput {
                id: "wshobson:plugins/a/agents/test-automator.md".into(),
                source: "wshobson-agents".into(),
                kind: DocKind::Agent,
                name: "a-test-automator".into(),
                description: "Automates tests".into(),
                path: "/repo/wshobson/plugins/a/agents/test-automator.md".into(),
                tags: vec![],
                body: "---\nname: a-test-automator\ndescription: Automates tests\n---\n# Test Automator\nShared body content for automation.\n".into(),
            },
            DocInput {
                id: "wshobson:plugins/b/agents/test-automator.md".into(),
                source: "wshobson-agents".into(),
                kind: DocKind::Agent,
                name: "b-test-automator".into(),
                description: "Automates tests".into(),
                path: "/repo/wshobson/plugins/b/agents/test-automator.md".into(),
                tags: vec![],
                body: "---\nname: b-test-automator\ndescription: Automates tests\n---\n# Test Automator\nShared body content for automation.\n".into(),
            },
            DocInput {
                id: "ecc:pi/core/skills/tdd-workflow/SKILL.md".into(),
                source: "ecc".into(),
                kind: DocKind::Skill,
                name: "tdd-workflow".into(),
                description: "TDD workflow".into(),
                path: "/repo/ecc/pi/core/skills/tdd-workflow/SKILL.md".into(),
                tags: vec![],
                body: "---\nname: tdd-workflow\n---\n# TDD Workflow\nWrite failing test first.\n".into(),
            },
            DocInput {
                id: "ecc:skills/tdd-workflow/SKILL.md".into(),
                source: "ecc".into(),
                kind: DocKind::Skill,
                name: "tdd-workflow".into(),
                description: "TDD workflow".into(),
                path: "/repo/ecc/skills/tdd-workflow/SKILL.md".into(),
                tags: vec![],
                body: "---\nname: tdd-workflow\n---\n# TDD Workflow\nWrite failing test first.\n".into(),
            },
            DocInput {
                id: "wshobson:tdd-workflows-tdd-orchestrator.md".into(),
                source: "wshobson-agents".into(),
                kind: DocKind::Agent,
                name: "tdd-workflows-tdd-orchestrator".into(),
                description: "Master TDD orchestrator for tdd-workflow".into(),
                path: "/repo/wshobson/plugins/tdd/agents/tdd-orchestrator.md".into(),
                tags: vec![],
                body: "---\nname: tdd-workflows-tdd-orchestrator\n---\n# Orchestrator\ntdd-workflow details.\n".into(),
            },
        ]);

        // Near-identical frontmatter-only differences collapse into 1 dedup group.
        let auto = ix.search("automation", 10);
        assert_eq!(auto.total, 1);
        assert_eq!(auto.hits[0].duplicates, 1);
        // Snippets skip frontmatter lines (L2/L3) while preserving true line numbers.
        assert_eq!(auto.hits[0].snippets[0].0, 6);

        // Exact name match beats longer names, and canonical `skills/` beats `pi/core/skills/`.
        let tdd = ix.search("tdd-workflow", 10);
        assert_eq!(tdd.hits[0].id, "ecc:skills/tdd-workflow/SKILL.md");
        assert_eq!(tdd.hits[0].duplicates, 1);

        // Noisy suggestions suppressed when terms are in-vocab.
        let zero_in_vocab = ix.search("\"nonexistent phrase\" automation", 10);
        assert!(zero_in_vocab.hits.is_empty());
        assert!(zero_in_vocab.suggestions.is_empty());
    }

    #[test]
    fn fuzzy_mask_pruning_matches_brute_force() {
        let mut rng = Rng(12345);
        let mut vocab = words(&mut rng, 400);
        vocab.extend(["über", "straße", "naïve", "tdd", "workflow"].map(str::to_string));
        let docs: Vec<DocInput> = vocab
            .iter()
            .enumerate()
            .map(|(i, w)| mk(&format!("d:{i}"), "s", DocKind::Skill, w, w, &[], w))
            .collect();
        let ix = SkillIndex::build(docs);
        for k in [1usize, 2] {
            for q in ["tset", "wrokflw", "ubër", "strafe", "kalomit", "skil", "xyz"] {
                let got: BTreeSet<u32> = ix.fuzzy(q, k).into_iter().map(|(id, _)| id).collect();
                let m = Myers::new(q);
                let want: BTreeSet<u32> = ix
                    .terms
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| m.dist(t) <= k)
                    .map(|(id, _)| id as u32)
                    .collect();
                assert_eq!(got, want, "fuzzy({q}, {k}) mismatch");
            }
        }
    }

    #[test]
    fn perf_smoke() {
        let mut rng = Rng(42);
        const L: &[u8] = b"etaoinshrdlucmfwypvbgkqjxz";
        let vocab: Vec<String> = (0..3000)
            .map(|_| {
                (0..3 + rng.below(8))
                    .map(|_| {
                        let k = rng.below(26) + 1;
                        L[rng.below(k)] as char
                    })
                    .collect()
            })
            .collect();
        let docs = corpus(&mut rng, 10_000, &vocab, 24, 12);
        let mb = docs.iter().map(|d| d.body.len()).sum::<usize>() as f64 / 1e6;
        let t = Instant::now();
        let ix = SkillIndex::build(docs);
        let st = ix.stats();
        println!(
            "build: {} docs {mb:.1} MB in {:?}; terms {} trigrams {} approx {} MB",
            st.docs,
            t.elapsed(),
            st.terms,
            st.trigrams,
            st.approx_bytes / 1_000_000
        );
        let mut qs = Vec::new();
        for i in 0..200 {
            let w = |r: &mut Rng| vocab[r.below(vocab.len())].clone();
            let (a, b, c) = (w(&mut rng), w(&mut rng), w(&mut rng));
            qs.push(match i % 10 {
                0 => a,
                1 => format!("{a} {b}"),
                2 => format!("{a} {b} {c}"),
                3 => format!("\"{a} {b}\""),
                4 => format!("/{a}.*{b}/"),
                5 => format!("{}*", &a[..3.min(a.len())]),
                6 => format!("{}~", a.chars().rev().collect::<String>()),
                7 => format!("kind:skill {a} lines:>20 sort:-lines"),
                8 => format!("name:{a} +{b} -{c}"),
                _ => format!("/(?i){a}|{b}/ source:src1"),
            });
        }
        let t = Instant::now();
        let mut total = 0;
        for q in &qs {
            total += ix.search(q, 10).total;
        }
        let avg = t.elapsed().as_secs_f64() * 1000.0 / qs.len() as f64;
        println!("queries: {} avg {avg:.3} ms (total hits {total})", qs.len());
        assert!(avg < 50.0, "avg {avg} ms");
    }
}
