"""Formulation 3: Pure Boolean Lexer, Recursive-Descent AST Parser & Truth-Table Evaluator."""

from __future__ import annotations

import itertools
import re
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeVar
from urllib.parse import unquote, urlparse

from core.exceptions import QueryParseError

Bit = Literal[0, 1]
T = TypeVar("T")


# ---------------------------------------------------------------------------
# Document Representation
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class DocumentView:
    """Immutable candidate document D = (Title, URL, Snippet) for Boolean evaluation."""

    title: str
    url: str
    snippet: str = ""

    @property
    def title_norm(self) -> str:
        return " ".join(self.title.lower().split())

    @property
    def snippet_norm(self) -> str:
        return " ".join(self.snippet.lower().split())

    @property
    def url_lower(self) -> str:
        return self.url.lower()

    @property
    def url_unquoted_lower(self) -> str:
        return unquote(self.url).lower()

    @property
    def host_lower(self) -> str:
        parsed = urlparse(self.url)
        return (parsed.hostname or "").lower().strip(".")

    @property
    def path_lower(self) -> str:
        parsed = urlparse(self.url)
        return (parsed.path or "").lower()

    @property
    def combined_norm(self) -> str:
        return f"{self.title_norm} {self.snippet_norm} {self.url_lower} {self.url_unquoted_lower}"

    @classmethod
    def from_obj(cls, obj: Any) -> "DocumentView":
        if isinstance(obj, cls):
            return obj
        return cls(
            title=str(getattr(obj, "title", "")),
            url=str(getattr(obj, "url", "")),
            snippet=str(getattr(obj, "snippet", "")),
        )


def _domain_matches(host: str, constraint: str) -> bool:
    """
    Deterministic host/domain matcher supporting exact hosts and wildcard TLD/subdomain
    scopes (e.g. `site:*.org` matches `example.org` and `sub.example.org`).
    """
    clean_host = host.lower().strip(".")
    clean_constraint = constraint.lower().strip()
    if not clean_host or not clean_constraint:
        return False

    # Strip optional scheme if user wrote site:https://example.com
    if "://" in clean_constraint:
        parsed_c = urlparse(clean_constraint)
        clean_constraint = (parsed_c.hostname or "").lower().strip(".")

    # Strip optional wildcard prefix `*.`
    if clean_constraint.startswith("*."):
        suffix = clean_constraint[2:].strip(".")
        if not suffix:
            return False
        return clean_host == suffix or clean_host.endswith(f".{suffix}")

    clean_constraint = clean_constraint.strip(".")
    return clean_host == clean_constraint or clean_host.endswith(f".{clean_constraint}")


# ---------------------------------------------------------------------------
# Boolean AST Nodes (Deterministic B = {0, 1} Algebra)
# ---------------------------------------------------------------------------
class ASTNode(ABC):
    """Abstract node in the deterministic Boolean expression tree."""

    @abstractmethod
    def evaluate(self, doc: DocumentView) -> Bit:
        """Evaluate this AST subtree against candidate document D -> {0, 1}."""

    @abstractmethod
    def eval_with_assignment(self, assignment: dict[str, Bit]) -> Bit:
        """Evaluate this AST subtree under an explicit Boolean truth assignment."""

    @abstractmethod
    def collect_atoms(self, out: list["PredicateNode"]) -> None:
        """Collect leaf predicates in deterministic left-to-right order."""

    @abstractmethod
    def render(self, *, backend: str = "google") -> str:
        """Render non-destructively to a search engine query string (zero quote stripping)."""


class PredicateNode(ASTNode, ABC):
    """Atomic Boolean predicate T ∈ {ExactPhrase, InURL, Site, InTitle, FileType, InText, Term}."""

    @property
    @abstractmethod
    def atom_key(self) -> str:
        """Unique canonical label for truth-table column identification."""

    def eval_with_assignment(self, assignment: dict[str, Bit]) -> Bit:
        return 1 if assignment[self.atom_key] else 0

    def collect_atoms(self, out: list["PredicateNode"]) -> None:
        out.append(self)


@dataclass(frozen=True, slots=True)
class ExactPhraseNode(PredicateNode):
    """ExactPhrase(s): deterministic case-insensitive exact substring match."""

    value: str

    @property
    def atom_key(self) -> str:
        return f'ExactPhrase("{self.value}")'

    def evaluate(self, doc: DocumentView) -> Bit:
        needle = " ".join(self.value.lower().split())
        if not needle:
            return 0
        return 1 if needle in doc.combined_norm else 0

    def render(self, *, backend: str = "google") -> str:
        return f'"{self.value}"'


@dataclass(frozen=True, slots=True)
class InURLNode(PredicateNode):
    """InURL(s): deterministic substring match strictly against document URL."""

    value: str
    quoted: bool = False

    @property
    def atom_key(self) -> str:
        return f"InURL({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        needle = self.value.lower().strip()
        if not needle:
            return 0
        return 1 if (needle in doc.url_lower or needle in doc.url_unquoted_lower) else 0

    def render(self, *, backend: str = "google") -> str:
        val = f'"{self.value}"' if (self.quoted or " " in self.value) else self.value
        return f"inurl:{val}"


@dataclass(frozen=True, slots=True)
class SiteNode(PredicateNode):
    """Site(s): deterministic domain/path constraint strictly against URL host (+ optional path)."""

    value: str

    @property
    def atom_key(self) -> str:
        return f"Site({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        raw = self.value.strip().lower()
        if not raw:
            return 0
        if "://" in raw:
            parsed = urlparse(raw)
            host_part = (parsed.hostname or "").lower()
            path_part = (parsed.path or "").rstrip("/")
        elif "/" in raw:
            host_part, rest = raw.split("/", 1)
            path_part = "/" + rest.rstrip("/")
        else:
            host_part = raw
            path_part = ""

        if not _domain_matches(doc.host_lower, host_part):
            return 0
        if path_part and not doc.path_lower.startswith(path_part):
            return 0
        return 1

    def render(self, *, backend: str = "google") -> str:
        target_val = self.value
        if backend.lower() in ("duckduckgo", "ddg", "yahoo", "bing", "brave", "searxng"):
            if target_val.startswith("*."):
                target_val = target_val[2:]
        return f"site:{target_val}"


@dataclass(frozen=True, slots=True)
class InTitleNode(PredicateNode):
    """InTitle(s): deterministic substring match strictly against document Title."""

    value: str
    quoted: bool = False

    @property
    def atom_key(self) -> str:
        return f"InTitle({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        needle = " ".join(self.value.lower().split())
        if not needle:
            return 0
        return 1 if needle in doc.title_norm else 0

    def render(self, *, backend: str = "google") -> str:
        val = f'"{self.value}"' if (self.quoted or " " in self.value) else self.value
        return f"intitle:{val}"


@dataclass(frozen=True, slots=True)
class FileTypeNode(PredicateNode):
    """FileType(s): deterministic URL path extension match."""

    value: str

    @property
    def atom_key(self) -> str:
        return f"FileType({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        ext = "." + self.value.lower().lstrip(".")
        if ext == ".":
            return 0
        path = doc.path_lower
        return 1 if (path.endswith(ext) or f"{ext}/" in path) else 0

    def render(self, *, backend: str = "google") -> str:
        return f"filetype:{self.value}"


@dataclass(frozen=True, slots=True)
class InTextNode(PredicateNode):
    """InText(s): deterministic substring match against Title + Snippet."""

    value: str
    quoted: bool = False

    @property
    def atom_key(self) -> str:
        return f"InText({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        needle = " ".join(self.value.lower().split())
        if not needle:
            return 0
        body = f"{doc.title_norm} {doc.snippet_norm}"
        return 1 if needle in body else 0

    def render(self, *, backend: str = "google") -> str:
        b = backend.lower()
        val = f'"{self.value}"' if (self.quoted or " " in self.value) else self.value
        if b in ("bing", "brave"):
            return f"inbody:{val}"
        if b in ("duckduckgo", "ddg", "yahoo", "searxng"):
            return f'"{self.value}"'
        return f"intext:{val}"


@dataclass(frozen=True, slots=True)
class TermNode(PredicateNode):
    """Term(s): deterministic case-insensitive substring/term match across (Title, URL, Snippet)."""

    value: str
    raw_operator: str | None = None

    @property
    def atom_key(self) -> str:
        if self.raw_operator:
            return f"Term({self.raw_operator}:{self.value})"
        return f"Term({self.value})"

    def evaluate(self, doc: DocumentView) -> Bit:
        needle = " ".join(self.value.lower().split())
        if not needle:
            return 0
        return 1 if needle in doc.combined_norm else 0

    def render(self, *, backend: str = "google") -> str:
        if self.raw_operator:
            val = f'"{self.value}"' if " " in self.value else self.value
            return f"{self.raw_operator}:{val}"
        return self.value


@dataclass(frozen=True, slots=True)
class AndNode(ASTNode):
    """Conjunction: Eval(T1 ∧ T2, D) = Eval(T1, D) * Eval(T2, D)."""

    left: ASTNode
    right: ASTNode

    def evaluate(self, doc: DocumentView) -> Bit:
        lhs = self.left.evaluate(doc)
        rhs = self.right.evaluate(doc)
        return 1 if (lhs * rhs) == 1 else 0

    def eval_with_assignment(self, assignment: dict[str, Bit]) -> Bit:
        lhs = self.left.eval_with_assignment(assignment)
        rhs = self.right.eval_with_assignment(assignment)
        return 1 if (lhs * rhs) == 1 else 0

    def collect_atoms(self, out: list[PredicateNode]) -> None:
        self.left.collect_atoms(out)
        self.right.collect_atoms(out)

    def render(self, *, backend: str = "google") -> str:
        return f"{self.left.render(backend=backend)} {self.right.render(backend=backend)}"


@dataclass(frozen=True, slots=True)
class OrNode(ASTNode):
    """Disjunction: Eval(T1 ∨ T2, D) = max(Eval(T1, D), Eval(T2, D))."""

    left: ASTNode
    right: ASTNode

    def evaluate(self, doc: DocumentView) -> Bit:
        lhs = self.left.evaluate(doc)
        rhs = self.right.evaluate(doc)
        return 1 if max(lhs, rhs) == 1 else 0

    def eval_with_assignment(self, assignment: dict[str, Bit]) -> Bit:
        lhs = self.left.eval_with_assignment(assignment)
        rhs = self.right.eval_with_assignment(assignment)
        return 1 if max(lhs, rhs) == 1 else 0

    def collect_atoms(self, out: list[PredicateNode]) -> None:
        self.left.collect_atoms(out)
        self.right.collect_atoms(out)

    def render(self, *, backend: str = "google") -> str:
        l_str = self.left.render(backend=backend)
        r_str = self.right.render(backend=backend)
        if backend.lower() == "yahoo":
            return f"{l_str} OR {r_str}"
        return f"({l_str} OR {r_str})"


@dataclass(frozen=True, slots=True)
class NotNode(ASTNode):
    """Negation: Eval(¬T1, D) = 1 - Eval(T1, D)."""

    operand: ASTNode

    def evaluate(self, doc: DocumentView) -> Bit:
        val = self.operand.evaluate(doc)
        return 1 if (1 - val) == 1 else 0

    def eval_with_assignment(self, assignment: dict[str, Bit]) -> Bit:
        val = self.operand.eval_with_assignment(assignment)
        return 1 if (1 - val) == 1 else 0

    def collect_atoms(self, out: list[PredicateNode]) -> None:
        self.operand.collect_atoms(out)

    def render(self, *, backend: str = "google") -> str:
        inner = self.operand.render(backend=backend)
        if isinstance(self.operand, PredicateNode):
            return f"-{inner}"
        return f"-({inner})"


# ---------------------------------------------------------------------------
# Pure Lexer & Recursive-Descent Boolean Parser
# ---------------------------------------------------------------------------
_LEXER_RE = re.compile(
    r"""
    (?P<neg_qual>-[A-Za-z][A-Za-z0-9_.-]*:(?:"[^"]*"|[^\s()]+))
    | (?P<pos_qual>[A-Za-z][A-Za-z0-9_.-]*:(?:"[^"]*"|[^\s()]+))
    | (?P<neg_phrase>-"[^"]*")
    | (?P<phrase>"[^"]*")
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<pipe>\|)
    | (?P<neg_word>-[^\s()]+)
    | (?P<word>[^\s()|]+)
    """,
    re.VERBOSE,
)

_OPERATOR_ALIASES: dict[str, str] = {
    "site": "site",
    "domain": "site",
    "host": "site",
    "hostname": "site",
    "inurl": "inurl",
    "allinurl": "inurl",
    "url": "inurl",
    "intitle": "intitle",
    "allintitle": "intitle",
    "title": "intitle",
    "http.title": "intitle",
    "services.http.response.html_title": "intitle",
    "filetype": "filetype",
    "ext": "filetype",
    "intext": "intext",
    "allintext": "intext",
    "inbody": "intext",
    "body": "intext",
    "http.html": "intext",
    "services.http.response.html_body": "intext",
}


@dataclass(frozen=True, slots=True)
class _LexToken:
    kind: Literal[
        "LPAREN",
        "RPAREN",
        "AND",
        "OR",
        "NOT",
        "PREDICATE",
        "NEG_PREDICATE",
    ]
    raw: str
    node: PredicateNode | None = None


def _build_qualifier_node(raw_op: str, raw_val: str) -> PredicateNode:
    op_lower = raw_op.lower()
    is_quoted = len(raw_val) >= 2 and raw_val.startswith('"') and raw_val.endswith('"')
    clean_val = raw_val[1:-1].strip() if is_quoted else raw_val.strip()
    if not clean_val:
        raise QueryParseError(f"Qualifier '{raw_op}:' cannot have an empty value.")

    canonical = _OPERATOR_ALIASES.get(op_lower)
    if canonical == "site":
        return SiteNode(value=clean_val)
    if canonical == "inurl":
        return InURLNode(value=clean_val, quoted=is_quoted)
    if canonical == "intitle":
        return InTitleNode(value=clean_val, quoted=is_quoted)
    if canonical == "filetype":
        return FileTypeNode(value=clean_val)
    if canonical == "intext":
        return InTextNode(value=clean_val, quoted=is_quoted)
    return TermNode(value=clean_val, raw_operator=op_lower)


def tokenize_boolean_query(raw_query: str) -> list[_LexToken]:
    """Tokenize a Boolean search query with strict quote and parenthesis validation."""
    if not raw_query or not raw_query.strip():
        raise QueryParseError("Query string cannot be empty.")

    normalized = " ".join(raw_query.strip().split())
    if normalized.count('"') % 2 != 0:
        raise QueryParseError(f"Unbalanced double quotation marks in query: {raw_query!r}")

    # Verify balanced parentheses outside quotes
    depth = 0
    in_quotes = False
    for ch in normalized:
        if ch == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    raise QueryParseError(f"Unmatched closing parenthesis in query: {raw_query!r}")
    if depth != 0:
        raise QueryParseError(f"Unclosed opening parenthesis in query: {raw_query!r}")

    raw_matches = list(_LEXER_RE.finditer(normalized))
    tokens: list[_LexToken] = []

    for idx, match in enumerate(raw_matches):
        kind = match.lastgroup
        raw_tok = match.group(0)

        if kind == "lparen":
            tokens.append(_LexToken(kind="LPAREN", raw=raw_tok))
        elif kind == "rparen":
            tokens.append(_LexToken(kind="RPAREN", raw=raw_tok))
        elif kind == "pipe":
            tokens.append(_LexToken(kind="OR", raw=raw_tok))
        elif kind in ("pos_qual", "neg_qual"):
            negated = kind == "neg_qual"
            body = raw_tok[1:] if negated else raw_tok
            op_part, val_part = body.split(":", 1)
            pred = _build_qualifier_node(op_part, val_part)
            tokens.append(
                _LexToken(
                    kind="NEG_PREDICATE" if negated else "PREDICATE",
                    raw=raw_tok,
                    node=pred,
                )
            )
        elif kind == "phrase":
            inner = raw_tok[1:-1].strip()
            if not inner:
                raise QueryParseError("Query contains an empty quoted phrase '\"\"'.")
            tokens.append(
                _LexToken(kind="PREDICATE", raw=raw_tok, node=ExactPhraseNode(value=inner))
            )
        elif kind == "neg_phrase":
            inner = raw_tok[2:-1].strip()
            if not inner:
                raise QueryParseError("Query contains an empty negated phrase '-\"\"'.")
            tokens.append(
                _LexToken(
                    kind="NEG_PREDICATE", raw=raw_tok, node=ExactPhraseNode(value=inner)
                )
            )
        elif kind == "neg_word":
            inner = raw_tok[1:].strip()
            if not inner:
                raise QueryParseError(f"Dangling negation operator '-' in query: {raw_query!r}")
            if inner.endswith(":") and inner[:-1].lower() in _OPERATOR_ALIASES:
                raise QueryParseError(f"Qualifier '{raw_tok}' cannot have an empty value.")
            tokens.append(
                _LexToken(kind="NEG_PREDICATE", raw=raw_tok, node=TermNode(value=inner))
            )
        else:
            if raw_tok.endswith(":") and raw_tok[:-1].lower() in _OPERATOR_ALIASES:
                raise QueryParseError(f"Qualifier '{raw_tok}' cannot have an empty value.")
            # Boolean keywords: uppercase AND / OR / NOT, plus lowercase `and`/`or`
            # when explicitly connecting two field qualifiers (e.g., Censys syntax).
            prev_is_qual = idx > 0 and raw_matches[idx - 1].lastgroup in ("pos_qual", "neg_qual")
            next_is_qual = (
                idx + 1 < len(raw_matches)
                and raw_matches[idx + 1].lastgroup in ("pos_qual", "neg_qual")
            )
            if raw_tok == "AND" or (raw_tok == "and" and prev_is_qual and next_is_qual):
                tokens.append(_LexToken(kind="AND", raw=raw_tok))
            elif raw_tok == "OR" or (raw_tok == "or" and prev_is_qual and next_is_qual):
                tokens.append(_LexToken(kind="OR", raw=raw_tok))
            elif raw_tok == "NOT":
                tokens.append(_LexToken(kind="NOT", raw=raw_tok))
            else:
                tokens.append(
                    _LexToken(kind="PREDICATE", raw=raw_tok, node=TermNode(value=raw_tok))
                )

    if not tokens:
        raise QueryParseError(f"Query produced zero valid tokens: {raw_query!r}")
    return tokens


@dataclass(frozen=True, slots=True)
class CompiledBooleanAST:
    """Compiled deterministic Boolean query AST over B = {0, 1}."""

    raw_query: str
    normalized_query: str
    root: ASTNode

    def evaluate(self, doc: Any) -> Bit:
        """
        Evaluate Eval(Q_AST, D) ∈ {0, 1}.
        Strictness guarantee: if result == 0, candidate document MUST be dropped.
        """
        view = DocumentView.from_obj(doc)
        return self.root.evaluate(view)

    def matches(self, doc: Any) -> bool:
        return self.evaluate(doc) == 1

    def filter_documents(self, docs: Sequence[T]) -> tuple[list[T], int]:
        """Drop every candidate where Eval(Q_AST, D) == 0. Returns (admitted, dropped_count)."""
        admitted: list[T] = []
        dropped = 0
        for doc in docs:
            if self.evaluate(doc) == 1:
                admitted.append(doc)
            else:
                dropped += 1
        return admitted, dropped

    def atoms(self) -> list[PredicateNode]:
        """Return unique atomic predicates in deterministic left-to-right order."""
        raw_atoms: list[PredicateNode] = []
        self.root.collect_atoms(raw_atoms)
        seen: set[str] = set()
        unique: list[PredicateNode] = []
        for atom in raw_atoms:
            key = atom.atom_key
            if key not in seen:
                seen.add(key)
                unique.append(atom)
        return unique

    def truth_table(
        self, max_atoms: int = 10
    ) -> list[tuple[dict[str, Bit], Bit]]:
        """
        Materialize the exact 2^k Boolean truth table over unique atomic predicates.
        Raises ValueError if k > max_atoms to prevent combinatorial explosion.
        """
        atom_keys = [a.atom_key for a in self.atoms()]
        if len(atom_keys) > max_atoms:
            raise ValueError(
                f"Truth table exceeds max_atoms={max_atoms} (got {len(atom_keys)} atoms)."
            )
        rows: list[tuple[dict[str, Bit], Bit]] = []
        for bits in itertools.product((0, 1), repeat=len(atom_keys)):
            assignment: dict[str, Bit] = {
                key: (1 if bit else 0) for key, bit in zip(atom_keys, bits, strict=True)
            }
            outcome = self.root.eval_with_assignment(assignment)
            rows.append((assignment, outcome))
        return rows

    def translate_for_backend(self, backend: str = "google") -> str:
        """
        Non-destructive backend dialect translation.
        Never strips quotation marks or deletes mandatory predicates.
        """
        return " ".join(self.root.render(backend=backend).split())


class BooleanASTParser:
    """
    Recursive-descent Boolean query parser implementing exact precedence:
        NOT / unary '-'  >  explicit or implicit AND  >  OR / '|'
    with arbitrary parenthesized grouping.
    """

    def __init__(self) -> None:
        self._tokens: list[_LexToken] = []
        self._pos: int = 0

    def parse(self, raw_query: str) -> CompiledBooleanAST:
        tokens = tokenize_boolean_query(raw_query)
        self._tokens = tokens
        self._pos = 0
        root = self._parse_or()
        if self._pos < len(self._tokens):
            raise QueryParseError(
                f"Unexpected trailing token {self._tokens[self._pos].raw!r} in query {raw_query!r}"
            )
        normalized = " ".join(raw_query.strip().split())
        return CompiledBooleanAST(
            raw_query=raw_query,
            normalized_query=normalized,
            root=root,
        )

    def _peek(self) -> _LexToken | None:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _consume(self) -> _LexToken:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _parse_or(self) -> ASTNode:
        node = self._parse_and()
        while (tok := self._peek()) is not None and tok.kind == "OR":
            self._consume()
            rhs = self._parse_and()
            node = OrNode(left=node, right=rhs)
        return node

    def _parse_and(self) -> ASTNode:
        node = self._parse_unary()
        while (tok := self._peek()) is not None:
            if tok.kind == "AND":
                self._consume()
                rhs = self._parse_unary()
                node = AndNode(left=node, right=rhs)
            elif tok.kind in ("PREDICATE", "NEG_PREDICATE", "NOT", "LPAREN"):
                # Implicit conjunction between adjacent terms/clauses
                rhs = self._parse_unary()
                node = AndNode(left=node, right=rhs)
            else:
                break
        return node

    def _parse_unary(self) -> ASTNode:
        tok = self._peek()
        if tok is None:
            raise QueryParseError("Unexpected end of Boolean expression.")
        if tok.kind == "NOT":
            self._consume()
            return NotNode(operand=self._parse_unary())
        if tok.kind == "NEG_PREDICATE":
            self._consume()
            assert tok.node is not None
            return NotNode(operand=tok.node)
        return self._parse_primary()

    def _parse_primary(self) -> ASTNode:
        tok = self._peek()
        if tok is None:
            raise QueryParseError("Unexpected end of Boolean expression; expected predicate.")
        if tok.kind == "LPAREN":
            self._consume()
            inner = self._parse_or()
            closing = self._peek()
            if closing is None or closing.kind != "RPAREN":
                raise QueryParseError("Expected closing parenthesis ')'.")
            self._consume()
            return inner
        if tok.kind == "PREDICATE":
            self._consume()
            assert tok.node is not None
            return tok.node
        raise QueryParseError(f"Unexpected operator token {tok.raw!r} where predicate expected.")


def compile_boolean_query(query: str) -> CompiledBooleanAST:
    """Convenience function compiling a query string into a deterministic Boolean AST."""
    return BooleanASTParser().parse(query)
