"""Deterministic Boolean AST truth-table verification & strict `--no-relax` dork tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from core.exceptions import QueryParseError
from core.models import SearchResult
from engine.orchestrator import strip_query_line
from math_kernel.ast_boolean import DocumentView, compile_boolean_query


class TestBooleanASTTruthTables(unittest.TestCase):
    """Formulation 3: Deterministic Boolean algebra B = {0, 1} truth-table proofs."""

    def test_exact_conjunction_disjunction_negation_truth_tables(self) -> None:
        # AND: Eval(A ∧ B) = Eval(A) * Eval(B)
        ast_and = compile_boolean_query("alpha AND beta")
        table_and = ast_and.truth_table()
        self.assertEqual(len(table_and), 4)
        for assign, out in table_and:
            a, b = assign["Term(alpha)"], assign["Term(beta)"]
            self.assertEqual(out, a * b)

        # OR: Eval(A ∨ B) = max(Eval(A), Eval(B))
        ast_or = compile_boolean_query("alpha OR beta")
        for assign, out in ast_or.truth_table():
            a, b = assign["Term(alpha)"], assign["Term(beta)"]
            self.assertEqual(out, max(a, b))

        # NOT: Eval(¬A) = 1 - Eval(A)
        ast_not = compile_boolean_query("NOT alpha")
        for assign, out in ast_not.truth_table():
            a = assign["Term(alpha)"]
            self.assertEqual(out, 1 - a)

    def test_de_morgan_equivalence_and_operator_precedence(self) -> None:
        """Verify ¬(A ∧ B) ≡ (¬A ∨ ¬B) and NOT > AND > OR precedence over all 2^3 assignments."""
        lhs_ast = compile_boolean_query("NOT (alpha AND beta)")
        rhs_ast = compile_boolean_query("(NOT alpha) OR (NOT beta)")
        self.assertEqual(lhs_ast.truth_table(), rhs_ast.truth_table())

        # Precedence: `a OR b AND NOT c` == `a OR (b AND (NOT c))`
        prec_ast = compile_boolean_query("alpha OR beta AND NOT gamma")
        for assign, out in prec_ast.truth_table():
            a, b, c = assign["Term(alpha)"], assign["Term(beta)"], assign["Term(gamma)"]
            expected = max(a, b * (1 - c))
            self.assertEqual(out, expected)


class TestStrictDorkPreservation(unittest.TestCase):
    """Verify `--no-relax` AST gate rejects 100% of non-matching candidates."""

    def test_inurl_and_exact_phrase_zero_false_positives(self) -> None:
        ast = compile_boolean_query('inurl:donate "braintreepayments.com"')

        exact_match = SearchResult(
            rank=1,
            title="Support Our Charity",
            url="https://nonprofit.org/donate/now",
            snippet="Scripts loaded from js.braintreepayments.com for secure checkout.",
            engine="mock",
            query=ast.raw_query,
        )
        missing_inurl = SearchResult(
            rank=2,
            title="Braintree Payments Docs",
            url="https://nonprofit.org/about-us",
            snippet="Read about braintreepayments.com integration.",
            engine="mock",
            query=ast.raw_query,
        )
        missing_exact_phrase = SearchResult(
            rank=3,
            title="Donate Today",
            url="https://nonprofit.org/donate",
            snippet="Donate to our town of Braintree Massachusetts payments office.",
            engine="mock",
            query=ast.raw_query,
        )

        admitted, dropped = ast.filter_documents([exact_match, missing_inurl, missing_exact_phrase])
        self.assertEqual(len(admitted), 1)
        self.assertEqual(dropped, 2)
        self.assertEqual(admitted[0].url, exact_match.url)

    def test_site_wildcard_intitle_and_negations(self) -> None:
        ast = compile_boolean_query(
            '"braintree" site:*.org inurl:donate intitle:"donate" -captcha -recaptcha -"verify you are human"'
        )

        valid_doc = DocumentView(
            title="Donate Now - Clean Org",
            url="https://clean.charity.org/donate/form",
            snippet="Powered by Braintree SDK without friction.",
        )
        wrong_tld = DocumentView(
            title="Donate Now - Commercial",
            url="https://clean.charity.com/donate/form",
            snippet="Powered by Braintree SDK.",
        )
        has_captcha = DocumentView(
            title="Donate Now - Protected",
            url="https://clean.charity.org/donate/form",
            snippet="Powered by Braintree. Protected by reCAPTCHA verification.",
        )
        has_negated_phrase = DocumentView(
            title="Donate Now - Gate",
            url="https://clean.charity.org/donate/form",
            snippet="Braintree checkout. Please verify you are human to proceed.",
        )
        missing_intitle = DocumentView(
            title="Support Our Mission",
            url="https://clean.charity.org/donate/form",
            snippet="Powered by Braintree SDK.",
        )

        self.assertEqual(ast.evaluate(valid_doc), 1)
        self.assertEqual(ast.evaluate(wrong_tld), 0)
        self.assertEqual(ast.evaluate(has_captcha), 0)
        self.assertEqual(ast.evaluate(has_negated_phrase), 0)
        self.assertEqual(ast.evaluate(missing_intitle), 0)

    def test_filetype_and_non_destructive_dialect_translation(self) -> None:
        ast = compile_boolean_query('"braintree" site:*.org filetype:pdf')
        pdf_ok = DocumentView(
            title="Braintree Annual Report",
            url="https://foundation.org/reports/2026-guide.pdf",
            snippet="Braintree integration overview.",
        )
        html_reject = DocumentView(
            title="Braintree Annual Report",
            url="https://foundation.org/reports/2026-guide.html",
            snippet="Braintree integration overview.",
        )
        self.assertEqual(ast.evaluate(pdf_ok), 1)
        self.assertEqual(ast.evaluate(html_reject), 0)

        # DuckDuckGo dialect strips `*.` from site:*.org while preserving quotes 100%
        ddg_rendered = ast.translate_for_backend("duckduckgo")
        self.assertIn('"braintree"', ddg_rendered)
        self.assertIn("site:org", ddg_rendered)
        self.assertIn("filetype:pdf", ddg_rendered)

    def test_malformed_queries_raise_parse_error(self) -> None:
        for bad in ("", "   ", '"unclosed phrase', "(a AND b", "a AND b)", '""', "inurl:"):
            with self.assertRaises(QueryParseError):
                compile_boolean_query(bad)

    def test_all_queries_in_source_txt_compile_deterministically(self) -> None:
        """Every single non-comment query in `/root/ntest/pack/source.txt` must parse cleanly."""
        source_path = Path("/root/ntest/pack/source.txt")
        try:
            has_source = source_path.is_file()
        except OSError:
            has_source = False
        if not has_source:
            self.skipTest("source.txt fixture not present or inaccessible")

        in_block = False
        parsed_count = 0
        for raw_line in source_path.read_text(encoding="utf-8").splitlines():
            cleaned, in_block = strip_query_line(raw_line, in_block)
            if not cleaned:
                continue
            compiled = compile_boolean_query(cleaned)
            self.assertGreaterEqual(len(compiled.atoms()), 1)
            # An unrelated noise document must evaluate to 0 for every dork in source.txt
            noise = DocumentView(
                title="Weather Forecast Tomorrow Sunny",
                url="https://weather.example.invalid/forecast",
                snippet="Clear skies and mild winds throughout the afternoon.",
            )
            self.assertEqual(
                compiled.evaluate(noise),
                0,
                f"Noise doc unexpectedly matched query: {cleaned}",
            )
            parsed_count += 1

        self.assertGreaterEqual(parsed_count, 150)


if __name__ == "__main__":
    unittest.main()
