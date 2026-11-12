"""Unit tests for the pure-stdlib DOM XSS scanner.

The five mandatory acceptance cases live verbatim under ``fixtures/`` and are
each asserted on individually below.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "fixtures")
DEMO = os.path.join(ROOT, "demo_site")

from xssscan.report import scan, write_report, summarize  # noqa: E402
from xssscan.taint import ModuleEngine  # noqa: E402


def fixture_path(name):
    return os.path.join(FIXTURES, name)


def scan_text_files(mapping):
    """Write a {relative_path: content} tree to a temp dir and scan it."""
    workdir = tempfile.mkdtemp(prefix="xssscan-test-")
    try:
        for relative, content in mapping.items():
            absolute = os.path.join(workdir, relative)
            os.makedirs(os.path.dirname(absolute), exist_ok=True)
            with open(absolute, "w", encoding="utf-8") as handle:
                handle.write(content)
        findings, count = scan(workdir)
        return findings, count
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class AcceptanceFixtureTests(unittest.TestCase):
    def setUp(self):
        self.findings, self.scanned = scan(FIXTURES)

    def test_case1_inner_html_location_hash_is_reported(self):
        # 1. el.innerHTML = location.hash -> report innerHTML + location.hash
        matches = [f for f in self.findings
                   if f["file"].endswith("case1_innerhtml_hash.js")]
        self.assertEqual(len(matches), 1)
        finding = matches[0]
        self.assertEqual(finding["sink_type"], "innerHTML")
        self.assertIn("location.hash", finding["sources"])
        self.assertEqual(finding["line"], 2)
        self.assertGreaterEqual(finding["col"], 1)

    def test_case2_text_content_is_not_a_sink(self):
        # 2. textContent is not a dangerous sink even with a source.
        matches = [f for f in self.findings
                   if f["file"].endswith("case2_textcontent_safe.js")]
        self.assertEqual(matches, [])

    def test_case3_literal_constant_eval_is_not_reported(self):
        # 3. const userInput = "hello"; eval(userInput) must stay silent.
        matches = [f for f in self.findings
                   if f["file"].endswith("case3_constant_eval_safe.js")]
        self.assertEqual(matches, [])

    def test_case4_cross_file_import_path_contains_both_files(self):
        # 4. export in case4_a.js, import + innerHTML in case4_b.js.
        matches = [f for f in self.findings
                   if f["file"].endswith("case4_b.js")]
        self.assertEqual(len(matches), 1)
        finding = matches[0]
        self.assertEqual(finding["sink_type"], "innerHTML")
        self.assertEqual(finding["sources"], ["location.search"])
        path_files = [step["file"] for step in finding["propagation_path"]]
        self.assertTrue(any(p.endswith("case4_a.js") for p in path_files))
        self.assertTrue(any(p.endswith("case4_b.js") for p in path_files))
        self.assertEqual(finding["line"], 3)

    def test_case5_inline_event_attribute_reports_button_line(self):
        # 5. <button onclick="render(location.hash)"> on line 4.
        matches = [f for f in self.findings
                   if f["file"].endswith("case5_event_attribute.html")]
        self.assertEqual(len(matches), 1)
        finding = matches[0]
        self.assertEqual(finding["sink_type"], "event_attribute")
        self.assertIn("location.hash", finding["sources"])
        self.assertEqual(finding["line"], 4)


class LinePositionTests(unittest.TestCase):
    def test_sink_line_matches_keyword_line_within_one(self):
        source = "\n\n// comment\nel.innerHTML = location.hash;\n"
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        # innerHTML keyword is on line 4.
        self.assertEqual(findings[0]["line"], 4)
        self.assertLessEqual(abs(findings[0]["line"] - 4), 1)

    def test_inline_script_line_maps_into_html_host(self):
        html = (
            "<html>\n<body>\n<script>\n"
            "el.innerHTML = location.hash;\n"
            "</script>\n</body>\n</html>\n"
        )
        findings, _ = scan_text_files({"page.html": html})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], "page.html")
        self.assertEqual(findings[0]["line"], 4)

    def test_event_attribute_column_points_at_element(self):
        html = '''<html><body>
  <button onclick="render(location.hash)">x</button>
</body></html>
'''
        findings, _ = scan_text_files({"page.html": html})
        event = [f for f in findings if f["sink_type"] == "event_attribute"]
        self.assertEqual(len(event), 1)
        self.assertEqual(event[0]["line"], 2)
        self.assertEqual(event[0]["col"], 3)


class TaintReachabilityTests(unittest.TestCase):
    def test_source_overwritten_with_constant_is_not_reported(self):
        source = (
            "let value = location.hash;\n"
            "value = 'fixed';\n"
            "el.innerHTML = value;\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(findings, [])

    def test_taint_flows_across_statements_and_function_arguments(self):
        source = (
            "function render(target, html) { target.innerHTML = html; }\n"
            "const data = location.hash;\n"
            "render(el, data);\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sink_type"], "innerHTML")
        self.assertEqual(findings[0]["sources"], ["location.hash"])

    def test_constant_folding_plus_string_concatenation(self):
        safe = (
            "const a = 'foo';\nconst b = 'bar';\n"
            "eval(a + b);\n"
        )
        findings, _ = scan_text_files({"safe.js": safe})
        self.assertEqual(findings, [])
        tainted = (
            "const prefix = 'x';\n"
            "const payload = prefix + location.hash;\n"
            "eval(payload);\n"
        )
        findings, _ = scan_text_files({"tainted.js": tainted})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sink_type"], "eval")

    def test_branch_taint_is_merged(self):
        source = (
            "let value = 'safe';\n"
            "if (flag) { value = location.search; }\n"
            "el.innerHTML = value;\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sources"], ["location.search"])

    def test_settimeout_string_argument_only(self):
        source = (
            "setTimeout(location.hash, 0);\n"
            "setTimeout(function () { callback(); }, 10);\n"
            "setTimeout('literal-code', 10);\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sink_type"], "setTimeout")

    def test_sources_and_sinks_catalog(self):
        source = """
el.innerHTML = location.hash;
el.outerHTML = location.search;
document.write(document.URL);
eval(document.referrer);
location.href = localStorage.getItem("next");
window.open(location.hash);
parent.postMessage(event.data, "*");
const fn = new Function(location.hash);
el.insertAdjacentHTML("beforeend", location.search);
setInterval(location.hash, 5);
"""
        findings, _ = scan_text_files({"page.js": source})
        types = {f["sink_type"] for f in findings}
        expected = {
            "innerHTML", "outerHTML", "document.write", "eval",
            "location_href", "window.open", "postMessage",
            "new_function", "insertAdjacentHTML", "setInterval",
        }
        self.assertTrue(expected.issubset(types), types)

    def test_event_data_source(self):
        source = (
            "window.addEventListener('message', function (event) {\n"
            "  el.innerHTML = event.data;\n"
            "});\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sources"], ["event.data"])

    def test_javascript_uri_with_source(self):
        html = '''<html><body>
<a href="javascript:go(location.hash)">go</a>
</body></html>
'''
        findings, _ = scan_text_files({"page.html": html})
        uris = [f for f in findings
                if f["sink_type"] == "javascript_uri"]
        self.assertEqual(len(uris), 1)
        self.assertEqual(uris[0]["line"], 2)
        self.assertIn("location.hash", uris[0]["sources"])

    def test_url_search_params_source(self):
        source = (
            "const params = new URLSearchParams(location.search);\n"
            "el.innerHTML = params.get('q');\n"
            "const fixed = new URLSearchParams('a=1').get('a');\n"
            "safe.textContent = fixed;\n"
        )
        findings, _ = scan_text_files({"page.js": source})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["sources"], ["URLSearchParams.get"])


class ConstantSafetyTests(unittest.TestCase):
    def test_all_constant_sinks_are_silent(self):
        source = """
const a = "x", b = "y";
eval(a + b);
const fn = new Function("return 1");
document.write("<b>fixed</b>");
setTimeout("console.log(1)", 10);
location.href = "/home";
window.open("/help");
el.innerHTML = "<em>fixed</em>";
"""
        findings, _ = scan_text_files({"safe.js": source})
        self.assertEqual(findings, [])

    def test_default_and_namespace_imports_propagate(self):
        files = {
            os.path.join("mod", "a.js"):
                "export const t = location.hash;\n"
                "export default location.search;\n",
            os.path.join("mod", "b.js"):
                'import def, { t as renamed } from "./a.js";\n'
                "el.innerHTML = renamed;\n"
                "window.open(def);\n",
        }
        findings, _ = scan_text_files(files)
        self.assertEqual(len(findings), 2)
        path_files = {
            step["file"]
            for finding in findings
            for step in finding["propagation_path"]
        }
        self.assertTrue(any(p.endswith("a.js") for p in path_files))
        self.assertTrue(any(p.endswith("b.js") for p in path_files))


class DeterminismTests(unittest.TestCase):
    def test_two_runs_produce_identical_json(self):
        out1 = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
        out2 = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
        try:
            findings, _ = scan(ROOT)
            write_report(findings, out1)
            write_report(findings, out2)
            with open(out1, encoding="utf-8") as handle:
                first = handle.read()
            with open(out2, encoding="utf-8") as handle:
                second = handle.read()
            self.assertEqual(first, second)
            payload = json.loads(first)
            self.assertEqual(payload["finding_count"], len(payload["findings"]))
        finally:
            os.unlink(out1)
            os.unlink(out2)


class CliTests(unittest.TestCase):
    def test_cli_summary_and_demo_runs_quickly(self):
        out_path = os.path.join(tempfile.mkdtemp(), "findings.json")
        command = [
            sys.executable, "-m", "xssscan.cli",
            "--root", DEMO, "--out", out_path,
        ]
        completed = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, timeout=90,
            check=True)
        summary = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertIn("scanned_files", summary)
        self.assertIn("finding_count", summary)
        self.assertIn("by_sink_type", summary)
        self.assertTrue(os.path.exists(out_path))
        with open(out_path, encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertEqual(summary["finding_count"], report["finding_count"])


if __name__ == "__main__":
    unittest.main()
