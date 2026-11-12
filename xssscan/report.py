"""Directory traversal, HTML/JS orchestration and deterministic JSON output."""

import json
import os

from .html_parser import (
    extract_html_nodes, first_code_line_offset, strip_javascript_scheme,
)
from .sinks import EVENT_ATTRIBUTE_SINK, JAVASCRIPT_URI_SINK
from .taint import ModuleEngine, Origin

HTML_EXTENSIONS = (".html", ".htm", ".xhtml")
JS_EXTENSIONS = (".js", ".mjs")


def iter_input_files(root):
    """Yield supported files under root in deterministic sorted order."""
    for directory, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for filename in sorted(filenames):
            extension = os.path.splitext(filename)[1].lower()
            if extension in HTML_EXTENSIONS or extension in JS_EXTENSIONS:
                yield os.path.join(directory, filename)


def _normalize(path, root):
    """Return a stable repo-relative POSIX-style path for reports."""
    absolute = os.path.abspath(path)
    root_absolute = os.path.abspath(root)
    try:
        relative = os.path.relpath(absolute, root_absolute)
    except ValueError:
        relative = absolute
    return relative.replace(os.sep, "/")


def scan(root):
    """Scan a directory and return (findings, scanned_file_count)."""
    root = os.path.abspath(root)
    engine = ModuleEngine()
    files = list(iter_input_files(root))
    all_findings = []

    # JS files first so cross-file import exports are available when inline
    # scripts or later modules import them.
    js_files = [path for path in files
                if os.path.splitext(path)[1].lower() in JS_EXTENSIONS]
    html_files = [path for path in files
                  if os.path.splitext(path)[1].lower() in HTML_EXTENSIONS]

    for path in js_files:
        record = engine.analyze_file(path)
        for finding in record["findings"]:
            finding = dict(finding)
            finding["file"] = _normalize(finding["file"], root)
            finding["propagation_path"] = [
                {"file": _normalize(step["file"], root),
                 "line": step["line"]}
                for step in finding["propagation_path"]
            ]
            all_findings.append(finding)

    for path in html_files:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            html_text = handle.read()
        relative = _normalize(path, root)
        all_findings.extend(
            _scan_html(engine, path, relative, html_text, root))

    all_findings.sort(key=_finding_sort_key)
    return all_findings, len(files)


def _finding_sort_key(finding):
    return (
        finding["file"], finding["line"], finding["col"],
        finding["sink_type"], tuple(finding["sources"]),
        json.dumps(finding["propagation_path"], sort_keys=True),
    )


def _scan_html(engine, absolute_path, relative_path, html_text, root):
    nodes = extract_html_nodes(html_text)
    findings = []

    for script in nodes["scripts"]:
        if not script.content.strip():
            continue
        offset = first_code_line_offset(script.content, script.start_line)
        inline_findings, _ = engine.analyze_inline(
            absolute_path, script.content, line_offset=offset)
        for finding in inline_findings:
            findings.append(_relativize_finding(finding, root))

    for event in nodes["events"]:
        findings.extend(_scan_event(engine, absolute_path, event, root))

    for uri in nodes["javascript_uris"]:
        findings.extend(_scan_javascript_uri(engine, absolute_path, uri, root))

    # Re-tag host file names with the relative path.
    for finding in findings:
        finding["file"] = relative_path
    return findings


def _relativize_finding(finding, root):
    finding = dict(finding)
    finding["propagation_path"] = [
        {"file": _normalize(step["file"], root), "line": step["line"]}
        for step in finding["propagation_path"]
    ]
    return finding


def _scan_event(engine, host_path, event, root):
    if not event.value.strip():
        return []
    # Event handler JS line 1 maps directly onto the HTML element line.
    findings, sources, value = engine.analyze_handler(
        host_path, event.value, line_offset=event.line - 1)
    results = [_relativize_finding(finding, root) for finding in findings]
    if value is not None and value.origins:
        origins = _dedupe_origins(value.origins)
        results.append({
            "file": _normalize(host_path, root),
            "sink_type": EVENT_ATTRIBUTE_SINK,
            "line": event.line,
            "col": event.col,
            "sources": sorted({o.label for o in origins}),
            "propagation_path": _origin_paths(origins, root, event.line),
        })
    return results


def _scan_javascript_uri(engine, host_path, uri, root):
    code = strip_javascript_scheme(uri.value)
    if not code.strip():
        return []
    findings, sources, value = engine.analyze_handler(
        host_path, code, line_offset=uri.line - 1)
    results = [_relativize_finding(finding, root) for finding in findings]
    if value is not None and value.origins:
        origins = _dedupe_origins(value.origins)
        results.append({
            "file": _normalize(host_path, root),
            "sink_type": JAVASCRIPT_URI_SINK,
            "line": uri.line,
            "col": uri.col,
            "sources": sorted({o.label for o in origins}),
            "propagation_path": _origin_paths(origins, root, uri.line),
        })
    return results


def _dedupe_origins(origins):
    unique = {}
    for origin in origins:
        unique[origin.key()] = origin
    return sorted(unique.values(), key=lambda o: (o.file, o.line, o.col, o.label))


def _origin_paths(origins, root, host_line):
    paths = []
    for origin in origins:
        for step in origin.path:
            normalized = {"file": _normalize(step["file"], root),
                          "line": step["line"]}
            if normalized not in paths:
                paths.append(normalized)
    sink_step = {"file": _normalize(origins[0].file if origins else "", root),
                 "line": host_line}
    if sink_step not in paths:
        paths.append(sink_step)
    return paths


def write_report(findings, out_path):
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    payload = {
        "findings": findings,
        "finding_count": len(findings),
    }
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True,
                  ensure_ascii=False)
        handle.write("\n")


def summarize(findings):
    counts = {}
    for finding in findings:
        counts[finding["sink_type"]] = counts.get(
            finding["sink_type"], 0) + 1
    return dict(sorted(counts.items()))
