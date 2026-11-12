"""HTML extraction built on the standard-library :mod:`html.parser`.

Extracts:
* inline ``<script>`` bodies (with host-file line offsets),
* ``on*`` event handler attribute values,
* ``href`` / ``src`` attributes whose value uses the ``javascript:`` scheme.
"""

from html.parser import HTMLParser

from . import sinks as sink_catalog
from . import sources as source_catalog


class InlineScript:
    __slots__ = ("content", "start_line", "start_col", "type")

    def __init__(self, content, start_line, start_col, script_type=None):
        self.content = content
        self.start_line = start_line
        self.start_col = start_col
        self.type = script_type


class EventAttribute:
    __slots__ = ("name", "value", "line", "col", "tag")

    def __init__(self, name, value, line, col, tag):
        self.name = name
        self.value = value
        self.line = line
        self.col = col
        self.tag = tag


class JavaScriptUri:
    __slots__ = ("attribute", "value", "line", "col", "tag")

    def __init__(self, attribute, value, line, col, tag):
        self.attribute = attribute
        self.value = value
        self.line = line
        self.col = col
        self.tag = tag


class _ExtractingParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.events = []
        self.javascript_uris = []
        self._script_buffer = None
        self._script_meta = None

    def handle_starttag(self, tag, attrs):
        line, col = self.getpos()
        col += 1  # getpos returns 0-based column; normalize to 1-based
        for attr_name, attr_value in attrs:
            if attr_name is None:
                continue
            lowered = attr_name.lower()
            if lowered.startswith("on") and len(lowered) > 2:
                self.events.append(EventAttribute(
                    lowered, attr_value or "", line, col, tag.lower()))
            if lowered in ("href", "src", "xlink:href") and attr_value:
                stripped = attr_value.lstrip()
                if stripped[:11].lower().startswith("javascript:"):
                    self.javascript_uris.append(JavaScriptUri(
                        lowered, stripped, line, col, tag.lower()))
        if tag.lower() == "script":
            script_type = None
            for attr_name, attr_value in attrs:
                if attr_name and attr_name.lower() == "type":
                    script_type = (attr_value or "").lower()
            self._script_buffer = []
            self._script_meta = (line, col, script_type)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() == "script":
            # Self-closed script has no body; flush the empty buffer.
            self._flush_script()

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self._flush_script()

    def handle_data(self, data):
        if self._script_buffer is not None:
            self._script_buffer.append(data)

    def _flush_script(self):
        if self._script_meta is None:
            return
        line, col, script_type = self._script_meta
        content = "".join(self._script_buffer or [])
        if self._is_executable(script_type):
            self.scripts.append(InlineScript(content, line, col, script_type))
        self._script_buffer = None
        self._script_meta = None

    @staticmethod
    def _is_executable(script_type):
        if not script_type:
            return True
        executable = {
            "text/javascript", "application/javascript", "module",
            "text/ecmascript", "application/ecmascript", "",
        }
        return script_type in executable

    def close(self):
        super().close()
        if self._script_meta is not None:
            self._flush_script()


def extract_html_nodes(html_text):
    parser = _ExtractingParser()
    parser.feed(html_text)
    parser.close()
    return {
        "scripts": parser.scripts,
        "events": parser.events,
        "javascript_uris": parser.javascript_uris,
    }


def first_code_line_offset(script_content, script_start_line):
    """Return the offset converting a JS line number to the host HTML line.

    The JS parser counts every character of the script content, including a
    leading newline directly after the opening ``<script>`` tag. Host line =
    ``script_start_line + js_line - 1``.
    """
    return script_start_line - 1


def strip_javascript_scheme(value):
    text = value.lstrip()
    if text[:11].lower().startswith("javascript:"):
        return text[11:]
    return text


__all__ = [
    "InlineScript", "EventAttribute", "JavaScriptUri",
    "extract_html_nodes", "first_code_line_offset",
    "strip_javascript_scheme",
    "sink_catalog", "source_catalog",
]
