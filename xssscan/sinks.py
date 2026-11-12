"""Declarative sink catalogue.

Each entry maps a JS construct to a stable sink type string used both in the
JSON report and in tests / documentation.
"""

# Object properties that execute HTML when assigned attacker controlled data.
HTML_PROPERTY_SINKS = {
    "innerHTML": "innerHTML",
    "outerHTML": "outerHTML",
}

# Assignment to location / location.href / document.location triggers
# navigation and therefore javascript: style script execution.
LOCATION_PROPERTY_SINKS = {
    "href": "location_href",
}

# Method calls: member name -> sink type.  The taint engine additionally
# checks the receiver / argument shape described in the README.
METHOD_SINKS = {
    "insertAdjacentHTML": "insertAdjacentHTML",
    "write": "document.write",
    "writeln": "document.write",
    "open": "window.open",
    "postMessage": "postMessage",
    "eval": "eval",
}

# Bare function / method names treated as sinks.
FUNCTION_SINKS = {
    "setTimeout": "setTimeout",
    "setInterval": "setInterval",
    "eval": "eval",
}

# Methods whose string argument is a dynamically compiled function body.
FUNCTION_CONSTRUCTOR = "Function"
FUNCTION_CONSTRUCTOR_SINK = "new_function"

# HTML-only sink types (produced by the HTML parser).
EVENT_ATTRIBUTE_SINK = "event_attribute"
JAVASCRIPT_URI_SINK = "javascript_uri"

# Setters considered dangerous regardless of receiver property origin style.
DANGEROUS_PROPERTY_NAMES = set(HTML_PROPERTY_SINKS) | {"location"}


def all_sink_types():
    """Return the sorted, de-duplicated list of sink type identifiers."""
    types_ = set(HTML_PROPERTY_SINKS.values())
    types_.update(LOCATION_PROPERTY_SINKS.values())
    types_.update(METHOD_SINKS.values())
    types_.update(FUNCTION_SINKS.values())
    types_.add(FUNCTION_CONSTRUCTOR_SINK)
    types_.add(EVENT_ATTRIBUTE_SINK)
    types_.add(JAVASCRIPT_URI_SINK)
    return sorted(types_)
