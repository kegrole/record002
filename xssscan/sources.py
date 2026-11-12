"""Declarative source catalogue of untrusted browser inputs."""

# location.hash / location.search etc.  The key is the trailing property name
# and the value is the canonical source label emitted in findings.
LOCATION_SOURCES = {
    "hash": "location.hash",
    "search": "location.search",
    "href": "location.href",
}

# document.URL and document.referrer.
DOCUMENT_PROPERTY_SOURCES = {
    "URL": "document.URL",
    "referrer": "document.referrer",
}

# Storage read method.
LOCAL_STORAGE_GET_ITEM = "localStorage.getItem"

# URLSearchParams read methods.
URL_PARAM_METHODS = {
    "get": "URLSearchParams.get",
    "getAll": "URLSearchParams.getAll",
}

# postMessage inbound payload.
EVENT_DATA = "event.data"

# Properties that are treated as event.data when reached on a parameter that
# the code itself names as an inbound message event.  We conservatively treat
# any ``<name>.data`` inside a function whose first parameter is named
# ``event`` / ``evt`` / ``e`` / ``messageEvent`` as a source.
EVENT_DATA_PARAM_NAMES = {"event", "evt", "e", "messageEvent", "ev"}


def all_source_labels():
    labels = set(LOCATION_SOURCES.values())
    labels.update(DOCUMENT_PROPERTY_SOURCES.values())
    labels.add(LOCAL_STORAGE_GET_ITEM)
    labels.update(URL_PARAM_METHODS.values())
    labels.add(EVENT_DATA)
    return sorted(labels)
