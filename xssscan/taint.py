"""Intra- and inter-file taint analysis built on the hand-written AST.

Flow-insensitive within a scope but statement-order aware: an assignment
overwrites the tracked value, so a source later replaced by a literal is no
longer tainted. Function parameters are analyzed at call time and ES module
imports follow exported bindings across files.
"""

import os

from . import sinks as sink_catalog
from . import sources as source_catalog
from .js_scanner import (
    JSSyntaxError, parse, parse_expression,  # noqa: F401
)


class Origin:
    """A single untrusted source occurrence."""

    __slots__ = ("label", "file", "line", "col", "path")

    def __init__(self, label, file, line, col, path=None):
        self.label = label
        self.file = file
        self.line = line
        self.col = col
        self.path = list(path) if path else [{"file": file, "line": line}]

    def clone(self):
        return Origin(self.label, self.file, self.line, self.col,
                      [dict(step) for step in self.path])

    def key(self):
        return self.label, self.file, self.line, self.col

    def to_dict(self):
        return {
            "source": self.label,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "path": [dict(step) for step in self.path],
        }


class Value:
    """Abstract value tracked through a program."""

    __slots__ = ("origins", "constant", "const_value", "kind", "function",
                 "members", "name")

    def __init__(self, origins=None, constant=False, const_value=None,
                 kind="unknown", function=None, name=None):
        self.origins = list(origins or [])
        self.constant = constant
        self.const_value = const_value
        self.kind = kind  # unknown | literal | function | object | array
        self.function = function
        self.members = {}
        self.name = name

    @property
    def tainted(self):
        return bool(self.origins)

    def copy(self):
        value = Value([o.clone() for o in self.origins], self.constant,
                      self.const_value, self.kind, self.function, self.name)
        value.members = dict(self.members)
        return value

    def with_step(self, file, line):
        value = self.copy()
        for origin in value.origins:
            step = {"file": file, "line": line}
            if not origin.path or origin.path[-1] != step:
                origin.path.append(step)
        return value

    def taint_only(self):
        return Value([o.clone() for o in self.origins])

    def merge(self, other):
        result = self.copy()
        seen = {o.key() for o in result.origins}
        for origin in other.origins:
            if origin.key() not in seen:
                result.origins.append(origin.clone())
                seen.add(origin.key())
        if result.kind == "unknown":
            result.kind = other.kind
        return result


def literal_value(node_value, kind):
    if kind == "number":
        try:
            text = str(node_value).replace("_", "")
            if text.lower().startswith("0x"):
                return int(text, 16)
            if text.lower().startswith("0b"):
                return int(text, 2)
            if text.lower().startswith("0o"):
                return int(text, 8)
            if "." in text or "e" in text.lower():
                return float(text)
            return int(text)
        except ValueError:
            return node_value
    if kind == "true":
        return True
    if kind == "false":
        return False
    if kind in ("null", "undefined"):
        return None
    return node_value


class Scope:
    def __init__(self, parent=None):
        self.parent = parent
        self.bindings = {}

    def declare(self, name, value):
        self.bindings[name] = value

    def lookup(self, name):
        scope = self
        while scope is not None:
            if name in scope.bindings:
                return scope.bindings[name]
            scope = scope.parent
        return None

    def assign(self, name, value):
        scope = self
        root = scope
        while scope is not None:
            if name in scope.bindings:
                scope.bindings[name] = value
                return
            root = scope
            scope = scope.parent
        root.bindings[name] = value

    def snapshot(self):
        data = {}
        scope = self
        while scope is not None:
            for key, value in scope.bindings.items():
                if key not in data:
                    data[key] = value.copy()
            scope = scope.parent
        return data

    def restore(self, data):
        self.bindings = dict(data)
        self.parent = None


PASSTHROUGH_METHODS = {
    "toString", "toLowerCase", "toUpperCase", "trim", "trimStart",
    "trimEnd", "substring", "substr", "slice", "concat", "replace",
    "replaceAll", "split", "charAt", "charCodeAt", "padStart", "padEnd",
    "repeat", "encodeURIComponent", "encodeURI", "decodeURIComponent",
    "decodeURI", "valueOf", "normalize", "match", "search",
    "includes", "indexOf", "startsWith", "endsWith", "at",
}

MAX_CALL_DEPTH = 4


class Analyzer:
    """Analyzes one JS module and records findings."""

    def __init__(self, file_path, module_engine, origin_file=None,
                 line_offset=0):
        self.file = file_path
        # origin_file is the HTML host of an inline script; line_offset maps
        # script-relative lines back onto the host file.
        self.origin_file = origin_file
        self.line_offset = line_offset
        self.engine = module_engine
        self.global_scope = Scope()
        self.findings = []
        self.source_occurrences = []
        self._finding_keys = set()
        self._current_scope = None
        self._observed_calls = {}
        self._function_identities = {}
        self.call_depth = 0

    def mapped_line(self, line):
        return line + self.line_offset

    def add_finding(self, sink_type, node, origins, extra_path=None):
        if not origins:
            return
        unique = {}
        for origin in origins:
            unique[origin.key()] = origin
        origins = sorted(unique.values(),
                         key=lambda o: (o.file, o.line, o.col, o.label))
        key = (self.origin_file or self.file, sink_type,
               self.mapped_line(node["line"]), node["col"],
               tuple(o.key() for o in origins))
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append({
            "file": self.origin_file or self.file,
            "sink_type": sink_type,
            "line": self.mapped_line(node["line"]),
            "col": node["col"],
            "sources": sorted({o.label for o in origins}),
            "propagation_path": self._build_path(origins, extra_path),
        })

    @staticmethod
    def _build_path(origins, extra_path):
        paths = []
        for origin in origins:
            for step in origin.path:
                if step not in paths:
                    paths.append(dict(step))
        if extra_path:
            for step in extra_path:
                if step not in paths:
                    paths.append(dict(step))
        return paths

    def analyze(self, program):
        self._hoist_functions(program["body"], self.global_scope)
        for statement in program["body"]:
            self.exec_statement(statement, self.global_scope)
        self._replay_observed_calls()
        return self.findings

    def _replay_observed_calls(self):
        for node_id, calls in self._observed_calls.items():
            function_node, closure_scope = self._function_identities[node_id]
            params = function_node.get("params", [])
            if not params:
                continue
            for signature in calls:
                if not any(signature):
                    continue
                local = Scope(closure_scope)
                for index, param in enumerate(params):
                    key_tuple = signature[index] if index < len(signature) else ()
                    origins = self._origins_from_keys(key_tuple)
                    local.declare(param, Value(origins=origins))
                body = function_node.get("body")
                if body is None:
                    continue
                if body["type"] == "block":
                    for statement in body["body"]:
                        self.exec_statement(statement, local)
                else:
                    self.eval_expression(body, local)

    def _origins_from_keys(self, key_tuple):
        origins = []
        for label, file_name, line, col in key_tuple:
            origins.append(Origin(label, file_name, line, col))
        return origins

    def _collect_functions(self, statements, bucket):
        for statement in statements:
            kind = statement["type"]
            if kind == "function_declaration":
                bucket.append(statement)
                self._collect_functions(statement["body"]["body"], bucket)
            elif kind in ("export_named", "export_default"):
                declaration = statement.get("declaration")
                if declaration and declaration["type"] == "function_declaration":
                    bucket.append(declaration)
                    self._collect_functions(declaration["body"]["body"], bucket)
            elif kind in ("var_declaration",):
                for declarator in statement["declarations"]:
                    init = declarator.get("init")
                    if init and init["type"] in (
                        "function_expression", "arrow_function"
                    ):
                        bucket.append(init)
            elif kind == "block":
                self._collect_functions(statement["body"], bucket)
            elif kind in ("if", "for", "for_in_of", "while", "do_while",
                          "try", "switch"):
                self._collect_functions(self._nested_statements(statement), bucket)

    @staticmethod
    def _nested_statements(node):
        statements = []
        for key in ("body", "consequent", "alternate", "finalizer"):
            value = node.get(key)
            if isinstance(value, dict) and value.get("type") == "block":
                statements.extend(value["body"])
            elif isinstance(value, list):
                statements.extend(
                    item for item in value if isinstance(item, dict))
        handler = node.get("handler")
        if handler:
            statements.extend(handler["body"]["body"])
        for case in node.get("cases", []):
            statements.extend(case["body"])
        return statements


    def _hoist_functions(self, statements, scope):
        for statement in statements:
            if statement["type"] == "function_declaration":
                scope.declare(statement["name"], Value(
                    kind="function", function=(statement, scope),
                    name=statement["name"]))
            elif statement["type"] in ("export_named", "export_default"):
                declaration = statement.get("declaration")
                if declaration and declaration["type"] == "function_declaration":
                    scope.declare(declaration["name"], Value(
                        kind="function", function=(declaration, scope),
                        name=declaration["name"]))

    def exec_statement(self, node, scope):
        method = getattr(self, "_stmt_" + node["type"], None)
        if method is not None:
            method(node, scope)

    def _stmt_empty(self, node, scope):
        return

    def _stmt_block(self, node, scope):
        inner = Scope(scope)
        for statement in node["body"]:
            self.exec_statement(statement, inner)

    def _stmt_var_declaration(self, node, scope):
        for declarator in node["declarations"]:
            if declarator["init"] is None:
                scope.declare(declarator["name"], Value())
            else:
                scope.declare(declarator["name"],
                              self.eval_expression(declarator["init"], scope))

    def _stmt_expression(self, node, scope):
        self.eval_expression(node["expression"], scope)

    def _stmt_function_declaration(self, node, scope):
        scope.declare(node["name"], Value(kind="function",
                                          function=(node, scope),
                                          name=node["name"]))

    def _stmt_return(self, node, scope):
        if node["argument"] is not None:
            self.eval_expression(node["argument"], scope)

    def _stmt_throw(self, node, scope):
        self.eval_expression(node["argument"], scope)

    def _stmt_if(self, node, scope):
        self.eval_expression(node["test"], scope)
        consequent_scope = Scope(scope)
        self.exec_statement(node["consequent"], consequent_scope)
        self._promote_assignments(scope, consequent_scope)
        if node["alternate"] is not None:
            alternate_scope = Scope(scope)
            self.exec_statement(node["alternate"], alternate_scope)
            self._promote_assignments(scope, alternate_scope)

    @staticmethod
    def _promote_assignments(parent, child):
        for name, value in child.bindings.items():
            existing = parent.lookup(name)
            if existing is None:
                parent.declare(name, value)
            elif value.tainted and not existing.tainted:
                parent.assign(name, existing.merge(value))
            elif value.tainted and existing.tainted:
                parent.assign(name, existing.merge(value))

    def _stmt_for(self, node, scope):
        inner = Scope(scope)
        if node["init"] is not None:
            self.exec_statement(node["init"], inner)
        if node["test"] is not None:
            self.eval_expression(node["test"], inner)
        if node["update"] is not None:
            self.eval_expression(node["update"], inner)
        self.exec_statement(node["body"], Scope(inner))
        self._promote_assignments(scope, inner)

    def _stmt_for_in_of(self, node, scope):
        right = self.eval_expression(node["right"], scope)
        inner = Scope(scope)
        self._bind_for_target(node["left"], right, inner)
        self.exec_statement(node["body"], Scope(inner))
        self._promote_assignments(scope, inner)

    def _bind_for_target(self, target, value, scope):
        if target["type"] == "var_declaration":
            for declarator in target["declarations"]:
                scope.declare(declarator["name"], value.taint_only())
        elif target["type"] == "identifier":
            scope.assign(target["name"], value.taint_only())

    def _stmt_while(self, node, scope):
        self.eval_expression(node["test"], scope)
        inner = Scope(scope)
        self.exec_statement(node["body"], inner)
        self._promote_assignments(scope, inner)

    def _stmt_do_while(self, node, scope):
        inner = Scope(scope)
        self.exec_statement(node["body"], inner)
        self.eval_expression(node["test"], inner)
        self._promote_assignments(scope, inner)

    def _stmt_switch(self, node, scope):
        self.eval_expression(node["discriminant"], scope)
        inner = Scope(scope)
        for case in node["cases"]:
            if case["test"] is not None:
                self.eval_expression(case["test"], inner)
            for statement in case["body"]:
                self.exec_statement(statement, inner)
        self._promote_assignments(scope, inner)

    def _stmt_try(self, node, scope):
        self.exec_statement(node["block"], Scope(scope))
        if node["handler"] is not None:
            handler = node["handler"]
            catch_scope = Scope(scope)
            if handler["param"]:
                catch_scope.declare(handler["param"], Value())
            for statement in handler["body"]["body"]:
                self.exec_statement(statement, catch_scope)
        if node["finalizer"] is not None:
            self.exec_statement(node["finalizer"], Scope(scope))

    # ----- expressions -----------------------------------------------
    def eval_expression(self, node, scope):
        if node is None:
            return Value()
        previous_scope = self._current_scope
        self._current_scope = scope
        method = getattr(self, "_eval_" + node["type"], None)
        try:
            if method is None:
                return Value()
            return method(node, scope)
        finally:
            self._current_scope = previous_scope

    def _eval_literal(self, node, scope):
        return Value(constant=True,
                     const_value=literal_value(node["value"], node["kind"]),
                     kind="literal")

    def _eval_identifier(self, node, scope):
        value = scope.lookup(node["name"])
        if value is None:
            return Value(name=node["name"])
        return value.with_step(self.origin_file or self.file, node["line"])

    def _eval_this(self, node, scope):
        return Value()

    def _eval_array(self, node, scope):
        value = Value(kind="array")
        for index, element in enumerate(node["elements"]):
            if element is not None:
                value.members[index] = self.eval_expression(element, scope)
                for origin in value.members[index].origins:
                    value.origins.append(origin.clone())
        return value

    def _eval_object(self, node, scope):
        value = Value(kind="object")
        for property_node in node["properties"]:
            key = self._property_key_name(property_node["key"])
            if property_node["value"] is None:
                continue
            member = self.eval_expression(property_node["value"], scope)
            value.members[key] = member
            for origin in member.origins:
                value.origins.append(origin.clone())
        return value

    @staticmethod
    def _property_key_name(node):
        if node["type"] == "identifier":
            return node["name"]
        if node["type"] == "literal":
            return str(node["value"])
        return None

    def _eval_template(self, node, scope):
        tainted = []
        constant_parts = list(node["quasis"])
        for expression in node["expressions"]:
            value = self.eval_expression(expression, scope)
            tainted.extend(o.clone() for o in value.origins)
        if tainted:
            return Value(origins=tainted)
        return Value(constant=True, const_value="".join(constant_parts),
                     kind="literal")

    def _eval_binary(self, node, scope):
        left = self.eval_expression(node["left"], scope)
        right = self.eval_expression(node["right"], scope)
        origins = [o.clone() for o in left.origins]
        origins.extend(o.clone() for o in right.origins)
        if node["operator"] in ("+",) and left.constant and right.constant:
            return Value(constant=True,
                         const_value=self._fold(left.const_value, right.const_value,
                                                node["operator"]),
                         kind="literal", origins=origins)
        if left.constant and right.constant and not origins:
            return Value(constant=True,
                         const_value=self._fold(left.const_value, right.const_value,
                                                node["operator"]),
                         kind="literal")
        return Value(origins=origins)

    def _eval_logical(self, node, scope):
        left = self.eval_expression(node["left"], scope)
        right = self.eval_expression(node["right"], scope)
        merged = left.merge(right)
        if node["operator"] == "&&" and left.constant and not left.const_value:
            return left
        if node["operator"] == "||" and left.constant and left.const_value:
            return left
        if node["operator"] == "??" and left.constant and left.const_value is not None:
            return left
        return merged

    def _eval_conditional(self, node, scope):
        test = self.eval_expression(node["test"], scope)
        consequent = self.eval_expression(node["consequent"], scope)
        alternate = self.eval_expression(node["alternate"], scope)
        if test.constant:
            chosen = consequent if test.const_value else alternate
            return chosen
        return consequent.merge(alternate)

    def _eval_unary(self, node, scope):
        argument = self.eval_expression(node["argument"], scope)
        if argument.constant and node["operator"] in (
            "-", "+", "!", "~", "typeof", "void"
        ):
            try:
                const_value = self._apply_unary(node["operator"],
                                                argument.const_value)
                return Value(constant=True, const_value=const_value,
                             kind="literal")
            except (TypeError, ValueError):
                pass
        return Value(origins=[o.clone() for o in argument.origins])

    def _eval_update(self, node, scope):
        argument = self.eval_expression(node["argument"], scope)
        return Value(origins=[o.clone() for o in argument.origins])

    @staticmethod
    def _fold(left, right, operator):
        try:
            if operator == "+":
                return left + right
            if operator == "-":
                return left - right
            if operator == "*":
                return left * right
            if operator == "/":
                return left / right
            if operator == "%":
                return left % right
        except TypeError:
            return None
        return None

    @staticmethod
    def _apply_unary(operator, const_value):
        if operator == "-":
            return -const_value
        if operator == "+":
            return +const_value
        if operator == "!":
            return not const_value
        if operator == "~":
            return ~const_value
        if operator == "typeof":
            return type(const_value).__name__
        return None

    def _eval_sequence(self, node, scope):
        result = Value()
        for expression in node["expressions"]:
            result = self.eval_expression(expression, scope)
        return result

    def _eval_arrow_function(self, node, scope):
        return Value(kind="function", function=(node, scope), name="arrow")

    def _eval_function_expression(self, node, scope):
        return Value(kind="function", function=(node, scope),
                     name=node.get("name"))

    def _chain(self, node):
        """Return dotted member chain as list of names / literal keys."""
        parts = []
        current = node
        while current["type"] == "member":
            if current["computed"]:
                key = current["property"]
                if key["type"] == "literal":
                    parts.append(str(key["value"]))
                else:
                    parts.append(None)
            else:
                parts.append(current["property"])
            current = current["object"]
        if current["type"] == "identifier":
            parts.append(current["name"])
            parts.reverse()
            return parts
        parts.reverse()
        return [None] + parts

    def _eval_member(self, node, scope):
        chain = self._chain(node)
        source = self._match_member_source(chain, node, scope)
        if source is not None:
            return source
        object_value = self.eval_expression(node["object"], scope)
        key = self._member_key(node, scope)
        if key is not None and key in object_value.members:
            member = object_value.members[key].with_step(
                self.origin_file or self.file, node["line"])
            return member
        if object_value.tainted:
            return object_value.with_step(self.origin_file or self.file,
                                          node["line"])
        return Value()

    def _member_key(self, node, scope):
        if not node["computed"]:
            return node["property"]
        key_node = node["property"]
        if key_node["type"] == "literal":
            return str(key_node["value"])
        key_value = self.eval_expression(key_node, scope)
        if key_value.constant:
            return str(key_value.const_value)
        return None

    def _match_member_source(self, chain, node, scope):
        file_name = self.origin_file or self.file
        line = self.mapped_line(node["line"])
        col = node["col"]
        if chain and chain[0] == "location" and len(chain) >= 2:
            label = source_catalog.LOCATION_SOURCES.get(chain[1])
            if label:
                return self._make_source(label, file_name, line, col)
        if chain and chain[0] == "window" and len(chain) >= 3 and chain[1] == "location":
            label = source_catalog.LOCATION_SOURCES.get(chain[2])
            if label:
                return self._make_source(label, file_name, line, col)
        if len(chain) >= 2 and chain[0] == "document":
            label = source_catalog.DOCUMENT_PROPERTY_SOURCES.get(chain[1])
            if label:
                return self._make_source(label, file_name, line, col)
        if len(chain) >= 2 and chain[0] in ("window", "document") and chain[1] == "location":
            label = source_catalog.LOCATION_SOURCES.get(chain[2] if len(chain) > 2 else "href")
            if label:
                return self._make_source(label, file_name, line, col)
        if self._is_event_data(chain, scope):
            return self._make_source(source_catalog.EVENT_DATA, file_name, line, col)
        return None

    def _is_event_data(self, chain, scope):
        if not chain or len(chain) < 2 or chain[-1] != "data":
            return False
        base = chain[0]
        if base in source_catalog.EVENT_DATA_PARAM_NAMES:
            return True
        value = scope.lookup(base) if base else None
        return bool(value and value.name in source_catalog.EVENT_DATA_PARAM_NAMES)

    def _make_source(self, label, file_name, line, col):
        origin = Origin(label, file_name, line, col)
        self.source_occurrences.append(origin.to_dict())
        return Value(origins=[origin])

    def _eval_assignment(self, node, scope):
        operator = node["operator"]
        right = self.eval_expression(node["right"], scope)
        left = node["left"]
        if left["type"] == "identifier":
            if operator == "=":
                scope.assign(left["name"], right)
                return right
            existing = self.eval_expression(left, scope)
            merged = self._compound(existing, right, operator)
            scope.assign(left["name"], merged)
            return merged
        if left["type"] == "member":
            return self._assign_member(left, right, operator, node, scope)
        return right

    def _compound(self, existing, right, operator):
        origins = [o.clone() for o in existing.origins]
        origins.extend(o.clone() for o in right.origins)
        if operator == "=":
            return right
        return Value(origins=origins)

    def _assign_member(self, left, right, operator, assignment_node, scope):
        chain = self._chain(left)
        # innerHTML / outerHTML style HTML sinks
        if chain and chain[-1] in sink_catalog.HTML_PROPERTY_SINKS:
            sink_type = sink_catalog.HTML_PROPERTY_SINKS[chain[-1]]
            self.add_finding(sink_type, left, right.origins)
        # location.href = ... / location = ... / document.location = ...
        if self._is_location_assignment(chain):
            self.add_finding(sink_catalog.LOCATION_PROPERTY_SINKS["href"],
                             left, right.origins)
        object_value = self.eval_expression(left["object"], scope)
        key = self._member_key(left, scope)
        if key is not None:
            if operator == "=":
                object_value.members[key] = right
            else:
                current = object_value.members.get(key, Value())
                object_value.members[key] = self._compound(
                    current, right, operator)
        return right

    @staticmethod
    def _is_location_assignment(chain):
        if not chain:
            return False
        if chain[-1] == "location":
            return True
        if len(chain) >= 2 and chain[-2] == "location" and chain[-1] == "href":
            return True
        if len(chain) >= 3 and chain[-2:] == ["location", "href"]:
            return True
        return False

    def _eval_call(self, node, scope):
        chain = self._chain(node["callee"]) if node["callee"]["type"] == "member" else None
        argument_values = [self.eval_expression(arg, scope)
                           for arg in node["arguments"]]
        # Source calls first.
        source_value = self._match_call_source(node, chain, argument_values, scope)
        if source_value is not None:
            return source_value
        # Sink calls.
        self._check_call_sink(node, chain, argument_values, scope)
        # User function call.
        callee_value = self.eval_expression(node["callee"], scope)
        if callee_value.function is not None:
            return self._invoke_function(callee_value, argument_values, node)
        if chain and chain[-1] in PASSTHROUGH_METHODS:
            base = self.eval_expression(node["callee"]["object"], scope)
            origins = [o.clone() for o in base.origins]
            for argument in argument_values:
                origins.extend(o.clone() for o in argument.origins)
            return Value(origins=origins)
        result_origins = []
        for argument in argument_values:
            result_origins.extend(o.clone() for o in argument.origins)
        return Value(origins=result_origins)

    def _match_call_source(self, node, chain, argument_values, scope):
        if not chain:
            return None
        file_name = self.origin_file or self.file
        line = self.mapped_line(node["line"])
        col = node["col"]
        # localStorage.getItem("k")
        if len(chain) >= 2 and chain[-2] == "localStorage" and chain[-1] == "getItem":
            return self._make_source(source_catalog.LOCAL_STORAGE_GET_ITEM,
                                    file_name, line, col)
        # new URLSearchParams(...).get(...)
        if chain[-1] in source_catalog.URL_PARAM_METHODS:
            receiver = node["callee"]["object"]
            receiver_chain = self._chain(receiver) if receiver["type"] in (
                "member", "identifier", "new") else []
            if self._is_url_search_params(receiver, receiver_chain):
                label = source_catalog.URL_PARAM_METHODS[chain[-1]]
                receiver_value = self.eval_expression(receiver, scope)
                if receiver_value.origins:
                    # Propagate the upstream untrusted origin while labelling
                    # this read as a URLSearchParams source step.
                    origin = Origin(label, file_name, line, col,
                                    path=[
                                        {"file": o.file, "line": o.line}
                                        for o in receiver_value.origins
                                    ] + [{"file": file_name, "line": line}])
                    self.source_occurrences.append(origin.to_dict())
                    return Value(origins=[origin])
                return Value()
        return None

    def _is_url_search_params(self, receiver, chain):
        if receiver["type"] == "new":
            callee_chain = self._chain(receiver["callee"]) if receiver["callee"]["type"] in (
                "member", "identifier") else []
            if callee_chain and callee_chain[-1] == "URLSearchParams":
                return True
        if chain and chain[-1] == "URLSearchParams":
            return True
        value = self.eval_expression(receiver, self._current_scope)
        return bool(value and value.name == "URLSearchParams")

    def _check_call_sink(self, node, chain, argument_values, scope):
        callee = node["callee"]
        # Bare eval(...)
        if callee["type"] == "identifier" and callee["name"] in (
            "eval",
        ):
            self._report_string_sink("eval", node, argument_values, index=0)
            return
        # setTimeout / setInterval with string first argument
        if callee["type"] == "identifier" and callee["name"] in (
            "setTimeout", "setInterval",
        ):
            self._report_string_sink(callee["name"], node, argument_values, 0)
            return
        if not chain:
            return
        name = chain[-1]
        if name == "addEventListener":
            self._summarize_event_listener(node, argument_values, scope)
            return
        if name in ("setTimeout", "setInterval"):
            self._report_string_sink(name, node, argument_values, 0)
            return
        if name == "eval":
            self._report_string_sink("eval", node, argument_values, 0)
            return
        if name == "insertAdjacentHTML":
            self._report_string_sink("insertAdjacentHTML", node,
                                    argument_values, 1 if len(argument_values) > 1 else 0)
            return
        if name in ("write", "writeln") and self._receiver_is(chain, "document"):
            for index, value in enumerate(argument_values):
                self._report_string_sink("document.write", node,
                                         argument_values, index)
            return
        if name == "open" and self._receiver_is(chain, "window"):
            if argument_values:
                self._report_string_sink("window.open", node, argument_values, 0)
            return
        if name == "postMessage" and self._receiver_is_parent(chain):
            if argument_values:
                self._report_string_sink("postMessage", node, argument_values, 0)
            return

    @staticmethod
    def _receiver_is(chain, receiver_name):
        return len(chain) >= 2 and chain[0] in (receiver_name, "window") or (
            len(chain) >= 2 and chain[-2] == receiver_name)

    @staticmethod
    def _receiver_is_parent(chain):
        if len(chain) < 2:
            return False
        if chain[0] == "parent" or chain[0] == "top":
            return True
        if chain[:2] == ["window", "parent"] or chain[:2] == ["window", "top"]:
            return True
        return False

    def _report_string_sink(self, sink_type, node, argument_values, index):
        if index >= len(argument_values):
            return
        value = argument_values[index]
        # Only dynamic (non-literal) string arguments are dangerous. A constant
        # string is treated as safe.
        if value.constant and not value.tainted:
            return
        if value.origins:
            self.add_finding(sink_type, node, value.origins)

    def _summarize_event_listener(self, node, argument_values, scope):
        if len(argument_values) < 2:
            return
        callback = node["arguments"][1]
        if callback["type"] not in ("function_expression", "arrow_function"):
            return
        params = callback.get("params", [])
        local = Scope(scope)
        if params:
            event_name = params[0]
            origin = Origin(source_catalog.EVENT_DATA,
                            self.origin_file or self.file,
                            self.mapped_line(callback["line"]), callback["col"])
            event_value = Value(origins=[origin], name=event_name)
            local.declare(event_name, event_value)
        body = callback.get("body")
        if body is None:
            return
        if body["type"] == "block":
            for statement in body["body"]:
                self.exec_statement(statement, local)
        else:
            self.eval_expression(body, local)

    def _eval_new(self, node, scope):
        argument_values = [self.eval_expression(arg, scope)
                           for arg in node["arguments"]]
        chain = self._chain(node["callee"]) if node["callee"]["type"] in (
            "member", "identifier") else []
        if chain and chain[-1] == sink_catalog.FUNCTION_CONSTRUCTOR:
            # new Function("body") — last argument is the function body.
            if argument_values:
                body_value = argument_values[-1]
                if body_value.origins:
                    self.add_finding(sink_catalog.FUNCTION_CONSTRUCTOR_SINK,
                                     node, body_value.origins)
            return Value(name="Function")
        if chain and chain[-1] == "URLSearchParams":
            value = Value(kind="object", name="URLSearchParams")
            for argument in argument_values:
                for origin in argument.origins:
                    value.origins.append(origin.clone())
            return value
        callee_value = self.eval_expression(node["callee"], scope)
        if callee_value.function is not None:
            return self._invoke_function(callee_value, argument_values, node)
        origins = []
        for argument in argument_values:
            origins.extend(o.clone() for o in argument.origins)
        return Value(origins=origins, name=chain[-1] if chain else None)

    def _invoke_function(self, callee_value, argument_values, call_node):
        function_node, closure_scope = callee_value.function
        identity = id(function_node)
        self._function_identities[identity] = (function_node, closure_scope)
        origin_signature = tuple(
            tuple(o.key() for o in value.origins) for value in argument_values
        )
        recorded = self._observed_calls.setdefault(identity, [])
        if origin_signature and origin_signature not in recorded:
            recorded.append(origin_signature)
        if self.call_depth >= MAX_CALL_DEPTH:
            origins = []
            for value in argument_values:
                origins.extend(o.clone() for o in value.origins)
            return Value(origins=origins)
        params = function_node.get("params", [])
        local = Scope(closure_scope)
        for index, param in enumerate(params):
            if index < len(argument_values):
                local.declare(param, argument_values[index].with_step(
                    self.origin_file or self.file, call_node["line"]))
            else:
                local.declare(param, Value())
        previous_depth = self.call_depth
        self.call_depth += 1
        return_value = Value()
        body = function_node.get("body")
        if body is not None and body["type"] == "block":
            for statement in body["body"]:
                self.exec_statement(statement, local)
                if statement["type"] == "return" and statement["argument"] is not None:
                    return_value = self.eval_expression(statement["argument"], local)
                    break
        elif body is not None:
            return_value = self.eval_expression(body, local)
        self.call_depth = previous_depth
        return return_value.with_step(self.origin_file or self.file,
                                      call_node["line"])

    # ----- module-level statements -----------------------------------
    def _stmt_import(self, node, scope):
        if not node["source"]:
            return
        exports = self.engine.resolve_module(self.file, node["source"])
        if exports is None:
            return
        if node["default"] and "default" in exports:
            scope.declare(node["default"], exports["default"].copy())
        if node["namespace"]:
            namespace = Value(kind="object")
            for name, value in exports.items():
                namespace.members[name] = value.copy()
            scope.declare(node["namespace"], namespace)
        for imported, local in node["named"]:
            if imported in exports:
                scope.declare(local, exports[imported].copy())

    def _stmt_export_named(self, node, scope):
        declaration = node.get("declaration")
        if declaration is not None:
            self.exec_statement(declaration, scope)
            if declaration["type"] == "var_declaration":
                for declarator in declaration["declarations"]:
                    value = scope.lookup(declarator["name"])
                    if value is not None:
                        self.engine.record_export(self.file, declarator["name"],
                                                  value)
            elif declaration["type"] == "function_declaration":
                value = scope.lookup(declaration["name"])
                if value is not None:
                    self.engine.record_export(self.file, declaration["name"],
                                              value)
        else:
            source = node.get("source")
            if source:
                foreign = self.engine.resolve_module(self.file, source)
                if foreign:
                    for local, exported in node["names"]:
                        if local in foreign:
                            self.engine.record_export(self.file, exported,
                                                      foreign[local])
            else:
                for local, exported in node["names"]:
                    value = scope.lookup(local)
                    if value is not None:
                        self.engine.record_export(self.file, exported, value)

    def _stmt_export_default(self, node, scope):
        declaration = node["declaration"]
        if declaration["type"] == "function_declaration":
            self.exec_statement(declaration, scope)
            value = scope.lookup(declaration["name"])
        else:
            value = self.eval_expression(declaration["expression"], scope)
        if value is not None:
            self.engine.record_export(self.file, "default", value)

    def _stmt_export_all(self, node, scope):
        exports = self.engine.resolve_module(self.file, node["source"])
        if not exports:
            return
        for name, value in exports.items():
            if name != "default":
                self.engine.record_export(self.file, name, value)


class ModuleEngine:
    """Owns module parsing, export tables and cross-file taint propagation."""

    def __init__(self):
        self.modules = {}  # absolute path -> {"ast", "exports", "findings"}
        self.analyzing = set()

    def analyze_file(self, path, source=None):
        path = os.path.abspath(path)
        if path in self.modules:
            return self.modules[path]
        if source is None:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        try:
            ast = parse(source)
        except JSSyntaxError:
            self.modules[path] = {"ast": None, "exports": {},
                                  "findings": [], "sources": []}
            return self.modules[path]
        record = {"ast": ast, "exports": {}, "findings": [], "sources": []}
        self.modules[path] = record
        self.analyzing.add(path)
        analyzer = Analyzer(path, self)
        try:
            record["findings"] = analyzer.analyze(ast)
            record["sources"] = analyzer.source_occurrences
        finally:
            self.analyzing.discard(path)
        return record

    def analyze_inline(self, host_file, source, line_offset=0):
        """Analyze an inline <script> and prefix findings with host lines."""
        try:
            ast = parse(source)
        except JSSyntaxError:
            return [], []
        analyzer = Analyzer(host_file, self, origin_file=host_file,
                            line_offset=line_offset)
        findings = analyzer.analyze(ast)
        return findings, analyzer.source_occurrences

    def analyze_handler(self, host_file, source, line_offset=0):
        """Analyze an inline event handler expression."""
        try:
            expression = parse_expression(source)
        except JSSyntaxError:
            return [], [], Value()
        analyzer = Analyzer(host_file, self, origin_file=host_file,
                            line_offset=line_offset)
        value = analyzer.eval_expression(expression, analyzer.global_scope)
        return analyzer.findings, analyzer.source_occurrences, value

    def record_export(self, importer_file, name, value):
        path = os.path.abspath(importer_file)
        record = self.modules.setdefault(path, {"ast": None, "exports": {},
                                                "findings": [], "sources": []})
        record.setdefault("exports", {})[name] = value.copy()

    def resolve_module(self, importer_file, specifier):
        if not specifier.startswith("."):
            return None
        base_dir = os.path.dirname(os.path.abspath(importer_file))
        candidate = os.path.normpath(os.path.join(base_dir, specifier))
        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.js")
        if not os.path.splitext(candidate)[1]:
            for suffix in (".js", ".mjs"):
                if os.path.exists(candidate + suffix):
                    candidate = candidate + suffix
                    break
        if not os.path.exists(candidate):
            return None
        candidate = os.path.abspath(candidate)
        if candidate in self.analyzing:
            return self.modules.get(candidate, {}).get("exports", {})
        record = self.analyze_file(candidate)
        return record.get("exports", {})


def scan_js_file(path, engine=None):
    engine = engine or ModuleEngine()
    record = engine.analyze_file(path)
    return record["findings"], engine
