"""A small, dependency-free JavaScript tokenizer and parser.

Supports the ES subset needed for static taint analysis: variable / function
declarations, control flow, arrow functions, ES module import/export,
template literals, member and call expressions. Every AST node carries
1-based ``line`` / ``col`` positions of its first token.
"""

import re


class JSSyntaxError(Exception):
    """Raised when input cannot be parsed."""


KEYWORDS = {
    "var", "let", "const", "function", "return", "if", "else", "for",
    "while", "do", "switch", "case", "default", "break", "continue",
    "new", "delete", "typeof", "void", "instanceof", "in", "of", "this",
    "true", "false", "null", "undefined", "try", "catch", "finally",
    "throw", "class", "extends", "super", "import", "export", "from",
    "as", "async", "await", "yield", "with", "static", "get", "set",
}

PUNCTUATORS = sorted(set([
    "...", "===", "!==", "==", "!=", "<=", ">=", "&&", "||", "??",
    "**", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "=>", "?.",
    "(", ")", "{", "}", "[", "]", ".", ",", ";", ":", "?", "=",
    "+", "-", "*", "/", "%", "<", ">", "!", "&", "|", "^", "~",
]), key=len, reverse=True)

NUMBER_RE = re.compile(
    r"0[xX][0-9a-fA-F_]+|0[oO][0-7_]+|0[bB][01_]+|"
    r"(?:\d[\d_]*\.?\d*|\.\d[\d_]*)(?:[eE][+-]?\d+)?"
)


class Tokenizer:
    def __init__(self, text):
        self.text = text
        self.length = len(text)
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens = []

    def _advance(self, count=1):
        chunk = self.text[self.pos:self.pos + count]
        for char in chunk:
            if char == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
        self.pos += count

    def _peek(self, offset=0):
        index = self.pos + offset
        if index >= self.length:
            return ""
        return self.text[index]

    def _emit(self, kind, value, line, col):
        self.tokens.append({"type": kind, "value": value, "line": line,
                            "col": col})

    def _skip_ws_comments(self):
        while self.pos < self.length:
            char = self._peek()
            if char in " \t\r\n":
                self._advance()
            elif char == "/" and self._peek(1) == "/":
                while self.pos < self.length and self._peek() != "\n":
                    self._advance()
            elif char == "/" and self._peek(1) == "*":
                self._advance(2)
                while self.pos < self.length and not (
                    self._peek() == "*" and self._peek(1) == "/"
                ):
                    self._advance()
                if self.pos < self.length:
                    self._advance(2)
            else:
                break

    def _read_string(self, quote):
        line, col = self.line, self.col
        self._advance()
        chars = []
        while self.pos < self.length and self._peek() != quote:
            char = self._peek()
            if char == "\\":
                chars.append(self.text[self.pos:self.pos + 2])
                self._advance(2 if self._peek(1) else 1)
            elif char == "\n":
                raise JSSyntaxError("unterminated string")
            else:
                chars.append(char)
                self._advance()
        self._advance()
        self._emit("string", self._decode_string("".join(chars)), line, col)

    @staticmethod
    def _decode_string(raw):
        try:
            return bytes(raw, "utf-8").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return raw

    def _read_template(self):
        start_line, start_col = self.line, self.col
        self._advance()
        parts = []
        buffer = []
        while self.pos < self.length:
            char = self._peek()
            if char == "\\":
                buffer.append(self.text[self.pos:self.pos + 2])
                self._advance(2 if self._peek(1) else 1)
            elif char == "`":
                self._advance()
                parts.append(("str", "".join(buffer)))
                self._emit("template", {"parts": parts}, start_line,
                           start_col)
                return
            elif char == "$" and self._peek(1) == "{":
                parts.append(("str", "".join(buffer)))
                buffer = []
                self._advance(2)
                depth = 1
                expr = []
                while self.pos < self.length and depth:
                    inner = self._peek()
                    if inner == "{":
                        depth += 1
                    elif inner == "}":
                        depth -= 1
                        if depth == 0:
                            self._advance()
                            break
                    expr.append(inner)
                    self._advance()
                parts.append(("expr", "".join(expr)))
            else:
                buffer.append(char)
                self._advance()
        raise JSSyntaxError("unterminated template literal")

    def _read_regex(self):
        line, col = self.line, self.col
        self._advance()
        in_class = False
        pattern = []
        while self.pos < self.length:
            char = self._peek()
            if char == "\\":
                pattern.append(self.text[self.pos:self.pos + 2])
                self._advance(2 if self._peek(1) else 1)
                continue
            if char == "\n":
                raise JSSyntaxError("unterminated regex")
            if char == "[":
                in_class = True
            elif char == "]":
                in_class = False
            elif char == "/" and not in_class:
                self._advance()
                break
            pattern.append(char)
            self._advance()
        flags = []
        while self.pos < self.length and self._peek().isalpha():
            flags.append(self._peek())
            self._advance()
        self._emit("regex", "".join(pattern) + "/" + "".join(flags),
                   line, col)

    def tokenize(self):
        previous = None
        while True:
            self._skip_ws_comments()
            if self.pos >= self.length:
                break
            line, col = self.line, self.col
            char = self._peek()
            if char in "'\"":
                self._read_string(char)
            elif char == "`":
                self._read_template()
            elif char.isalpha() or char in "_$":
                start = self.pos
                while self.pos < self.length and (
                    self._peek().isalnum() or self._peek() in "_$"
                ):
                    self._advance()
                value = self.text[start:self.pos]
                self._emit("name", value, line, col)
            elif char.isdigit() or (char == "." and self._peek(1).isdigit()):
                match = NUMBER_RE.match(self.text, self.pos)
                if not match:
                    raise JSSyntaxError("bad number at %d:%d" % (line, col))
                value = match.group(0)
                self._advance(len(value))
                self._emit("number", value, line, col)
            else:
                for punct in PUNCTUATORS:
                    if self.text.startswith(punct, self.pos):
                        if punct == "/" and self._regex_allowed(previous):
                            self._read_regex()
                            previous = self.tokens[-1]
                            break
                        self._advance(len(punct))
                        self._emit("punct", punct, line, col)
                        break
                else:
                    self._advance()
                    self._emit("punct", char, line, col)
            previous = self.tokens[-1]
        self._emit("eof", "", self.line, self.col)
        return self.tokens

    @staticmethod
    def _regex_allowed(previous):
        if previous is None:
            return True
        if previous["type"] in ("string", "number", "regex", "template"):
            return False
        if previous["type"] == "name" and previous["value"] not in KEYWORDS:
            return False
        if previous["type"] == "punct" and previous["value"] in (")", "]"):
            return False
        if previous["type"] == "name" and previous["value"] in (
            "this", "true", "false", "null", "undefined", "super",
        ):
            return False
        return True


def tokenize(source):
    return Tokenizer(source).tokenize()


class Node(dict):
    """AST node behaving both as a mapping and an attribute object."""

    def __init__(self, node_kind, line, col, **fields):
        super().__init__(type=node_kind, line=line, col=col, **fields)

    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


ASSIGN_OPS = {
    "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**=",
}


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.index = 0

    @property
    def current(self):
        return self.tokens[self.index]

    def advance(self):
        token = self.tokens[self.index]
        if token["type"] != "eof":
            self.index += 1
        return token

    def check(self, kind, value=None):
        token = self.current
        if token["type"] != kind:
            return False
        return value is None or token["value"] == value

    def match(self, kind, value=None):
        if self.check(kind, value):
            self.advance()
            return True
        return False

    def expect(self, kind, value=None):
        if not self.check(kind, value):
            token = self.current
            raise JSSyntaxError(
                "expected %s %r got %r at %d:%d" % (
                    kind, value, token["value"], token["line"], token["col"])
            )
        return self.advance()

    def parse_program(self):
        body = []
        while not self.check("eof"):
            body.append(self.parse_statement())
        return Node("program", 1, 1, body=body)

    def parse_statement(self):
        token = self.current
        if token["type"] == "punct" and token["value"] == "{":
            return self.parse_block()
        if token["type"] == "punct" and token["value"] == ";":
            self.advance()
            return Node("empty", token["line"], token["col"])
        if token["type"] != "name":
            expression = self.parse_expression()
            self.match("punct", ";")
            return Node("expression", expression["line"], expression["col"],
                        expression=expression)
        value = token["value"]
        if value in ("var", "let", "const"):
            return self.parse_var_declaration()
        if value == "function":
            return self.parse_function_declaration()
        if value == "class":
            return self.parse_class()
        if value == "return":
            self.advance()
            argument = None
            if not (self.check("punct", ";") or self.check("punct", "}")):
                argument = self.parse_expression()
            self.match("punct", ";")
            return Node("return", token["line"], token["col"],
                        argument=argument)
        if value == "if":
            return self.parse_if()
        if value in ("for", "while", "do"):
            return self.parse_loop(value)
        if value == "try":
            return self.parse_try()
        if value == "throw":
            self.advance()
            argument = self.parse_expression()
            self.match("punct", ";")
            return Node("throw", token["line"], token["col"],
                        argument=argument)
        if value in ("break", "continue"):
            self.advance()
            self.match("punct", ";")
            return Node(value, token["line"], token["col"])
        if value == "switch":
            return self.parse_switch()
        if value == "import":
            return self.parse_import()
        if value == "export":
            return self.parse_export()
        if value in ("async",) and self.peek(1).get("value") == "function":
            return self.parse_function_declaration()
        expression = self.parse_expression()
        self.match("punct", ";")
        return Node("expression", expression["line"], expression["col"],
                    expression=expression)

    def parse_block(self):
        token = self.expect("punct", "{")
        body = []
        while not self.check("punct", "}") and not self.check("eof"):
            body.append(self.parse_statement())
        self.expect("punct", "}")
        return Node("block", token["line"], token["col"], body=body)

    def parse_var_declaration(self, terminate=True):
        keyword = self.advance()
        declarations = []
        while True:
            name_token = self.expect("name")
            init = None
            if self.match("punct", "="):
                init = self.parse_assignment()
            declarations.append(Node(
                "declarator", name_token["line"], name_token["col"],
                name=name_token["value"], init=init))
            if not self.match("punct", ","):
                break
        if terminate:
            self.match("punct", ";")
        return Node("var_declaration", keyword["line"], keyword["col"],
                    kind=keyword["value"], declarations=declarations)

    def parse_function_params(self):
        self.expect("punct", "(")
        params = []
        while not self.check("punct", ")"):
            if self.match("punct", "..."):
                pass
            token = self.expect("name")
            params.append(token["value"])
            if not self.match("punct", ","):
                break
        self.expect("punct", ")")
        return params

    def parse_function_body(self):
        return self.parse_block()

    def parse_function_declaration(self):
        token = self.advance()  # function (async handled by caller)
        if token["value"] == "async":
            token = self.expect("name", "function")
        name = None
        if self.check("name"):
            name = self.advance()["value"]
        params = self.parse_function_params()
        body = self.parse_function_body()
        return Node("function_declaration", token["line"], token["col"],
                    name=name, params=params, body=body)

    def parse_function_expression(self, token):
        if self.match("name", "function"):
            token = self.current
        name = None
        if self.check("name"):
            name = self.advance()["value"]
        params = self.parse_function_params()
        body = self.parse_function_body()
        return Node("function_expression", token["line"], token["col"],
                    name=name, params=params, body=body)

    def parse_class(self):
        token = self.advance()
        if self.check("name"):
            self.advance()
        if self.check("name", "extends"):
            self.advance()
            self.parse_left_hand_side()
        self.expect("punct", "{")
        while not self.check("punct", "}") and not self.check("eof"):
            if self.check("punct", ";"):
                self.advance()
                continue
            if self.check("name") and self.current["value"] in (
                "static", "get", "set", "async"
            ):
                self.advance()
            if self.check("name", "function"):
                self.advance()
            if self.check("name"):
                self.advance()
            if self.check("punct", "?"):
                self.advance()
            if self.check("punct", "("):
                self.parse_function_params()
                self.parse_block()
            else:
                while not self.check("punct", ";") and not self.check("eof"):
                    self.advance()
                self.match("punct", ";")
        self.expect("punct", "}")
        return Node("class_declaration", token["line"], token["col"])

    def parse_if(self):
        token = self.advance()
        self.expect("punct", "(")
        test = self.parse_expression()
        self.expect("punct", ")")
        consequent = self.parse_statement()
        alternate = None
        if self.match("name", "else"):
            alternate = self.parse_statement()
        return Node("if", token["line"], token["col"], test=test,
                    consequent=consequent, alternate=alternate)

    def parse_loop(self, kind):
        token = self.advance()
        if kind == "do":
            body = self.parse_statement()
            self.expect("name", "while")
            self.expect("punct", "(")
            test = self.parse_expression()
            self.expect("punct", ")")
            self.match("punct", ";")
            return Node("do_while", token["line"], token["col"], body=body,
                        test=test)
        self.expect("punct", "(")
        init = None
        if not self.check("punct", ";"):
            if self.check("name") and self.current["value"] in (
                "var", "let", "const"
            ):
                init = self.parse_var_declaration(terminate=False)
            else:
                init = self.parse_expression()
        if kind == "for" and self.check("name") and self.current["value"] in (
            "in", "of"
        ):
            operator = self.advance()["value"]
            right = self.parse_expression()
            self.expect("punct", ")")
            body = self.parse_statement()
            return Node("for_in_of", token["line"], token["col"],
                        operator=operator, left=init, right=right, body=body)
        self.expect("punct", ";")
        test = None
        if not self.check("punct", ";") and not self.check("punct", ")"):
            test = self.parse_expression()
        self.expect("punct", ";")
        update = None
        if not self.check("punct", ")"):
            update = self.parse_expression()
        self.expect("punct", ")")
        body = self.parse_statement()
        return Node("for", token["line"], token["col"], init=init, test=test,
                    update=update, body=body)

    def parse_try(self):
        token = self.advance()
        block = self.parse_block()
        handler = None
        if self.match("name", "catch"):
            param = None
            if self.match("punct", "("):
                if self.check("name"):
                    param = self.advance()["value"]
                self.expect("punct", ")")
            catch_body = self.parse_block()
            handler = Node("catch_clause", token["line"], token["col"],
                           param=param, body=catch_body)
        finalizer = None
        if self.match("name", "finally"):
            finalizer = self.parse_block()
        return Node("try", token["line"], token["col"], block=block,
                    handler=handler, finalizer=finalizer)

    def parse_switch(self):
        token = self.advance()
        self.expect("punct", "(")
        discriminant = self.parse_expression()
        self.expect("punct", ")")
        self.expect("punct", "{")
        cases = []
        while not self.check("punct", "}") and not self.check("eof"):
            case_token = self.advance()  # case or default
            test = None
            if case_token["value"] == "case":
                test = self.parse_expression()
            self.expect("punct", ":")
            body = []
            while not self.check("punct", "}") and not (
                self.check("name") and self.current["value"] in ("case", "default")
            ):
                body.append(self.parse_statement())
            cases.append(Node("case", case_token["line"], case_token["col"],
                              test=test, body=body))
        self.expect("punct", "}")
        return Node("switch", token["line"], token["col"],
                    discriminant=discriminant, cases=cases)

    # ----- modules ----------------------------------------------------
    def parse_import(self):
        token = self.advance()  # import
        default_name = None
        named = []
        namespace = None
        if self.check("name") and self.current["value"] != "from":
            default_name = self.advance()["value"]
            self.match("punct", ",")
        if self.match("punct", "*"):
            self.expect("name", "as")
            namespace = self.expect("name")["value"]
        elif self.check("punct", "{"):
            self.advance()
            while not self.check("punct", "}"):
                imported = self.expect("name")["value"]
                local = imported
                if self.match("name", "as"):
                    local = self.expect("name")["value"]
                named.append((imported, local))
                if not self.match("punct", ","):
                    break
            self.expect("punct", "}")
        source = None
        if self.match("name", "from"):
            source = self.expect("string")["value"]
        elif self.check("string"):
            source = self.advance()["value"]
        self.match("punct", ";")
        return Node("import", token["line"], token["col"], source=source,
                    default=default_name, named=named, namespace=namespace)

    def parse_export(self):
        token = self.advance()  # export
        if self.match("name", "default"):
            if self.check("name", "function"):
                declaration = self.parse_function_declaration()
            else:
                expression = self.parse_assignment()
                self.match("punct", ";")
                declaration = Node("expression", expression["line"],
                                   expression["col"], expression=expression)
            return Node("export_default", token["line"], token["col"],
                        declaration=declaration)
        if self.check("name", "function"):
            declaration = self.parse_function_declaration()
            return Node("export_named", token["line"], token["col"],
                        declaration=declaration, names=[])
        if self.check("name") and self.current["value"] in ("var", "let", "const"):
            declaration = self.parse_var_declaration()
            return Node("export_named", token["line"], token["col"],
                        declaration=declaration, names=[])
        if self.match("punct", "*"):
            self.expect("name", "as")
            alias = self.expect("name")["value"]
            source = None
            if self.match("name", "from"):
                source = self.expect("string")["value"]
            self.match("punct", ";")
            return Node("export_all", token["line"], token["col"],
                        alias=alias, source=source)
        self.expect("punct", "{")
        names = []
        while not self.check("punct", "}"):
            local = self.expect("name")["value"]
            exported = local
            if self.match("name", "as"):
                exported = self.expect("name")["value"]
            names.append((local, exported))
            if not self.match("punct", ","):
                break
        self.expect("punct", "}")
        source = None
        if self.match("name", "from"):
            source = self.expect("string")["value"]
        self.match("punct", ";")
        return Node("export_named", token["line"], token["col"],
                    declaration=None, names=names, source=source)

    # ----- expressions ------------------------------------------------
    def parse_expression(self):
        expression = self.parse_assignment()
        while self.check("punct", ","):
            token = self.advance()
            right = self.parse_assignment()
            expression = Node("sequence", token["line"], token["col"],
                              expressions=[expression, right])
        return expression

    def parse_assignment(self):
        if self.check("name", "async") and self.peek(1).get("value") == "function":
            return self.parse_function_expression(self.advance())
        left = self.parse_conditional()
        if self.check("punct") and self.current["value"] in ASSIGN_OPS:
            token = self.advance()
            right = self.parse_assignment()
            return Node("assignment", token["line"], token["col"],
                        operator=token["value"], left=left, right=right)
        return left

    def parse_conditional(self):
        test = self.parse_binary(0)
        if self.match("punct", "?"):
            token = self.tokens[self.index - 1]
            consequent = self.parse_assignment()
            self.expect("punct", ":")
            alternate = self.parse_assignment()
            return Node("conditional", token["line"], token["col"],
                        test=test, consequent=consequent, alternate=alternate)
        return test

    BINARY_PRECEDENCE = {
        "||": 1, "??": 1, "&&": 2,
        "|": 3, "^": 4, "&": 5,
        "==": 6, "!=": 6, "===": 6, "!==": 6,
        "<": 7, ">": 7, "<=": 7, ">=": 7, "instanceof": 7, "in": 7,
        "<<": 8, ">>": 8, ">>>": 8,
        "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11,
    }

    def parse_binary(self, min_precedence):
        left = self.parse_unary()
        while True:
            token = self.current
            operator = token["value"]
            precedence = self.BINARY_PRECEDENCE.get(operator)
            if precedence is None or precedence < min_precedence:
                break
            self.advance()
            right = self.parse_binary(precedence + 1)
            kind = "logical" if operator in ("&&", "||", "??") else "binary"
            left = Node(kind, token["line"], token["col"], operator=operator,
                        left=left, right=right)
        return left

    def parse_unary(self):
        token = self.current
        is_punct_op = token["type"] == "punct" and token["value"] in (
            "!", "-", "+", "~", "*")
        is_word_op = token["type"] == "name" and token["value"] in (
            "typeof", "void", "delete", "await")
        if is_punct_op or is_word_op:
            self.advance()
            argument = self.parse_unary()
            return Node("unary", token["line"], token["col"],
                        operator=token["value"], argument=argument)
        if token["type"] == "punct" and token["value"] in ("++", "--"):
            self.advance()
            argument = self.parse_unary()
            return Node("update", token["line"], token["col"],
                        operator=token["value"], prefix=True, argument=argument)
        return self.parse_postfix()

    def parse_postfix(self):
        expression = self.parse_left_hand_side()
        if self.check("punct") and self.current["value"] in ("++", "--"):
            token = self.advance()
            return Node("update", token["line"], token["col"],
                        operator=token["value"], prefix=False, argument=expression)
        return expression

    def parse_left_hand_side(self):
        expression = self.parse_new_expression()
        return self.parse_call_suffix(expression)

    def parse_new_expression(self):
        if self.check("name", "new"):
            token = self.advance()
            callee = self.parse_new_expression()
            arguments = []
            if self.check("punct", "("):
                arguments = self.parse_arguments()
            node = Node("new", token["line"], token["col"], callee=callee,
                        arguments=arguments)
            return self.parse_call_suffix(node)
        return self.parse_primary()

    def parse_call_suffix(self, expression):
        while True:
            if self.match("punct", "."):
                token = self.tokens[self.index - 1]
                property_name = self.expect("name")["value"]
                expression = Node("member", token["line"], token["col"],
                                object=expression, property=property_name,
                                computed=False)
            elif self.match("punct", "?."):
                token = self.tokens[self.index - 1]
                property_name = self.expect("name")["value"]
                expression = Node("member", token["line"], token["col"],
                                object=expression, property=property_name,
                                computed=False, optional=True)
            elif self.match("punct", "["):
                token = self.tokens[self.index - 1]
                property_expr = self.parse_expression()
                self.expect("punct", "]")
                expression = Node("member", token["line"], token["col"],
                                object=expression, property=property_expr,
                                computed=True)
            elif self.check("punct", "("):
                token = self.current
                arguments = self.parse_arguments()
                expression = Node("call", token["line"], token["col"],
                                callee=expression, arguments=arguments)
            elif self.check("name") and self.current["value"] == "=>":
                return self.parse_arrow_from_params(expression)
            else:
                return expression

    def parse_arguments(self):
        self.expect("punct", "(")
        arguments = []
        while not self.check("punct", ")"):
            self.match("punct", "...")
            arguments.append(self.parse_assignment())
            if not self.match("punct", ","):
                break
        self.expect("punct", ")")
        return arguments

    def parse_arrow_from_params(self, params_node):
        params = []
        if params_node["type"] == "identifier":
            params = [params_node["name"]]
        elif params_node["type"] == "sequence":
            params = [self._identifier_name(item)
                      for item in params_node["expressions"]]
        arrow = self.expect("punct", "=>")
        if self.check("punct", "{"):
            body = self.parse_block()
        else:
            body = self.parse_assignment()
        return Node("arrow_function", arrow["line"], arrow["col"],
                    params=[name for name in params if name], body=body)

    @staticmethod
    def _identifier_name(node):
        if node["type"] == "identifier":
            return node["name"]
        if node["type"] == "assignment" and node["left"]["type"] == "identifier":
            return node["left"]["name"]
        return None

    def parse_primary(self):
        token = self.current
        if token["type"] == "number":
            self.advance()
            return Node("literal", token["line"], token["col"],
                        value=token["value"], kind="number")
        if token["type"] == "string":
            self.advance()
            return Node("literal", token["line"], token["col"],
                        value=token["value"], kind="string")
        if token["type"] == "regex":
            self.advance()
            return Node("literal", token["line"], token["col"],
                        value=token["value"], kind="regex")
        if token["type"] == "template":
            self.advance()
            return self._template_node(token)
        if token["type"] == "punct" and token["value"] == "(":
            self.advance()
            if self.check("punct", ")"):
                self.advance()
                arrow = self.expect("punct", "=>")
                if self.check("punct", "{"):
                    body = self.parse_block()
                else:
                    body = self.parse_assignment()
                return Node("arrow_function", arrow["line"], arrow["col"],
                            params=[], body=body)
            expression = self.parse_expression()
            self.expect("punct", ")")
            if self.check("punct", "=>"):
                return self.parse_arrow_from_params(expression)
            return expression
        if token["type"] == "punct" and token["value"] == "[":
            self.advance()
            elements = []
            while not self.check("punct", "]"):
                if self.match("punct", ","):
                    elements.append(None)
                    continue
                self.match("punct", "...")
                elements.append(self.parse_assignment())
                if not self.match("punct", ","):
                    break
            self.expect("punct", "]")
            return Node("array", token["line"], token["col"], elements=elements)
        if token["type"] == "punct" and token["value"] == "{":
            return self.parse_object_literal()
        if token["type"] == "name":
            if token["value"] in ("true", "false", "null", "undefined"):
                self.advance()
                return Node("literal", token["line"], token["col"],
                            value=token["value"], kind=token["value"])
            if token["value"] == "function":
                return self.parse_function_expression(token)
            if token["value"] == "async" and self.peek(1).get("value") == "function":
                return self.parse_function_expression(token)
            if token["value"] == "this":
                self.advance()
                return Node("this", token["line"], token["col"])
            if token["value"] not in KEYWORDS:
                self.advance()
                node = Node("identifier", token["line"], token["col"],
                            name=token["value"])
                if self.check("punct", "=>"):
                    return self.parse_arrow_from_params(node)
                return node
        raise JSSyntaxError("unexpected token %r at %d:%d" % (
            token["value"], token["line"], token["col"]))

    def parse_object_literal(self):
        token = self.expect("punct", "{")
        properties = []
        while not self.check("punct", "}"):
            if self.check("name") and self.current["value"] in (
                "get", "set", "async"
            ) and self.peek(1).get("type") == "name":
                self.advance()  # method modifier
            key = self._parse_property_key()
            value = None
            if self.match("punct", ":"):
                value = self.parse_assignment()
            elif self.check("punct", "("):
                params = self.parse_function_params()
                body = self.parse_block()
                value = Node("function_expression", token["line"], token["col"],
                             name=None, params=params, body=body)
            properties.append(Node("property", key.line, key.col, key=key,
                                   value=value))
            if not self.match("punct", ","):
                break
        self.expect("punct", "}")
        return Node("object", token["line"], token["col"], properties=properties)

    def _parse_property_key(self):
        token = self.current
        if token["type"] in ("string", "number"):
            self.advance()
            return Node("literal", token["line"], token["col"],
                        value=token["value"], kind=token["type"])
        if token["type"] == "punct" and token["value"] == "[":
            self.advance()
            expression = self.parse_assignment()
            self.expect("punct", "]")
            return expression
        name = self.expect("name")["value"]
        return Node("identifier", token["line"], token["col"], name=name)

    def _template_node(self, token):
        expressions = []
        quasis = []
        for kind, content in token["value"]["parts"]:
            if kind == "str":
                quasis.append(content)
            else:
                sub_tokens = Tokenizer(content).tokenize()
                sub_parser = Parser(sub_tokens)
                expressions.append(sub_parser.parse_expression())
        return Node("template", token["line"], token["col"], quasis=quasis,
                    expressions=expressions)


def parse(source):
    """Parse a JS source string and return a program node."""
    return Parser(Tokenizer(source).tokenize()).parse_program()


def parse_expression(source):
    """Parse a standalone expression (used for inline event handlers)."""
    parser = Parser(Tokenizer(source).tokenize())
    return parser.parse_expression()
