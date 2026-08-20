#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║  VORTEX — Full-Featured Python Code Obfuscator              ║
# ║  Requires Python 3.9+ (ast.unparse)                         ║
# ║                                                              ║
# ║  Transforms applied:                                         ║
# ║    • Scope-aware identifier renaming                         ║
# ║    • XOR string encryption (injected runtime decryptor)      ║
# ║    • Integer encoding (4 strategies)                         ║
# ║    • Dead code injection (5 templates)                       ║
# ║    • Opaque predicate control flow obfuscation               ║
# ║    • Import mangling (__import__ rewrite)                    ║
# ║    • Comment + docstring stripping                           ║
# ║    • Anti-debug timing guard                                 ║
# ║    • Bytecode mode: marshal → zlib → base85 → exec()        ║
# ╚══════════════════════════════════════════════════════════════╝

from __future__ import annotations

import ast
import argparse
import base64
import marshal
import os
import random
import string
import sys
import textwrap
import zlib
from typing import Any, Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
#  1.  NAME GENERATOR
#      Collision-free obfuscated identifiers.
#      Maintains a forward map: original → obfuscated.
#      Skips builtins, dunders, and anything in PYTHON_RESERVED.
# ─────────────────────────────────────────────────────────────────────────────

class NameGenerator:
    PYTHON_RESERVED: Set[str] = {
        # Keywords
        "False", "None", "True", "and", "as", "assert", "async", "await",
        "break", "class", "continue", "def", "del", "elif", "else", "except",
        "finally", "for", "from", "global", "if", "import", "in", "is",
        "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
        "while", "with", "yield",
        # Builtins
        "__import__", "__name__", "__file__", "__doc__", "__package__",
        "__spec__", "__loader__", "__builtins__", "__debug__", "__build_class__",
        "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
        "bytes", "callable", "chr", "classmethod", "compile", "complex",
        "copyright", "credits", "delattr", "dict", "dir", "divmod", "enumerate",
        "eval", "exec", "filter", "float", "format", "frozenset", "getattr",
        "globals", "hasattr", "hash", "help", "hex", "id", "input", "int",
        "isinstance", "issubclass", "iter", "len", "license", "list", "locals",
        "map", "max", "memoryview", "min", "next", "object", "oct", "open",
        "ord", "pow", "print", "property", "quit", "range", "repr", "reversed",
        "round", "set", "setattr", "slice", "sorted", "staticmethod", "str",
        "sum", "super", "tuple", "type", "vars", "zip",
        # Common exception types
        "ArithmeticError", "AssertionError", "AttributeError", "BaseException",
        "BlockingIOError", "BrokenPipeError", "BufferError", "BytesWarning",
        "ChildProcessError", "ConnectionAbortedError", "ConnectionError",
        "ConnectionRefusedError", "ConnectionResetError", "DeprecationWarning",
        "EOFError", "EnvironmentError", "Exception", "FileExistsError",
        "FileNotFoundError", "FloatingPointError", "FutureWarning", "GeneratorExit",
        "IOError", "ImportError", "ImportWarning", "IndentationError", "IndexError",
        "InterruptedError", "IsADirectoryError", "IsADirectoryError", "KeyError",
        "KeyboardInterrupt", "LookupError", "MemoryError", "ModuleNotFoundError",
        "NameError", "NotADirectoryError", "NotImplemented", "NotImplementedError",
        "OSError", "OverflowError", "PendingDeprecationWarning", "PermissionError",
        "ProcessLookupError", "RecursionError", "ReferenceError", "ResourceWarning",
        "RuntimeError", "RuntimeWarning", "StopAsyncIteration", "StopIteration",
        "SyntaxError", "SyntaxWarning", "SystemError", "SystemExit", "TabError",
        "TimeoutError", "TypeError", "UnboundLocalError", "UnicodeDecodeError",
        "UnicodeEncodeError", "UnicodeError", "UnicodeTranslateError",
        "UnicodeWarning", "UserWarning", "ValueError", "Warning", "ZeroDivisionError",
        # Implicit names that must never be renamed
        "self", "cls", "args", "kwargs", "Ellipsis",
    }

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        self._forward: Dict[str, str] = {}
        self._used: Set[str] = set()
        self._chars = string.ascii_letters

    # ── public ────────────────────────────────────────────────────────────────

    def get(self, name: str) -> str:
        """Return the obfuscated form of *name*, creating it if necessary."""
        if self._is_safe(name):
            return name
        if name not in self._forward:
            self._forward[name] = self._fresh()
        return self._forward[name]

    def has(self, name: str) -> bool:
        return name in self._forward

    def renamed(self, name: str) -> str:
        """Return the already-mapped obfuscated name (or original if unmapped)."""
        return self._forward.get(name, name)

    def fresh(self) -> str:
        """Generate an anonymous fresh name (not linked to any original)."""
        return self._fresh()

    # ── private ───────────────────────────────────────────────────────────────

    def _is_safe(self, name: str) -> bool:
        return (
            name in self.PYTHON_RESERVED
            or (name.startswith("__") and name.endswith("__"))
        )

    def _fresh(self) -> str:
        while True:
            length = self._rng.randint(10, 20)
            candidate = "_" + "".join(self._rng.choices(self._chars, k=length)) + "_"
            if candidate not in self._used and candidate not in self.PYTHON_RESERVED:
                self._used.add(candidate)
                return candidate


# ─────────────────────────────────────────────────────────────────────────────
#  2.  SCOPE ANALYZER  (pre-pass)
#      Walks the AST before transformation.
#      Collects every name that is *stored* in a local scope — these are the
#      only names we can safely rename without breaking attribute access or
#      external module APIs.
# ─────────────────────────────────────────────────────────────────────────────

class ScopeAnalyzer(ast.NodeVisitor):
    def __init__(self, rename_globals: bool = False) -> None:
        self._rename_globals = rename_globals
        self._stack: List[Set[str]] = []   # scope stack (innermost last)
        self._renameable: Set[str] = set()

    def collect(self, tree: ast.AST) -> Set[str]:
        self.visit(tree)
        return set(self._renameable)

    # ── scope boundaries ──────────────────────────────────────────────────────

    def _push(self) -> None:
        self._stack.append(set())

    def _pop(self) -> None:
        if self._stack:
            self._renameable |= self._stack.pop()

    def _declare(self, name: str) -> None:
        if self._stack:
            self._stack[-1].add(name)
        elif self._rename_globals:
            self._renameable.add(name)

    # ── visitors ──────────────────────────────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._push()
        all_args = (
            node.args.args
            + node.args.posonlyargs
            + node.args.kwonlyargs
        )
        for arg in all_args:
            self._declare(arg.arg)
        if node.args.vararg:
            self._declare(node.args.vararg.arg)
        if node.args.kwarg:
            self._declare(node.args.kwarg.arg)
        self.generic_visit(node)
        self._pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._push()
        self.generic_visit(node)
        self._pop()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._declare(node.id)

    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name):
            self._declare(node.target.id)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                self._declare(item.optional_vars.id)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._declare(node.name)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        if isinstance(node.target, ast.Name):
            self._declare(node.target.id)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._declare(alias.asname or alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self._declare(alias.asname or alias.name)


# ─────────────────────────────────────────────────────────────────────────────
#  3.  STRING ENCRYPTOR
#      XOR cipher with a random 32-byte key, encoded as base64.
#      Injects a private decrypt helper function at the top of the module.
#      All string literals are replaced with calls to that helper.
# ─────────────────────────────────────────────────────────────────────────────

class StringEncryptor:
    def __init__(self, fn_name: str, key: Optional[bytes] = None) -> None:
        self.fn_name = fn_name
        self._key = key or bytes(random.randint(0, 255) for _ in range(32))

    def encrypt(self, plaintext: str) -> str:
        raw = plaintext.encode("utf-8")
        k = (self._key * (len(raw) // len(self._key) + 1))[: len(raw)]
        cipher = bytes(a ^ b for a, b in zip(raw, k))
        return base64.b64encode(cipher).decode("ascii")

    def helper_ast(self) -> ast.FunctionDef:
        """
        Generate AST for the inline decryptor:

            def <fn_name>(_d):
                _k = <key_bytes>
                _r = __import__('base64').b64decode(_d)
                _k2 = (_k * (len(_r) // len(_k) + 1))[:len(_r)]
                return bytes(_x ^ _y for _x, _y in zip(_r, _k2)).decode('utf-8')
        """
        src = textwrap.dedent(f"""\
        def {self.fn_name}(_d):
            _k = {self._key!r}
            _r = __import__('base64').b64decode(_d)
            _k2 = (_k * (len(_r) // len(_k) + 1))[:len(_r)]
            return bytes(_x ^ _y for _x, _y in zip(_r, _k2)).decode('utf-8')
        """)
        fn_node: ast.FunctionDef = ast.parse(src).body[0]  # type: ignore[assignment]
        ast.fix_missing_locations(fn_node)
        return fn_node

    def call_node(self, encrypted: str, ref_node: ast.AST) -> ast.Call:
        """Return AST call node:  <fn_name>('<encrypted_payload>')"""
        call = ast.Call(
            func=ast.Name(id=self.fn_name, ctx=ast.Load()),
            args=[ast.Constant(value=encrypted)],
            keywords=[],
        )
        ast.copy_location(call, ref_node)
        ast.fix_missing_locations(call)
        return call


# ─────────────────────────────────────────────────────────────────────────────
#  4.  INTEGER ENCODER
#      Replaces integer literals with equivalent arithmetic expressions.
#      Four strategies are selected randomly per literal.
# ─────────────────────────────────────────────────────────────────────────────

class IntegerEncoder:
    _MAX: int = 10_000_000  # don't touch huge literals (e.g. magic numbers)

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng

    def encode(self, n: int) -> ast.expr:
        if abs(n) > self._MAX:
            return ast.Constant(value=n)
        try:
            method = self._rng.choice(("xor", "add", "mul", "nxn"))
            node = getattr(self, f"_enc_{method}")(n)
            ast.fix_missing_locations(node)
            return node
        except Exception:
            return ast.Constant(value=n)

    # ── strategies ────────────────────────────────────────────────────────────

    def _enc_xor(self, n: int) -> ast.BinOp:
        mask = self._rng.randint(0x100, 0xFFFF)
        return ast.BinOp(
            left=ast.Constant(value=n ^ mask),
            op=ast.BitXor(),
            right=ast.Constant(value=mask),
        )

    def _enc_add(self, n: int) -> ast.BinOp:
        delta = self._rng.randint(10_000, 999_999)
        return ast.BinOp(
            left=ast.Constant(value=n + delta),
            op=ast.Sub(),
            right=ast.Constant(value=delta),
        )

    def _enc_mul(self, n: int) -> ast.expr:
        if n == 0:
            return self._enc_xor(0)
        factor = self._rng.randint(3, 127)
        return ast.BinOp(
            left=ast.Constant(value=n * factor),
            op=ast.FloorDiv(),
            right=ast.Constant(value=factor),
        )

    def _enc_nxn(self, n: int) -> ast.BinOp:
        # n = (n | noise) ^ noise   where (noise & n) == 0
        noise = self._rng.randint(1, 0xFF) << 17
        attempts = 0
        while (noise & n) and attempts < 20:
            noise = self._rng.randint(1, 0xFF) << 17
            attempts += 1
        if noise & n:
            return self._enc_xor(n)
        return ast.BinOp(
            left=ast.BinOp(
                left=ast.Constant(value=n | noise),
                op=ast.BitOr(),
                right=ast.Constant(value=0),
            ),
            op=ast.BitXor(),
            right=ast.Constant(value=noise),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  5.  DEAD CODE INJECTOR
#      Five templates, all guaranteed to have zero side effects.
#      Every generated variable is deleted at the end of its template.
# ─────────────────────────────────────────────────────────────────────────────

class DeadCodeInjector:
    def __init__(self, rng: random.Random, ng: NameGenerator) -> None:
        self._rng = rng
        self._ng = ng
        self._templates = [
            self._tpl_never_branch,
            self._tpl_tautology,
            self._tpl_comprehension_discard,
            self._tpl_hash_discard,
            self._tpl_lambda_discard,
        ]

    def generate(self) -> List[ast.stmt]:
        nodes = self._rng.choice(self._templates)()
        for n in nodes:
            ast.fix_missing_locations(n)
        return nodes

    # ── templates ─────────────────────────────────────────────────────────────

    def _tpl_never_branch(self) -> List[ast.stmt]:
        """
        v = <int>
        if (v & 0) != 0:     ← always False
            ...unreachable...
        del v
        """
        v = self._ng.fresh()
        val = self._rng.randint(1, 9999)
        assign = ast.Assign(
            targets=[ast.Name(id=v, ctx=ast.Store())],
            value=ast.Constant(value=val),
            lineno=0, col_offset=0,
        )
        guard = ast.If(
            test=ast.Compare(
                left=ast.BinOp(
                    left=ast.Name(id=v, ctx=ast.Load()),
                    op=ast.BitAnd(),
                    right=ast.Constant(value=0),
                ),
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=0)],
            ),
            body=[ast.Expr(value=ast.Constant(value=None), lineno=0, col_offset=0)],
            orelse=[],
            lineno=0, col_offset=0,
        )
        delete = ast.Delete(
            targets=[ast.Name(id=v, ctx=ast.Del())],
            lineno=0, col_offset=0,
        )
        return [assign, guard, delete]

    def _tpl_tautology(self) -> List[ast.stmt]:
        """
        v = (a * b) // b     ← always == a
        del v
        """
        v = self._ng.fresh()
        a = self._rng.randint(2, 500)
        b = self._rng.randint(2, 500)
        assign = ast.Assign(
            targets=[ast.Name(id=v, ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=a),
                    op=ast.Mult(),
                    right=ast.Constant(value=b),
                ),
                op=ast.FloorDiv(),
                right=ast.Constant(value=b),
            ),
            lineno=0, col_offset=0,
        )
        delete = ast.Delete(
            targets=[ast.Name(id=v, ctx=ast.Del())],
            lineno=0, col_offset=0,
        )
        return [assign, delete]

    def _tpl_comprehension_discard(self) -> List[ast.stmt]:
        """
        v = [_i * c for _i in range(n)]
        del v
        """
        v = self._ng.fresh()
        n = self._rng.randint(2, 7)
        c = self._rng.randint(1, 20)
        lc = ast.ListComp(
            elt=ast.BinOp(
                left=ast.Name(id="_i", ctx=ast.Load()),
                op=ast.Mult(),
                right=ast.Constant(value=c),
            ),
            generators=[
                ast.comprehension(
                    target=ast.Name(id="_i", ctx=ast.Store()),
                    iter=ast.Call(
                        func=ast.Name(id="range", ctx=ast.Load()),
                        args=[ast.Constant(value=n)],
                        keywords=[],
                    ),
                    ifs=[],
                    is_async=0,
                )
            ],
        )
        assign = ast.Assign(
            targets=[ast.Name(id=v, ctx=ast.Store())],
            value=lc,
            lineno=0, col_offset=0,
        )
        delete = ast.Delete(
            targets=[ast.Name(id=v, ctx=ast.Del())],
            lineno=0, col_offset=0,
        )
        return [assign, delete]

    def _tpl_hash_discard(self) -> List[ast.stmt]:
        """
        v = hash(<random literal>)
        del v
        """
        v = self._ng.fresh()
        payload: Any = self._rng.choice([
            self._rng.randint(0, 999_999),
            "".join(self._rng.choices(string.ascii_lowercase, k=self._rng.randint(4, 12))),
            round(self._rng.uniform(-1000.0, 1000.0), 4),
        ])
        assign = ast.Assign(
            targets=[ast.Name(id=v, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id="hash", ctx=ast.Load()),
                args=[ast.Constant(value=payload)],
                keywords=[],
            ),
            lineno=0, col_offset=0,
        )
        delete = ast.Delete(
            targets=[ast.Name(id=v, ctx=ast.Del())],
            lineno=0, col_offset=0,
        )
        return [assign, delete]

    def _tpl_lambda_discard(self) -> List[ast.stmt]:
        """
        v = (lambda _v: _v * n)(m)
        del v
        """
        v = self._ng.fresh()
        n = self._rng.randint(2, 50)
        m = self._rng.randint(1, 200)
        call = ast.Call(
            func=ast.Lambda(
                args=ast.arguments(
                    posonlyargs=[],
                    args=[ast.arg(arg="_v")],
                    vararg=None,
                    kwonlyargs=[],
                    kw_defaults=[],
                    kwarg=None,
                    defaults=[],
                ),
                body=ast.BinOp(
                    left=ast.Name(id="_v", ctx=ast.Load()),
                    op=ast.Mult(),
                    right=ast.Constant(value=n),
                ),
            ),
            args=[ast.Constant(value=m)],
            keywords=[],
        )
        assign = ast.Assign(
            targets=[ast.Name(id=v, ctx=ast.Store())],
            value=call,
            lineno=0, col_offset=0,
        )
        delete = ast.Delete(
            targets=[ast.Name(id=v, ctx=ast.Del())],
            lineno=0, col_offset=0,
        )
        return [assign, delete]


# ─────────────────────────────────────────────────────────────────────────────
#  6.  MAIN AST TRANSFORMER
#      Single-pass NodeTransformer that applies every enabled layer.
# ─────────────────────────────────────────────────────────────────────────────

class VortexTransformer(ast.NodeTransformer):
    def __init__(
        self,
        ng: NameGenerator,
        se: StringEncryptor,
        ie: IntegerEncoder,
        di: DeadCodeInjector,
        renameable: Set[str],
        opts: Dict[str, bool],
        rng: random.Random,
    ) -> None:
        self._ng = ng
        self._se = se
        self._ie = ie
        self._di = di
        self._renameable = renameable
        self._opts = opts
        self._rng = rng

    # ── helpers ───────────────────────────────────────────────────────────────

    def _can_rename(self, name: str) -> bool:
        return (
            self._opts.get("rename", False)
            and name in self._renameable
            and name not in NameGenerator.PYTHON_RESERVED
            and not (name.startswith("__") and name.endswith("__"))
        )

    def _dead_inject(self, body: List[ast.stmt]) -> List[ast.stmt]:
        if not self._opts.get("dead_code") or not body:
            return body
        # Pick 1-3 injection points; don't inject into single-statement bodies
        if len(body) < 2:
            return body
        count = min(self._rng.randint(1, 3), len(body))
        positions = sorted(self._rng.sample(range(len(body)), count))
        result = list(body)
        offset = 0
        for pos in positions:
            dead = self._di.generate()
            idx = pos + offset
            for stmt in dead:
                result.insert(idx, stmt)
                idx += 1
                offset += 1
        return result

    def _opaque_predicate(self, ref_node: ast.AST) -> ast.expr:
        """
        Returns an expression that always evaluates to True.
        Form:  (mask | ~mask) != 0
        """
        mask = self._rng.randint(1, 0xFFFF)
        node = ast.Compare(
            left=ast.BinOp(
                left=ast.Constant(value=mask),
                op=ast.BitOr(),
                right=ast.UnaryOp(op=ast.Invert(), operand=ast.Constant(value=mask)),
            ),
            ops=[ast.NotEq()],
            comparators=[ast.Constant(value=0)],
        )
        ast.copy_location(node, ref_node)
        ast.fix_missing_locations(node)
        return node

    # ── visitors ──────────────────────────────────────────────────────────────

    def visit_Module(self, node: ast.Module) -> ast.Module:
        self.generic_visit(node)
        node.body = self._dead_inject(node.body)
        return node

    # -- functions / methods ---------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        # Rename the function name itself
        if self._can_rename(node.name):
            node.name = self._ng.get(node.name)

        # Rename all argument names
        if self._opts.get("rename"):
            all_args = (
                node.args.args
                + node.args.posonlyargs
                + node.args.kwonlyargs
            )
            for arg in all_args:
                if self._can_rename(arg.arg):
                    old = arg.arg
                    arg.arg = self._ng.get(old)
                    # Ensure the new name is recognized in the renameable set
                    self._renameable.discard(old)
                    self._renameable.add(self._ng.renamed(old))
            if node.args.vararg and self._can_rename(node.args.vararg.arg):
                node.args.vararg.arg = self._ng.get(node.args.vararg.arg)
            if node.args.kwarg and self._can_rename(node.args.kwarg.arg):
                node.args.kwarg.arg = self._ng.get(node.args.kwarg.arg)

        # Strip docstring
        if self._opts.get("strip_docs") and node.body:
            first = node.body[0]
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                node.body = node.body[1:] or [ast.Pass(lineno=0, col_offset=0)]

        # Recurse then inject dead code
        node.body = [self.visit(s) for s in node.body]
        node.body = self._dead_inject(node.body)
        ast.fix_missing_locations(node)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # -- classes ---------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        if self._can_rename(node.name):
            node.name = self._ng.get(node.name)
        self.generic_visit(node)
        return node

    # -- names -----------------------------------------------------------------

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if self._can_rename(node.id):
            node.id = self._ng.get(node.id)
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if node.name and self._can_rename(node.name):
            node.name = self._ng.get(node.name)
        self.generic_visit(node)
        return node

    def visit_NamedExpr(self, node: ast.NamedExpr) -> ast.AST:
        # walrus operator target
        if isinstance(node.target, ast.Name) and self._can_rename(node.target.id):
            node.target.id = self._ng.get(node.target.id)
        self.generic_visit(node)
        return node

    # -- f-strings --------------------------------------------------------------
    # JoinedStr.values may only contain Constant and FormattedValue nodes.
    # Encrypting a literal Constant by replacing it with a Call would make the
    # AST invalid because a Call is not a legal direct child of JoinedStr.
    # Keep literal f-string text intact, while still transforming expressions
    # inside { ... } and format specifications.

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                value.value = self.visit(value.value)
                if value.format_spec is not None:
                    value.format_spec = self.visit(value.format_spec)
        return node

    # -- constants (string encrypt + integer encode) ---------------------------

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        # String encryption
        if (
            self._opts.get("encrypt_strings")
            and isinstance(node.value, str)
            and len(node.value) >= 2
            and "\n" not in node.value[:5]     # skip obvious multiline templates
            and not node.value.startswith("%")  # skip old-style format strings
        ):
            try:
                enc = self._se.encrypt(node.value)
                return self._se.call_node(enc, node)
            except Exception:
                pass

        # Integer encoding (skip booleans — True/False are int subclasses)
        if (
            self._opts.get("encode_integers")
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
        ):
            try:
                encoded = self._ie.encode(node.value)
                ast.copy_location(encoded, node)
                return encoded
            except Exception:
                pass

        return node

    # -- control flow (opaque predicates) -------------------------------------

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)
        if self._opts.get("control_flow"):
            # test → (test) and (opaque_always_true)
            node.test = ast.BoolOp(
                op=ast.And(),
                values=[node.test, self._opaque_predicate(node)],
            )
            ast.fix_missing_locations(node)
        return node

    def visit_While(self, node: ast.While) -> ast.AST:
        self.generic_visit(node)
        if self._opts.get("control_flow") and self._rng.random() < 0.6:
            node.test = ast.BoolOp(
                op=ast.And(),
                values=[node.test, self._opaque_predicate(node)],
            )
            ast.fix_missing_locations(node)
        return node

    # -- docstrings at expression statement level ------------------------------

    def visit_Expr(self, node: ast.Expr) -> Optional[ast.AST]:
        if (
            self._opts.get("strip_docs")
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return None  # drop the statement entirely
        self.generic_visit(node)
        return node


# ─────────────────────────────────────────────────────────────────────────────
#  7.  IMPORT MANGLER
#      Rewrites import statements as __import__() expressions.
#      `import X`          → `X = __import__('X')`
#      `from X import Y`   → `Y = __import__('X', {}, {}, ['Y']).Y`
# ─────────────────────────────────────────────────────────────────────────────

def mangle_imports(tree: ast.Module) -> ast.Module:
    new_body: List[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                asname = alias.asname or alias.name.split(".")[0]
                stmt = ast.Assign(
                    targets=[ast.Name(id=asname, ctx=ast.Store())],
                    value=ast.Call(
                        func=ast.Name(id="__import__", ctx=ast.Load()),
                        args=[ast.Constant(value=alias.name)],
                        keywords=[],
                    ),
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                )
                ast.fix_missing_locations(stmt)
                new_body.append(stmt)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                asname = alias.asname or alias.name
                stmt = ast.Assign(
                    targets=[ast.Name(id=asname, ctx=ast.Store())],
                    value=ast.Attribute(
                        value=ast.Call(
                            func=ast.Name(id="__import__", ctx=ast.Load()),
                            args=[
                                ast.Constant(value=node.module),
                                ast.Dict(keys=[], values=[]),
                                ast.Dict(keys=[], values=[]),
                                ast.List(
                                    elts=[ast.Constant(value=alias.name)],
                                    ctx=ast.Load(),
                                ),
                            ],
                            keywords=[],
                        ),
                        attr=alias.name,
                        ctx=ast.Load(),
                    ),
                    lineno=node.lineno,
                    col_offset=node.col_offset,
                )
                ast.fix_missing_locations(stmt)
                new_body.append(stmt)
        else:
            new_body.append(node)
    tree.body = new_body
    return tree


# ─────────────────────────────────────────────────────────────────────────────
#  8.  COMMENT STRIPPER
#      Strips # comments from source text, correctly skipping # inside strings.
# ─────────────────────────────────────────────────────────────────────────────

def strip_comments(source: str) -> str:
    result_lines: List[str] = []
    for raw_line in source.splitlines():
        chars: List[str] = []
        in_str = False
        str_char = ""
        triple = False
        i = 0
        while i < len(raw_line):
            ch = raw_line[i]
            if in_str:
                chars.append(ch)
                if ch == "\\" and i + 1 < len(raw_line):
                    chars.append(raw_line[i + 1])
                    i += 2
                    continue
                seg = raw_line[i : i + 3] if triple else ch
                if triple and seg == str_char * 3:
                    chars.append(raw_line[i + 1])
                    chars.append(raw_line[i + 2])
                    i += 3
                    in_str = False
                    continue
                elif not triple and ch == str_char:
                    in_str = False
            else:
                if ch in ('"', "'"):
                    triple_candidate = raw_line[i : i + 3]
                    if triple_candidate in ('"""', "'''"):
                        in_str, triple, str_char = True, True, ch
                        chars.extend(triple_candidate)
                        i += 3
                        continue
                    else:
                        in_str, triple, str_char = True, False, ch
                        chars.append(ch)
                elif ch == "#":
                    break
                else:
                    chars.append(ch)
            i += 1
        stripped = "".join(chars).rstrip()
        if stripped:
            result_lines.append(stripped)
    return "\n".join(result_lines)


# ─────────────────────────────────────────────────────────────────────────────
#  9.  ANTI-DEBUG GUARD
#      Timing-based: measures a tight loop's wall-clock time.
#      A debugger stepping through will blow the 1.5-second threshold.
# ─────────────────────────────────────────────────────────────────────────────

_ANTI_DEBUG_SOURCE = textwrap.dedent("""\
import time as _time
_t0 = _time.perf_counter()
for _i in range(100_000):
    pass
_t1 = _time.perf_counter()
if (_t1 - _t0) > 1.5:
    raise SystemExit(0)
del _t0, _t1, _i
""")


# ─────────────────────────────────────────────────────────────────────────────
#  10. BYTECODE ENCODER
#      Maximum opacity: compile → marshal → zlib(level=9) → base85 → exec()
#      The output is a valid Python file with a single exec() call.
#      No source-level analysis is possible without first executing the loader.
# ─────────────────────────────────────────────────────────────────────────────

def encode_bytecode(source: str) -> str:
    code_obj = compile(source, "<vortex>", "exec", optimize=2)
    raw = marshal.dumps(code_obj)
    compressed = zlib.compress(raw, level=9)
    encoded = base64.b85encode(compressed).decode("ascii")
    return (
        "import marshal,zlib,base64\n"
        f"exec(marshal.loads(zlib.decompress(base64.b85decode({encoded!r}))))\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  11. PIPELINE — public entry point
# ─────────────────────────────────────────────────────────────────────────────

def obfuscate(
    source: str,
    *,
    rename: bool = True,
    rename_globals: bool = False,
    encrypt_strings: bool = True,
    encode_integers: bool = True,
    control_flow: bool = True,
    dead_code: bool = True,
    mangle_imports_flag: bool = True,
    anti_debug: bool = False,
    strip_docs: bool = True,
    bytecode_mode: bool = False,
    seed: Optional[int] = None,
) -> str:
    """
    Full obfuscation pipeline.

    Parameters
    ----------
    source            : Original Python 3.9+ source code.
    rename            : Rename locally-scoped identifiers.
    rename_globals    : Also rename module-level names (breaks public APIs).
    encrypt_strings   : XOR-encrypt all string literals ≥ 2 chars.
    encode_integers   : Replace integer literals with arithmetic expressions.
    control_flow      : Inject opaque predicates into if/while conditions.
    dead_code         : Insert unreachable junk code throughout function bodies.
    mangle_imports_flag: Convert `import X` statements to __import__() calls.
    anti_debug        : Prepend a timing-based anti-debug guard.
    strip_docs        : Remove all docstrings.
    bytecode_mode     : Compile to bytecode, compress, base85-encode. Wraps
                        all other transforms — most opaque output possible.
    seed              : RNG seed for reproducible output.

    Returns
    -------
    str : Obfuscated Python source.
    """
    rng = random.Random(seed)

    # ── Phase 1: strip comments ───────────────────────────────────────────────
    source = strip_comments(source)

    # ── Phase 2: parse ────────────────────────────────────────────────────────
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(f"Source parse error: {exc}") from exc

    # ── Phase 3: scope analysis ───────────────────────────────────────────────
    analyzer = ScopeAnalyzer(rename_globals=rename_globals)
    renameable: Set[str] = analyzer.collect(tree)

    # ── Phase 4: init components ──────────────────────────────────────────────
    ng = NameGenerator(seed=seed)
    se_fn_name = ng.fresh()                       # private decrypt helper name
    se = StringEncryptor(fn_name=se_fn_name)
    ie = IntegerEncoder(rng)
    di = DeadCodeInjector(rng, ng)

    opts: Dict[str, bool] = {
        "rename": rename,
        "encrypt_strings": encrypt_strings,
        "encode_integers": encode_integers,
        "control_flow": control_flow,
        "dead_code": dead_code,
        "strip_docs": strip_docs,
    }

    # ── Phase 5: import mangling ──────────────────────────────────────────────
    if mangle_imports_flag:
        tree = mangle_imports(tree)

    # ── Phase 6: inject string-decrypt helper at top of module ────────────────
    if encrypt_strings:
        helper = se.helper_ast()
        tree.body.insert(0, helper)

    # ── Phase 7: main transformation ─────────────────────────────────────────
    transformer = VortexTransformer(ng, se, ie, di, renameable, opts, rng)
    tree = transformer.visit(tree)
    ast.fix_missing_locations(tree)

    # ── Phase 8: unparse ──────────────────────────────────────────────────────
    try:
        result = ast.unparse(tree)
    except Exception as exc:
        raise ValueError(f"ast.unparse failed: {exc}") from exc

    # ── Phase 9: anti-debug header ────────────────────────────────────────────
    if anti_debug:
        result = _ANTI_DEBUG_SOURCE + "\n" + result

    # ── Phase 10: compact ─────────────────────────────────────────────────────
    result = "\n".join(line for line in result.splitlines() if line.strip())

    # ── Phase 11: bytecode wrap ───────────────────────────────────────────────
    if bytecode_mode:
        result = encode_bytecode(result)

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  12. CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vortex",
        description="VORTEX — Full-featured Python code obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples
        --------
          vortex target.py                         # all transforms, default output
          vortex target.py -o protected.py         # explicit output path
          vortex target.py --bytecode              # marshal+zlib+base85 (most opaque)
          vortex target.py --anti-debug --verify   # guard + syntax check
          vortex target.py --rename-globals \\
                           --no-dead-code          # rename everything, skip junk code
          vortex target.py --seed 1337             # reproducible output
        """),
    )

    parser.add_argument("input", help="Input .py file")
    parser.add_argument("-o", "--output", default=None,
                        help="Output path (default: <input>_obf.py)")

    # -- toggle groups ---------------------------------------------------------
    parser.add_argument("--rename-globals",  action="store_true",
                        help="Rename module-level names (breaks public API surface)")
    parser.add_argument("--no-rename",       action="store_true",
                        help="Disable all identifier renaming")
    parser.add_argument("--no-strings",      action="store_true",
                        help="Disable string encryption")
    parser.add_argument("--no-integers",     action="store_true",
                        help="Disable integer encoding")
    parser.add_argument("--no-flow",         action="store_true",
                        help="Disable control-flow obfuscation")
    parser.add_argument("--no-dead-code",    action="store_true",
                        help="Disable dead code injection")
    parser.add_argument("--no-imports",      action="store_true",
                        help="Disable import mangling")
    parser.add_argument("--keep-docs",       action="store_true",
                        help="Preserve docstrings")

    # -- extras ----------------------------------------------------------------
    parser.add_argument("--anti-debug", action="store_true",
                        help="Prepend timing-based anti-debug guard")
    parser.add_argument("--bytecode",   action="store_true",
                        help="Compile → marshal → zlib → base85 (nuclear option)")
    parser.add_argument("--seed",       type=int, default=None,
                        help="RNG seed for reproducible, deterministic output")
    parser.add_argument("--verify",     action="store_true",
                        help="Parse output after obfuscation to confirm syntax is clean")
    parser.add_argument("--stats",      action="store_true",
                        help="Print a transform summary after completion")

    args = parser.parse_args()

    # ── validate input ────────────────────────────────────────────────────────
    if not os.path.isfile(args.input):
        print(f"[!] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as fh:
        source = fh.read()

    in_bytes = len(source.encode("utf-8"))
    print(f"[*] VORTEX  →  {args.input}  ({in_bytes:,} bytes)")

    # ── run pipeline ──────────────────────────────────────────────────────────
    try:
        result = obfuscate(
            source,
            rename=not args.no_rename,
            rename_globals=args.rename_globals,
            encrypt_strings=not args.no_strings,
            encode_integers=not args.no_integers,
            control_flow=not args.no_flow,
            dead_code=not args.no_dead_code,
            mangle_imports_flag=not args.no_imports,
            anti_debug=args.anti_debug,
            strip_docs=not args.keep_docs,
            bytecode_mode=args.bytecode,
            seed=args.seed,
        )
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    # ── optional verification ─────────────────────────────────────────────────
    if args.verify and not args.bytecode:
        try:
            ast.parse(result)
            print("[+] Syntax verified — output parses cleanly")
        except SyntaxError as exc:
            print(f"[!] Output has syntax error: {exc}", file=sys.stderr)
            sys.exit(1)

    # ── write output ──────────────────────────────────────────────────────────
    out_path = args.output
    if not out_path:
        base, ext = os.path.splitext(args.input)
        out_path = base + "_obf" + (ext or ".py")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(result)

    out_bytes = len(result.encode("utf-8"))
    ratio = out_bytes / max(in_bytes, 1) * 100
    print(f"[+] Output  →  {out_path}  ({out_bytes:,} bytes,  {ratio:.1f}% of original)")

    # ── stats -----------------------------------------------------------------
    if args.stats:
        applied = []
        if not args.no_rename:    applied.append("Identifier renaming (scope-aware)")
        if args.rename_globals:   applied.append("Global/module-level rename")
        if not args.no_strings:   applied.append("String XOR encryption (32-byte key, base64)")
        if not args.no_integers:  applied.append("Integer encoding (XOR / add / mul / NxN)")
        if not args.no_flow:      applied.append("Opaque predicate injection (if + while)")
        if not args.no_dead_code: applied.append("Dead code injection (5 templates)")
        if not args.no_imports:   applied.append("Import mangling (__import__ rewrite)")
        if args.anti_debug:       applied.append("Anti-debug timing guard")
        if not args.keep_docs:    applied.append("Docstring removal")
        if args.bytecode:         applied.append("Bytecode: marshal → zlib(9) → base85 → exec()")
        print()
        print("  Transforms applied:")
        for t in applied:
            print(f"    ✓  {t}")
        print()
        print(f"  Obfuscation ratio: {ratio:.1f}%")
        if ratio < 100:
            print(f"  Size delta: -{in_bytes - out_bytes:,} bytes")
        else:
            print(f"  Size delta: +{out_bytes - in_bytes:,} bytes  (encryption payload + dead code)")


if __name__ == "__main__":
    main()