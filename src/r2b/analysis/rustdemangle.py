"""Pure-Python Rust symbol demangler (legacy Itanium and v0).

No third-party demangle library. Unknown or truncated symbols are returned
unchanged so a bad decode never replaces a real name with a guess.
"""

from __future__ import annotations

import re

_LEGACY_RE = re.compile(r"^_?_ZN")
_LEGACY_SUBS = (
    ("$LT$", "<"),
    ("$GT$", ">"),
    ("$LP$", "("),
    ("$RP$", ")"),
    ("$C$", ","),
    ("$SP$", "@"),
    ("$BP$", "*"),
    ("$RF$", "&"),
    ("$u20$", " "),
    ("$u7b$", "{"),
    ("$u7d$", "}"),
    ("$u27$", "'"),
    ("$u5b$", "["),
    ("$u5d$", "]"),
    ("..", "::"),
)
_U_ESCAPE = re.compile(r"\$u([0-9a-fA-F]{2,6})\$")
_HASH_COMPONENT = re.compile(r"^h[0-9a-f]{16}$")
_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_BASIC_TYPES = {
    "a": "i8",
    "b": "bool",
    "c": "char",
    "d": "f64",
    "e": "str",
    "f": "f32",
    "h": "u8",
    "i": "isize",
    "j": "usize",
    "l": "i32",
    "m": "u32",
    "n": "i128",
    "o": "u128",
    "s": "i16",
    "t": "u16",
    "u": "()",
    "v": "...",
    "x": "i64",
    "y": "u64",
    "z": "!",
    "p": "_",
}


_MAX_DEPTH = 64
_MAX_BINDERS = 16
_MAX_OUTPUT = 4096


def demangle(name: str) -> str | None:
    """Return a demangled Rust path, or None when ``name`` is not mangled."""
    try:
        text = name.strip()
        for prefix in ("sym.", "imp.", "sym.imp."):
            if text.startswith(prefix):
                text = text[len(prefix) :]
        if text.startswith("__ZN"):
            text = text[1:]
        if text.startswith("_R"):
            return _demangle_v0(text)
        if _LEGACY_RE.match(text):
            return _demangle_legacy(text)
        return None
    except (_DemangleError, ValueError, RecursionError, OverflowError, MemoryError):
        return None


def pretty_symbol(name: str) -> str:
    """Demangle when the spelling is Rust. Otherwise return ``name``."""
    try:
        decoded = demangle(name)
        return decoded if decoded else name
    except Exception:
        return name


class _DemangleError(Exception):
    pass


def _join(parts: list[str], sep: str = ", ") -> str:
    total = 0
    out: list[str] = []
    for part in parts:
        total += len(part) + (len(sep) if out else 0)
        if total > _MAX_OUTPUT:
            raise _DemangleError("output")
        out.append(part)
    return sep.join(out)


def _unescape_legacy(ident: str) -> str:
    def repl(match: re.Match[str]) -> str:
        code = int(match.group(1), 16)
        if code > 0x10FFFF:
            raise _DemangleError("unicode")
        return chr(code)

    text = _U_ESCAPE.sub(repl, ident)
    for src, dst in _LEGACY_SUBS:
        text = text.replace(src, dst)
    return text.replace(".", "-")


def _demangle_legacy(symbol: str) -> str:
    if not symbol.startswith("_ZN"):
        raise _DemangleError("prefix")
    body = symbol[3:]
    if not body.endswith("E"):
        raise _DemangleError("suffix")
    parts: list[str] = []
    i = 0
    end = len(body) - 1
    while i < end:
        if not body[i].isdigit():
            raise _DemangleError("length")
        j = i
        while j < end and body[j].isdigit():
            j += 1
        length = int(body[i:j])
        i = j
        if length <= 0 or i + length > end:
            raise _DemangleError("span")
        parts.append(_unescape_legacy(body[i : i + length]))
        i += length
    if i != end:
        raise _DemangleError("tail")
    if parts and _HASH_COMPONENT.match(parts[-1]):
        parts.pop()
    if not parts:
        raise _DemangleError("empty")
    return _join(parts, "::")


class _Node:
    __slots__ = ("kind", "text", "inner", "trait")

    def __init__(
        self, kind: str, text: str, inner: str | None = None, trait: str | None = None
    ) -> None:
        if len(text) > _MAX_OUTPUT:
            raise _DemangleError("output")
        if inner is not None and len(inner) > _MAX_OUTPUT:
            raise _DemangleError("output")
        if trait is not None and len(trait) > _MAX_OUTPUT:
            raise _DemangleError("output")
        self.kind = kind
        self.text = text
        self.inner = inner
        self.trait = trait

    def display(self) -> str:
        return self.text


class _V0:
    def __init__(self, data: str) -> None:
        self.data = data
        self.i = 0
        self.base = 0
        self.depth = 0
        self.memo: dict[int, _Node] = {}

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            raise _DemangleError("depth")

    def _leave(self) -> None:
        self.depth = max(0, self.depth - 1)

    def parse(self) -> str:
        if self.data.startswith("_R"):
            self.i = 2
            self.base = 2
        else:
            raise _DemangleError("prefix")
        if self.i < len(self.data) and self.data[self.i].isdigit():
            self._decimal()
        node = self._path()
        if self.i < len(self.data) and self.data[self.i] in "CNMXYIB":
            if self.data[self.i] == "B":
                self._eat()
                self._backref()
            else:
                self._path()
        if self.i < len(self.data) and self.data[self.i] in ".$":
            return node.display()
        if self.i != len(self.data):
            raise _DemangleError("tail")
        return node.display()

    def _peek(self) -> str:
        if self.i >= len(self.data):
            raise _DemangleError("eof")
        return self.data[self.i]

    def _eat(self) -> str:
        ch = self._peek()
        self.i += 1
        return ch

    def _decimal(self) -> int:
        start = self.i
        while self.i < len(self.data) and self.data[self.i].isdigit():
            self.i += 1
        if self.i == start:
            raise _DemangleError("decimal")
        return int(self.data[start : self.i])

    def _base62(self) -> int:
        start = self.i
        while self.i < len(self.data) and self.data[self.i] in _BASE62:
            self.i += 1
        if self.i >= len(self.data) or self.data[self.i] != "_":
            raise _DemangleError("base62")
        digits = self.data[start : self.i]
        self.i += 1
        if not digits:
            return 0
        value = 0
        for ch in digits:
            value = value * 62 + _BASE62.index(ch)
        return value

    def _ident(self) -> str:
        if self._peek() == "s":
            self._eat()
            self._base62()
        puny = False
        if self._peek() == "u":
            self._eat()
            puny = True
        length = self._decimal()
        if self.i < len(self.data) and self.data[self.i] == "_":
            self._eat()
        if self.i + length > len(self.data):
            raise _DemangleError("ident")
        raw = self.data[self.i : self.i + length]
        self.i += length
        if puny:
            # Rust v0 uses '_' as the punycode delimiter, not RFC 3492 '-'.
            # No delimiter means the whole ident is punycode (empty prefix).
            if "_" in raw:
                head, _, tail = raw.rpartition("_")
                raw = _punycode(tail, head.replace("_", " "))
            else:
                raw = _punycode(raw, "")
        return raw

    def _maybe_disambiguator(self) -> None:
        """Optional ``s<base62>_`` before an impl type. ``s`` alone is i16."""
        if self.i >= len(self.data) or self.data[self.i] != "s":
            return
        nxt = self.data[self.i + 1] if self.i + 1 < len(self.data) else ""
        if nxt != "_" and nxt not in _BASE62:
            return
        self._eat()
        self._base62()

    def _pos(self, index: int | None = None) -> int:
        return (self.i if index is None else index) - self.base

    def _backref(self) -> _Node:
        # Caller already consumed the 'B'. The offset is a byte index from the
        # first byte after '_R'. Non-empty base-62 digits encode value-1, so
        # ``B0_`` is 1 and ``B_`` is 0. The target must be an earlier node.
        origin = self._pos() - 1
        digits_at = self.i
        raw = self._base62()
        offset = raw if self.i == digits_at + 1 else raw + 1
        if offset >= origin:
            raise _DemangleError("backref")
        node = self.memo.get(offset)
        if node is None:
            raise _DemangleError("backref-missing")
        return node

    def _path(self) -> _Node:
        self._enter()
        try:
            return self._path_body()
        finally:
            self._leave()

    def _path_body(self) -> _Node:
        start = self._pos()
        tag = self._eat()
        if tag == "B":
            return self._backref()
        if tag == "C":
            node = _Node("crate", self._ident())
        elif tag == "N":
            ns = self._eat()
            inner = self._path()
            ident = self._ident()
            node = _format_nested(ns, inner, ident)
        elif tag == "M":
            # "M" <disambiguator> <impl-path> <type>
            # The type may backref the impl path before the impl node exists.
            self._maybe_disambiguator()
            impl_path = self._path()
            self.memo[start] = impl_path
            ty = self._type()
            node = _Node("impl", ty.display(), inner=ty.display())
        elif tag == "X":
            # "X" <disambiguator> <impl-path> <type> <trait-path>
            self._maybe_disambiguator()
            self._path()
            ty = self._type()
            trait = self._path()
            node = _Node(
                "trait_impl",
                f"<{ty.display()} as {trait.display()}>",
                inner=ty.display(),
                trait=trait.display(),
            )
        elif tag == "Y":
            # "Y" <type> <trait-path>. No disambiguator: a following ``s`` is i16.
            ty = self._type()
            trait = self._path()
            node = _Node(
                "trait_impl",
                f"<{ty.display()} as {trait.display()}>",
                inner=ty.display(),
                trait=trait.display(),
            )
        elif tag == "I":
            inner = self._path()
            args: list[str] = []
            while self._peek() != "E":
                args.append(self._generic().display())
            self._eat()
            node = _Node("generic", f"{inner.display()}::<{_join(args)}>")
        else:
            raise _DemangleError(f"path {tag}")
        self.memo[start] = node
        return node

    def _generic(self) -> _Node:
        if self._peek() == "K":
            self._eat()
            return self._const()
        if self._peek() == "L":
            return self._lifetime()
        return self._type()

    def _lifetime(self) -> _Node:
        self._eat()
        self._base62()
        return _Node("lt", "'_")

    def _const(self) -> _Node:
        if self._peek() == "B":
            self._eat()
            return self._backref()
        if self._peek() == "p":
            self._eat()
            return _Node("const", "_")
        typ = None
        if self._peek() in _BASIC_TYPES or self._peek() in "CNMXYIRQPASOTF":
            typ = self._type()
        neg = False
        if self._peek() == "n":
            self._eat()
            neg = True
        start = self.i
        while self.i < len(self.data) and self.data[self.i] in "0123456789abcdefABCDEF":
            self.i += 1
        if self.i == start or self.i >= len(self.data) or self.data[self.i] != "_":
            raise _DemangleError("const")
        digits = self.data[start : self.i]
        self._eat()
        try:
            value = int(digits, 16)
        except ValueError as exc:
            raise _DemangleError("const") from exc
        kind = typ.display() if typ is not None else ""
        if kind == "bool":
            text = "true" if value else "false"
        elif kind == "char" and 0x20 <= value <= 0x7E:
            text = f"'{chr(value)}'"
        elif kind == "char":
            text = f"'\\u{{{value:x}}}'"
        else:
            text = f"-{value}" if neg else str(value)
        return _Node("const", text)

    def _type(self) -> _Node:
        self._enter()
        try:
            return self._type_body()
        finally:
            self._leave()

    def _type_body(self) -> _Node:
        start = self._pos()
        tag = self._peek()
        if tag == "B":
            self._eat()
            return self._backref()
        if tag in _BASIC_TYPES:
            self._eat()
            node = _Node("type", _BASIC_TYPES[tag])
            self.memo[start] = node
            return node
        if tag in "CNMXYI":
            return self._path()
        if tag == "R":
            self._eat()
            if self._peek() == "L":
                self._lifetime()
            inner = self._type()
            node = _Node("type", f"&{inner.display()}")
        elif tag == "Q":
            self._eat()
            if self._peek() == "L":
                self._lifetime()
            inner = self._type()
            node = _Node("type", f"&mut {inner.display()}")
        elif tag == "P":
            self._eat()
            inner = self._type()
            node = _Node("type", f"*const {inner.display()}")
        elif tag == "O":
            self._eat()
            inner = self._type()
            node = _Node("type", f"*mut {inner.display()}")
        elif tag == "A":
            self._eat()
            inner = self._type()
            const = self._const()
            node = _Node("type", f"[{inner.display()}; {const.display()}]")
        elif tag == "S":
            self._eat()
            inner = self._type()
            node = _Node("type", f"[{inner.display()}]")
        elif tag == "T":
            self._eat()
            items: list[str] = []
            while self._peek() != "E":
                items.append(self._type().display())
            self._eat()
            text = f"({_join(items)})" if len(items) != 1 else f"({items[0]},)"
            node = _Node("type", text)
        elif tag == "F":
            node = self._fn_type()
        else:
            raise _DemangleError(f"type {tag}")
        self.memo[start] = node
        return node

    def _fn_type(self) -> _Node:
        self._eat()
        binder = ""
        if self._peek() == "G":
            self._eat()
            count = self._base62()
            if count > _MAX_BINDERS:
                raise _DemangleError("binder")
            binder = "for<" + ", ".join(f"'_{n}" for n in range(count)) + "> "
        unsafe = ""
        if self._peek() == "U":
            self._eat()
            unsafe = "unsafe "
        if self._peek() == "K":
            self._eat()
            abi = self._ident()
            abi_text = f'extern "{abi}" '
        else:
            abi_text = ""
        inputs: list[str] = []
        while self._peek() != "E":
            inputs.append(self._type().display())
        self._eat()
        ret = self._type().display()
        ret_text = "" if ret == "()" else f" -> {ret}"
        return _Node("type", f"{binder}{unsafe}{abi_text}fn({_join(inputs)}){ret_text}")


def _format_nested(ns: str, inner: _Node, ident: str) -> _Node:
    if ns == "C":
        label = "{closure}" if ident in {"", "_"} else ident
        text = f"{inner.display()}::{label}"
        return _Node("nested", text)
    if inner.kind == "impl":
        return _Node("nested", f"<{inner.inner or inner.display()}>::{ident}")
    if inner.kind == "trait_impl":
        return _Node("nested", f"{inner.display()}::{ident}")
    if not ident:
        return _Node("nested", inner.display())
    return _Node("nested", f"{inner.display()}::{ident}")


def _punycode(tail: str, prefix: str) -> str:
    """Decode a punycode digit tail onto ``prefix``. RFC 3492, enough for Rust idents."""
    try:
        n = 128
        i = 0
        bias = 72
        out = list(prefix)
        pos = 0
        while pos < len(tail):
            old_i = i
            w = 1
            k = 36
            while True:
                if pos >= len(tail):
                    return prefix + "-" + tail
                ch = tail[pos]
                pos += 1
                # RFC 3492: a-z = 0..25, 0-9 = 26..35 (case-insensitive letters).
                if "a" <= ch <= "z":
                    digit = ord(ch) - 97
                elif "A" <= ch <= "Z":
                    digit = ord(ch) - 65
                elif "0" <= ch <= "9":
                    digit = ord(ch) - 48 + 26
                else:
                    digit = -1
                if digit < 0 or digit > 35:
                    return prefix + "-" + tail
                i += digit * w
                t = 1 if k <= bias else 26 if k >= bias + 26 else k - bias
                if digit < t:
                    break
                w *= 36 - t
                k += 36
            delta = i - old_i
            bias = _puny_bias(delta, len(out) + 1, old_i == 0)
            n += i // (len(out) + 1)
            if n > 0x10FFFF or i > 1_000_000 or len(out) > 1024:
                raise ValueError("punycode")
            i %= len(out) + 1
            out.insert(i, chr(n))
            i += 1
        return "".join(out)
    except (OverflowError, ValueError):
        return prefix + "-" + tail


def _puny_bias(delta: int, points: int, first: bool) -> int:
    delta = delta // 700 if first else delta // 2
    delta += delta // points
    k = 0
    while delta > 455:
        delta //= 35
        k += 36
    return k + (36 * delta) // (delta + 38)


def _demangle_v0(symbol: str) -> str:
    return _V0(symbol).parse()
