"""RFC 8785 JSON Canonicalization Scheme, written from the RFC text."""
import math

class JCSError(ValueError):
    pass

def _num(x):
    if isinstance(x, bool):
        raise JCSError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > 2**53:  # beyond IEEE-754 exact range: RFC 8785 sec 3.2.2.3 / I-JSON
            f = float(x)
            if int(f) != x:
                raise JCSError("integer not exactly representable as IEEE-754 double")
            x = f
        else:
            return str(x)
    if math.isnan(x) or math.isinf(x):
        raise JCSError("NaN/Infinity not allowed")
    if x == 0:
        return "0"  # also -0
    # ECMAScript Number::toString (ES2019 7.1.12.1) from the shortest round-trip digits
    r = repr(x)
    sign = "-" if x < 0 else ""
    r = r.lstrip("-")
    if "e" in r:
        mant, e = r.split("e"); e = int(e)
    else:
        mant, e = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + e - lead  # position of decimal point relative to digits
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        ee = n - 1
        es = ("+" if ee >= 0 else "-") + str(abs(ee))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s

_ESC = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}

def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JCSError("lone surrogate in string")
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

def _utf16_key(s):
    return s.encode("utf-16-be")

def canonicalize(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, (int, float)): return _num(v)
    if isinstance(v, str): return _str(v)
    if isinstance(v, (list, tuple)): return "[" + ",".join(canonicalize(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str): raise JCSError("non-string key")
        ks = sorted(v, key=_utf16_key)
        return "{" + ",".join(_str(k) + ":" + canonicalize(v[k]) for k in ks) + "}"
    raise JCSError("unsupported type %r" % type(v))

def canonical_bytes(v):
    return canonicalize(v).encode("utf-8")

def loads_strict(text):
    """Parse JSON rejecting duplicate keys (RFC 8785 sec 3.1 requires I-JSON)."""
    import json
    def hook(pairs):
        d = {}
        for k, val in pairs:
            if k in d: raise JCSError("duplicate key %r" % k)
            d[k] = val
        return d
    def bad(c): raise JCSError("non-finite literal " + c)
    return json.loads(text, object_pairs_hook=hook, parse_constant=bad)
