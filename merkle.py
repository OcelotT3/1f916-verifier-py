"""RFC 6962 / RFC 9162 Merkle tree hashing and proof verification (from RFC text)."""
import hashlib, re

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
MAX_SAFE = 2**53 - 1  # spec 5a: "safe" integers; we adopt the JS safe-integer range as the bound

class ProofError(ValueError):
    pass

def check_hex64(h, what="hash"):
    if not isinstance(h, str) or not HEX64.match(h):
        raise ProofError("%s is not exactly 64 lowercase hex chars: %r" % (what, h))
    return bytes.fromhex(h)

def check_uint(n, what="integer"):
    if isinstance(n, bool) or not isinstance(n, int) or n < 0 or n > MAX_SAFE:
        raise ProofError("%s is not a safe non-negative integer: %r" % (what, n))
    return n

def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()

def node_hash(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()

def event_leaf(hash_hex: str) -> bytes:
    """1F916 leaf: the lowercase-hex chain hash AS UTF-8 TEXT (64 bytes), not decoded."""
    check_hex64(hash_hex, "leaf hash")
    return leaf_hash(hash_hex.encode("ascii"))

def mth(leaves):
    """Merkle Tree Hash of a list of leaf byte strings (RFC 6962 2.1)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))

def inclusion_path(m, leaves):
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return inclusion_path(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(m - k, leaves[k:]) + [mth(leaves[:k])]

def consistency_path(m, leaves):
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    return sub(m, leaves, True)

def verify_inclusion(leaf_index, tree_size, leaf_h: bytes, proof_hex, root_hex) -> None:
    """RFC 9162 2.1.3.2. Raises ProofError on failure."""
    check_uint(leaf_index, "leaf_index"); check_uint(tree_size, "tree_size")
    root = check_hex64(root_hex, "root")
    if not isinstance(proof_hex, list):
        raise ProofError("proof is not a list")
    path = [check_hex64(p, "proof[%d]" % i) for i, p in enumerate(proof_hex)]
    if leaf_index >= tree_size:
        raise ProofError("leaf_index >= tree_size")
    fn, sn, r = leaf_index, tree_size - 1, leaf_h
    for p in path:
        if sn == 0:
            raise ProofError("proof too long")
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2; sn //= 2
        else:
            r = node_hash(r, p)
        fn //= 2; sn //= 2
    if sn != 0:
        raise ProofError("proof too short")
    if r != root:
        raise ProofError("computed root %s != %s" % (r.hex(), root_hex))

def verify_consistency(first, second, first_root_hex, second_root_hex, proof_hex) -> None:
    """RFC 9162 2.1.4.2. Raises ProofError on failure."""
    check_uint(first, "from tree_size"); check_uint(second, "to tree_size")
    r1 = check_hex64(first_root_hex, "from root"); r2 = check_hex64(second_root_hex, "to root")
    if not isinstance(proof_hex, list):
        raise ProofError("proof is not a list")
    path = [check_hex64(p, "proof[%d]" % i) for i, p in enumerate(proof_hex)]
    if first > second:
        raise ProofError("first > second (regression)")
    if first == second:
        if path:
            raise ProofError("non-empty proof for equal sizes")
        if r1 != r2:
            raise ProofError("equal sizes, different roots")
        return
    if first == 0:
        # RFC 9162: consistency from the empty tree is trivially true; proof must be empty
        if path:
            raise ProofError("non-empty proof from size 0")
        return
    if not path:
        raise ProofError("empty proof")
    if first & (first - 1) == 0:  # exact power of two: prepend first_hash (integer test, no shifts on size)
        path = [r1] + path
    fn, sn = first - 1, second - 1
    while fn % 2 == 1:
        fn //= 2; sn //= 2
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ProofError("proof too long")
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr); sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2; sn //= 2
        else:
            sr = node_hash(sr, c)
        fn //= 2; sn //= 2
    if sn != 0:
        raise ProofError("proof too short")
    if fr != r1:
        raise ProofError("reconstructed old root mismatch")
    if sr != r2:
        raise ProofError("reconstructed new root mismatch")
