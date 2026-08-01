# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Independent implementation of SPEC.md, verified against tests/KAT.txt.

This is a from-scratch Python implementation of the Castella permutation,
duplex, tree mode, and Compress-Castella hash, written from SPEC.md alone
(not translated from the C++).  It exists to prove that the specification
is complete and unambiguous: if this program reproduces every digest in
the KAT file, an implementer needs nothing but SPEC.md.

Usage: python3 spec-conformance.py [path/to/KAT.txt]

Pure Python, no dependencies.  Verifying all 58 KATs takes several seconds
(the point is independence, not speed).
"""

import sys
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import NoReturn, Protocol

# Every check below raises rather than asserts: `python3 -O` strips
# asserts, and tests/duplex-diff-fuzz.py relies on the parameter bounds
# here to catch drift against the ones it mirrors by hand.  Parameter
# violations raise ValueError, matching the std::invalid_argument the
# C++ throws for the same conditions.


class ModelInvariantError(Exception):
    """An internal invariant of this model does not hold (a bug in this file)."""


# ---- AES round (AESENC semantics: SubBytes, ShiftRows, MixColumns, XOR key)

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

XTIME = bytes(((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1 for x in range(256))


def aesenc(block: bytes, key: bytes) -> bytes:
    """Apply one AES encryption round (AESENC semantics) with round key."""
    # SubBytes
    b = bytes(SBOX[x] for x in block)
    # ShiftRows (column-major layout: byte index = 4*col + row; row r
    # rotates left by r)
    s = bytearray(16)
    for col in range(4):
        for row in range(4):
            s[4 * col + row] = b[4 * ((col + row) % 4) + row]
    # MixColumns, then AddRoundKey
    out = bytearray(16)
    for col in range(4):
        c = 4 * col
        s0, s1, s2, s3 = s[c], s[c + 1], s[c + 2], s[c + 3]
        out[c] = XTIME[s0] ^ XTIME[s1] ^ s1 ^ s2 ^ s3
        out[c + 1] = s0 ^ XTIME[s1] ^ XTIME[s2] ^ s2 ^ s3
        out[c + 2] = s0 ^ s1 ^ XTIME[s2] ^ XTIME[s3] ^ s3
        out[c + 3] = XTIME[s0] ^ s0 ^ s1 ^ s2 ^ XTIME[s3]
    return bytes(o ^ k for o, k in zip(out, key, strict=True))


# ---- Round constants (128-bit Galois LFSR, GCM polynomial)

MASK64 = (1 << 64) - 1


def lfsr_step(l0: int, l1: int) -> tuple[int, int]:
    """Advance the 128-bit Galois LFSR (GCM polynomial) by one step."""
    carry = l1 >> 63
    l1 = ((l1 << 1) | (l0 >> 63)) & MASK64
    l0 = ((l0 << 1) ^ (carry * 0x87)) & MASK64
    return l0, l1


def lfsr_stream() -> Iterator[bytes]:
    """Yield the LFSR states (as 16-byte blocks), 128 steps apart."""
    seed = b"expand 16-byte c"
    l0 = int.from_bytes(seed[0:8], "little")
    l1 = int.from_bytes(seed[8:16], "little")
    while True:
        yield l0.to_bytes(8, "little") + l1.to_bytes(8, "little")
        for _ in range(128):
            l0, l1 = lfsr_step(l0, l1)


def make_round_constants() -> tuple[list[list[list[bytes]]], list[bytes]]:
    """RC[r][aes_r][i] for 16 rounds x 3 AES rounds x 16 blocks, and the
    16 Compress-Castella initial-state blocks that follow them."""
    gen = lfsr_stream()
    rc = [[[next(gen) for _ in range(16)] for _ in range(3)] for _ in range(16)]
    cch_init = [next(gen) for _ in range(16)]
    return rc, cch_init


RC, CCH_INIT = make_round_constants()


# ---- The Castella permutation

def permute(state: list[bytes], n: int) -> list[bytes]:
    """Apply n rounds of the Castella permutation to the 16-block state."""
    if len(state) != 16:
        raise ModelInvariantError(
            f"permute: state has {len(state)} blocks, expected 16")
    if not 0 <= n <= 16:
        raise ValueError(f"permute: n is {n}, expected 0 <= n <= 16")
    for r in range(16 - n, 16):
        for aes_r in range(3):
            state = [aesenc(state[i], RC[r][aes_r][i]) for i in range(16)]
        # Transpose the 16x16 byte matrix (row i = block i).
        state = [bytes(state[j][i] for j in range(16)) for i in range(16)]
    return state


# ---- Integer encodings (little-endian, unlike SP 800-185)

def byte_width(x: int) -> int:
    """Return the minimum number of bytes needed to hold x (at least 1)."""
    return max(1, (x.bit_length() + 7) // 8)


def left_encode(x: int) -> bytes:
    """Encode x as a width byte followed by the little-endian value."""
    w = byte_width(x)
    return bytes([w]) + x.to_bytes(w, "little")


def right_encode(x: int) -> bytes:
    """Encode x as the little-endian value followed by a width byte."""
    w = byte_width(x)
    return x.to_bytes(w, "little") + bytes([w])


def encode_string(x: bytes) -> bytes:
    """Prefix x with its left-encoded byte length."""
    return left_encode(len(x)) + x


# ---- The Castella duplex

class Duplex:
    """Castella duplex/sponge, mirroring Castella::Duplex from the C++ library."""

    def __init__(self, C: int, num_rounds: int, suffix: int,
                 N: bytes, S: bytes):
        if C % 2 != 0:
            raise ValueError(f"Duplex: C is odd ({C})")
        if not 2 <= C <= 8:
            raise ValueError(f"Duplex: C is {C}, expected 2 <= C <= 8")
        if not 3 <= num_rounds <= 16:
            raise ValueError(f"Duplex: num_rounds is {num_rounds}, "
                             f"expected 3 <= num_rounds <= 16")
        self.C = C
        self.R = 16 - C
        self.num_rounds = num_rounds
        self.suffix = suffix
        self.state = [bytes(16)] * 16
        self.buf = bytearray()
        self.add(left_encode(256))
        self.add(left_encode(16 * self.R))
        self.add(left_encode(num_rounds))
        self.add(encode_string(N))
        self.add(encode_string(S))
        self._pad_and_permute()

    def _absorb_and_permute(self) -> None:
        if len(self.buf) != 16 * self.R:
            raise ModelInvariantError(
                f"Duplex absorb: buffer holds {len(self.buf)} bytes, "
                f"expected the full rate of {16 * self.R}")
        flat = bytearray(b"".join(self.state))
        for k in range(16 * self.R):
            flat[k] ^= self.buf[k]
        state = [bytes(flat[16 * i:16 * i + 16]) for i in range(16)]
        self.state = permute(state, self.num_rounds)
        self.buf.clear()

    def add(self, data: bytes) -> None:
        """Absorb data bytes, permuting whenever the rate fills."""
        for byte in data:
            self.buf.append(byte)
            if len(self.buf) == 16 * self.R:
                self._absorb_and_permute()

    def _pad_and_permute(self) -> None:
        if len(self.buf) >= 16 * self.R:  # never full here
            raise ModelInvariantError(
                f"Duplex pad: buffer holds {len(self.buf)} bytes, expected "
                f"fewer than the rate ({16 * self.R})")
        self.buf.append(0x01)
        while len(self.buf) < 16 * self.R:
            self.buf.append(0x00)
        self.buf[-1] |= 0x80
        self._absorb_and_permute()

    def squeeze(self, n: int) -> bytes:
        """Append the suffix, pad, permute, and return the first n bytes."""
        if not 0 <= n <= 16 * self.R:
            raise ValueError(f"Duplex.squeeze: n is {n}, expected "
                             f"0 <= n <= {16 * self.R}")
        self.add(bytes([self.suffix]))
        self._pad_and_permute()
        return b"".join(self.state)[:n]


# ---- Compress-Castella (non-cryptographic)

class CompressCastella:
    """Compress-Castella non-cryptographic compression node (see cch.hpp)."""

    def __init__(self, mix_rate: int):
        if mix_rate != 0 and not 1 <= mix_rate <= 2048:
            raise ValueError(f"CompressCastella: mix_rate is {mix_rate}, "
                             f"expected 0 or 1 <= mix_rate <= 2048")
        self.mix_rate = mix_rate
        mix_block = (mix_rate & 0xFFFF).to_bytes(2, "little") * 8
        self.state = [bytes(a ^ b for a, b in zip(blk, mix_block, strict=True))
                      for blk in CCH_INIT]
        self.buf = bytearray()
        self.absorbs_since_mix = 0
        self.has_been_finalized = False

    def _absorb_block(self) -> None:
        if len(self.buf) != 256:
            raise ModelInvariantError(
                f"cch compress: buffer holds {len(self.buf)} bytes, "
                f"expected 256")
        m = [bytes(self.buf[16 * i:16 * i + 16]) for i in range(16)]
        self.state = [aesenc(aesenc(aesenc(m[i], s), m[i]), s)
                      for i, s in enumerate(self.state)]
        self.buf.clear()
        if self.mix_rate > 0:
            self.absorbs_since_mix += 1
            if self.absorbs_since_mix >= self.mix_rate:
                self.state = permute(self.state, 3)
                self.absorbs_since_mix = 0

    def add(self, data: bytes) -> None:
        """Absorb data bytes, compressing whenever a 256-byte block fills.

        Finalization prevents further updates.  The check is
        unconditional, so an empty data raises too (as in cch.hpp).
        """
        if self.has_been_finalized:
            raise RuntimeError("CompressCastella.add: state is finalized")
        for byte in data:
            self.buf.append(byte)
            if len(self.buf) == 256:
                self._absorb_block()

    def digest(self, n: int) -> bytes:
        """Pad, compress, finalize with a permutation, return n bytes.

        Finalization happens on the first call only, so repeated
        extraction is idempotent (unlike a duplex squeeze).
        """
        if not 0 <= n <= 64:
            raise ValueError(f"CompressCastella.digest: n is {n}, expected "
                             f"0 <= n <= 64")
        if not self.has_been_finalized:
            i = 0
            while len(self.buf) < 256:  # padding bytes 0, 1, 2, ...
                self.buf.append(i & 0xFF)
                i += 1
            self._absorb_block()
            self.state = permute(self.state, 4)
            self.has_been_finalized = True
        return b"".join(self.state)[:n]


# ---- The tree mode

# A one-method protocol is the point, not too few methods.
# pylint: disable-next=too-few-public-methods
class TreeNode(Protocol):
    """All the tree needs of a node: it absorbs bytes.

    Extraction is not here -- Duplex squeezes and CompressCastella
    digests -- so tree_digest takes it as a separate callable.
    """

    def add(self, data: bytes) -> None:
        """Absorb data bytes."""


# pylint: disable=too-many-arguments
# pylint: disable=too-many-positional-arguments
def tree_digest[NodeT: TreeNode](make_node: Callable[[], NodeT],
                                 extract: Callable[[NodeT, int], bytes],
                                 chunk_size: int, cv_len: int,
                                 msg: bytes, out: int) -> bytes:
    """Compute the two-level tree-mode digest of msg."""
    chunks = [msg[i:i + chunk_size] for i in range(0, len(msg), chunk_size)]
    if not chunks:
        chunks = [b""]

    def role_prefix(role: int) -> bytes:
        return bytes([role]) + left_encode(chunk_size) + left_encode(cv_len)

    final = make_node()
    final.add(role_prefix(0x00))
    final.add(chunks[0])
    for i in range(1, len(chunks)):
        leaf = make_node()
        leaf.add(role_prefix(0x01))
        leaf.add(left_encode(i))
        leaf.add(chunks[i])
        final.add(extract(leaf, cv_len))
    final.add(right_encode(len(chunks) - 1))
    return extract(final, out)


# ---- KAT verification

# How many vectors tests/KAT.txt holds.  Checked only for that file, so a
# truncated or partly written one cannot report success on what it did
# read.  Update it deliberately when `kat --generate` changes the sweeps.
EXPECTED_KATS = 58


def kat_msg(msglen: int) -> bytes:
    """Build the KAT message of the given length (msg[i] = i mod 256)."""
    return bytes(i & 0xFF for i in range(msglen))


class KatFields(dict[str, str]):
    """The key=value fields of one KAT line, naming the line on any error."""

    def __init__(self, lineno: int, tokens: list[str]):
        for tok in tokens:
            if "=" not in tok:
                raise ValueError(
                    f"line {lineno}: field {tok!r} is not key=value")
        super().__init__(tok.split("=", 1) for tok in tokens)
        self.lineno = lineno

    def __missing__(self, key: str) -> NoReturn:
        raise ValueError(f"line {self.lineno}: missing field {key!r}")


def _duplex_from_kat(f: dict[str, str]) -> Duplex:
    """Build a Duplex node from the parsed KAT fields."""
    return Duplex(int(f["C"]), int(f["rounds"]), int(f["suffix"]),
                  bytes.fromhex(f["fn"]), bytes.fromhex(f["custom"]))


def _cch_from_kat(f: dict[str, str]) -> CompressCastella:
    """Build a CompressCastella node from the parsed KAT fields."""
    return CompressCastella(int(f["mix"]))


def verify_kat_file(path: str, expect_count: int | None = None) -> int:
    """Verify every KAT in the file; return 0 on full success, 1 otherwise.

    If expect_count is given, the file must hold exactly that many
    vectors: verifying fewer is a failure, not a success on a short file.
    """
    num_verified = 0
    num_failed = 0
    with open(path, encoding="ascii") as file:
        for lineno, line in enumerate(file, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            typ, *rest = line.split()
            f = KatFields(lineno, rest)
            msg = kat_msg(int(f["msglen"]))
            out = int(f["out"])
            expected = f["digest"]

            if typ == "duplex":
                node = _duplex_from_kat(f)
                node.add(msg)
                actual = node.squeeze(out)
            elif typ == "tree":
                actual = tree_digest(partial(_duplex_from_kat, f),
                                     lambda node, n: node.squeeze(n),
                                     int(f["chunk"]), 16 * int(f["C"]),
                                     msg, out)
            elif typ == "cchtree":
                actual = tree_digest(partial(_cch_from_kat, f),
                                     lambda node, n: node.digest(n),
                                     int(f["chunk"]), 64, msg, out)
            else:
                raise ValueError(f"line {lineno}: unknown KAT type {typ!r}")

            if actual.hex() == expected:
                num_verified += 1
            else:
                num_failed += 1
                print(f"FAILED: line {lineno}:")
                print(f"    expected digest = {expected}")
                print(f"    actual digest   = {actual.hex()}")
            print(f"\rline {lineno}: {num_verified} verified", end="",
                  flush=True)
    print(f"\r{path}: {num_verified} KATs verified, {num_failed} failed")
    if num_failed > 0:
        return 1
    if expect_count is None:
        return 0 if num_verified > 0 else 1
    if num_verified != expect_count:
        print(f"{path}: expected {expect_count} KATs, verified {num_verified}"
              " -- the file is incomplete, or EXPECTED_KATS is stale")
        return 1
    return 0


if __name__ == "__main__":
    # Relative to this file, not the working directory, so the script
    # runs from anywhere.
    DEFAULT_KAT = Path(__file__).resolve().parent.parent / "tests" / "KAT.txt"
    if len(sys.argv) > 1:
        sys.exit(verify_kat_file(sys.argv[1]))
    sys.exit(verify_kat_file(str(DEFAULT_KAT), EXPECTED_KATS))
