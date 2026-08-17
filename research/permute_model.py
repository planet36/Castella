# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

"""The shared model of the Castella permutation's layers.

The AES pieces (S-box, DDT, ShiftRows, MixColumns, one aesenc round) and the
simd_transpose map, factored out of permute-trail-search.py so that every
program modeling `P` uses one implementation, validated in one place by
self_test().

Pure standard library: importing this must not require z3, so
trail-model-crossvalidate.py can gate it from `make test` unconditionally.

spec-conformance.py must NEVER import this module.  It is the independent
from-the-spec implementation that trail-model-crossvalidate.py checks this
model against; sharing code between them would make that comparison circular.
"""

from collections.abc import Sequence
from itertools import batched

BLOCK_BYTES = 16
AES_NUM_ROUNDS = 3

type StateBytes = list[list[int]]               # a solved difference


class SelfTestError(Exception):
    """The S-box, DDT, or AES round model disagrees with a known value."""


def make_sbox() -> list[int]:
    """Build the AES S-box (GF(2^8) inverse composed with the affine map)."""
    # Multiplicative inverse in GF(2^8) mod 0x11B, then the AES affine map.
    def gf_mul(a: int, b: int) -> int:
        p = 0
        while b:
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return p

    inv = [0] * 256
    for x in range(1, 256):
        for y in range(1, 256):
            if gf_mul(x, y) == 1:
                inv[x] = y
                break

    def rol8(v: int, n: int) -> int:
        return ((v << n) | (v >> (8 - n))) & 0xFF

    return [inv[x] ^ rol8(inv[x], 1) ^ rol8(inv[x], 2) ^ rol8(inv[x], 3)
            ^ rol8(inv[x], 4) ^ 0x63 for x in range(256)]


SBOX = make_sbox()


def make_ddt() -> list[list[int]]:
    """Build the S-box difference distribution table DDT[din][dout]."""
    ddt = [[0] * 256 for _ in range(256)]
    for x in range(256):
        for din in range(256):
            ddt[din][SBOX[x] ^ SBOX[x ^ din]] += 1
    return ddt


DDT = make_ddt()

# For each nonzero din, the unique dout with DDT[din][dout] == 4.
DDT4_OUT = [0] * 256
for _din in range(1, 256):
    _fours = [d for d in range(256) if DDT[_din][d] == 4]
    if len(_fours) != 1:
        raise SelfTestError(f"AES DDT row {_din:#04x} has {len(_fours)} "
                            f"entries equal to 4, expected exactly one")
    DDT4_OUT[_din] = _fours[0]

# For each nonzero din, the douts with DDT[din][dout] != 0 (127 each).
DDT_ALLOWED = [[b for b in range(256) if DDT[a][b] != 0]
               for a in range(256)]


def xtime(a: int) -> int:
    """Multiply a by x in GF(2^8) mod the AES polynomial 0x11B."""
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


# AES ShiftRows: output byte (row, col) comes from input byte (row, (col+row)%4).
# Byte index within a block = 4*col + row (AES column-major order), matching
# permute-min-active-sboxes.py and the aesenc byte order.
def shift_rows_src(byte_idx: int) -> int:
    """Return the input byte index that ShiftRows moves to byte_idx."""
    col, row = divmod(byte_idx, 4)
    return 4 * ((col + row) % 4) + row


def mix_column(col: Sequence[int]) -> list[int]:
    """Apply the AES MixColumns transform to one 4-byte column."""
    a0, a1, a2, a3 = col
    return [xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
            a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
            xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)]


def aes_round_zero_key(state: list[int]) -> list[int]:
    """Apply one AESENC round with a zero round key to a 16-byte state."""
    # aesenc order: ShiftRows, SubBytes, MixColumns, AddRoundKey (key = 0).
    sr = [state[shift_rows_src(b)] for b in range(BLOCK_BYTES)]
    sb = [SBOX[v] for v in sr]
    out = []
    for col in batched(sb, 4):
        out += mix_column(col)
    return out


# simd_transpose: byte k of word j of block i -> byte k of word i of block j,
# where a word is 16/N bytes.  Returns {(block, byte): (block, byte)}.
def transpose_map(num_blocks: int) -> dict[tuple[int, int], tuple[int, int]]:
    """Map each (block, byte) to its destination under simd_transpose."""
    word_size = BLOCK_BYTES // num_blocks
    mapping = {}
    for i in range(num_blocks):
        for b in range(BLOCK_BYTES):
            j, k = divmod(b, word_size)
            mapping[(i, b)] = (j, i * word_size + k)
    return mapping


# Known-answer (input, output) pairs for one AES round with a zero round key,
# captured from the _mm_aesenc_si128 hardware instruction on x86-64
# (2026-07-19); self_test() checks this file's Python AES model against them.
AESENC_VECTORS = [
    ("00000000000000000000000000000000", "63636363636363636363636363636363"),
    ("000102030405060708090a0b0c0d0e0f", "6a6a5c452c6d3351b0d95d61279c215c"),
    ("53000000000000000000000000000000", "64ededea636363636363636363636363"),
    ("0718293a4b5c6d7e8fa0b1c2d3e4f506", "e87db50820d91fd30ba645a43946dc71"),
]


def self_test() -> None:
    """Sanity-check the S-box, DDT, and AES round model against known values.

    Raises SelfTestError on any mismatch.  Deliberately not `assert`: this
    runs on every invocation, not only under --self-test, and an
    assert-based version would pass vacuously under `python3 -O`.
    """
    for din, want in ((0x00, 0x63), (0x53, 0xED), (0xFF, 0x16)):
        if SBOX[din] != want:
            raise SelfTestError(f"S-box: S[{din:#04x}] is {SBOX[din]:#04x}, "
                                f"expected {want:#04x}")
    for din in range(1, 256):
        for dout, entry in enumerate(DDT[din]):
            if entry not in (0, 2, 4):
                raise SelfTestError(
                    f"DDT[{din:#04x}][{dout:#04x}] is {entry}, expected "
                    f"0, 2 or 4")
    for din in range(256):
        total = sum(DDT[din])
        if total != 256:
            raise SelfTestError(f"DDT row {din:#04x} sums to {total}, "
                                f"expected 256")
    for hex_in, hex_out in AESENC_VECTORS:
        state = list(bytes.fromhex(hex_in))
        got = aes_round_zero_key(state)
        if got != list(bytes.fromhex(hex_out)):
            raise SelfTestError(
                f"AES round model mismatch for input {hex_in}: got "
                f"{bytes(got).hex()}, expected {hex_out}")


def hex_state(state_bytes: StateBytes) -> str:
    """Format a state's blocks as space-separated hex strings."""
    return " ".join("".join(f"{v:02x}" for v in block)
                    for block in state_bytes)


# Run on import, like the DDT4_OUT check above: every program that models `P`
# then gets the same validated layers, so no importer has to remember to check
# what it borrows.  1.7 ms against a 29 ms import.
self_test()
