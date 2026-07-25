# SPDX-FileCopyrightText: Steven Ward
# SPDX-License-Identifier: MPL-2.0

# pylint: disable=invalid-name

"""Differential fuzzer: Castella::Duplex against the SPEC.md model.

Generates random programs of duplex API calls -- interleaved add,
add_left_encoded, add_right_encoded, apply_padding_rule and squeeze_bytes,
over random constructor parameters -- and checks that the C++ library and the
independent Python model in spec-conformance.py agree on every squeeze.

A program is one generated unit of work: constructor parameters plus a call
sequence ending in at least one squeeze.  It is not a single comparison -- one
program yields as many comparisons as it has squeezes, which is why the summary
counts both.

This covers what KAT.txt cannot: every duplex KAT is a single add followed by a
single squeeze, so split and streamed adds, both encoding entry points,
explicit padding, and successive squeezes are otherwise unverified against the
spec.

The C++ side is driven by duplex-diff-driver, which must be built first:

    make duplex-diff-driver
    python3 duplex-diff-fuzz.py

The whole run is batched through one driver process, because the pure-Python
model is the slow side.  The seed defaults to a fixed value so `make test` is
deterministic; pass --seed to explore new programs, as with equivalence-tests.

Usage: python3 duplex-diff-fuzz.py [-n PROGRAMS] [--seed SEED] [--driver PATH]
"""

import argparse
import importlib.util
import random
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DRIVER = HERE / "duplex-diff-driver"
MODEL_PATH = HERE.parent / "research" / "spec-conformance.py"

# "Castell" -- the same default seed as equivalence-tests.cpp
DEFAULT_SEED = 0x436173_74656C6C
SEED_MAX = 2**64  # exclusive, matching equivalence-tests' uint64_t seed


def seed_arg(s):
    """Parse a seed: decimal or 0x-prefixed, within [0, 2**64)."""
    try:
        value = int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid seed: {s!r}") from None
    if not 0 <= value < SEED_MAX:
        raise argparse.ArgumentTypeError(f"seed not in [0, 2**64): {s}")
    return value


def load_model():
    """Import spec-conformance.py (its hyphen blocks a plain import)."""
    spec = importlib.util.spec_from_file_location("spec_conformance", MODEL_PATH)
    if spec is None or spec.loader is None:
        sys.exit(f"cannot load the model at {MODEL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # the __main__ guard keeps this cheap
    return module


model = load_model()

# ---- Program generation

CAPACITIES = (2, 4, 6, 8)  # C_MIN..C_MAX, even

# Values straddling every byte_width transition reachable in a uint64_t.  The
# integer encodings absorb only byte_width(x) + 1 bytes, so these are free.
INT_VALUES = (0, 1, 2, 127, 128, 254, 255, 256, 257, 65535, 65536, 65537,
              2**24 - 1, 2**24, 2**32 - 1, 2**32, 2**56 - 1, 2**56,
              2**64 - 1)

# Ops that absorb; a squeeze is appended separately.
ABSORB_OPS = ("add", "addle", "addre", "addlei", "addrei", "pad")


class Program:
    """One generated program: constructor parameters plus a list of ops."""

    # pylint: disable=too-few-public-methods
    # pylint: disable=too-many-arguments
    # pylint: disable=too-many-positional-arguments
    def __init__(self, prog_id, C, rounds, suffix, N, S, ops):
        self.prog_id = prog_id
        self.C = C
        self.rounds = rounds
        self.suffix = suffix
        self.N = N
        self.S = S
        self.ops = ops


def gen_bytes(rng, n):
    """Build n pseudorandom bytes."""
    return bytes(rng.randrange(256) for _ in range(n))


def gen_len(rng, rate):
    """Pick a byte-string length, biased to the interesting boundaries."""
    if rng.random() < 0.65:
        return rng.choice((0, 1, 2, 15, 16, 17, 127, 128,
                           254, 255, 256, 257,
                           rate - 1, rate, rate + 1,
                           2 * rate - 1, 2 * rate, 2 * rate + 1))
    return rng.randrange(0, 2 * rate + 2)


def gen_squeeze_len(rng, C):
    """Pick a squeeze length within [0, rate]; the C++ clamp is out of scope."""
    rate = 16 * (16 - C)
    if rng.random() < 0.5:
        return rng.choice((0, 1, 2, 16, 16 * C // 2, rate - 1, rate))
    return rng.randrange(0, rate + 1)


def gen_program(rng, prog_id):
    """Generate one random program."""
    C = rng.choice(CAPACITIES)
    rate = 16 * (16 - C)
    rounds = rng.randint(3, 16)
    suffix = rng.choice((0, 0x01, 0x1F, 0x80, 0xFF, rng.randrange(256)))
    N = gen_bytes(rng, rng.choice((0, 0, 1, 7, 8, 16, 32)))
    S = gen_bytes(rng, rng.choice((0, 0, 1, 7, 8, 16, 32)))

    ops = []
    for _ in range(rng.randint(1, 7)):
        op = rng.choice(ABSORB_OPS)
        if op in ("addlei", "addrei"):
            value = (rng.choice(INT_VALUES) if rng.random() < 0.75
                     else rng.randrange(2**64))
            ops.append((op, value))
        elif op == "pad":
            ops.append((op,))
        else:
            ops.append((op, gen_bytes(rng, gen_len(rng, rate))))

        if rng.random() < 0.15:  # an interleaved squeeze
            ops.append(("squeeze", gen_squeeze_len(rng, C)))

    ops.append(("squeeze", gen_squeeze_len(rng, C)))
    return Program(prog_id, C, rounds, suffix, N, S, ops)


# ---- The two sides

def hex_field(data):
    """Render a byte string as a script field ("-" when empty)."""
    return data.hex() if data else "-"


def script_lines(program):
    """Render a program as driver script lines."""
    new_op = (f"new {program.C} {program.rounds} {program.suffix} "
              f"{hex_field(program.N)} {hex_field(program.S)}")
    lines = [f"program {program.prog_id}", new_op]
    for op in program.ops:
        if op[0] == "pad":
            lines.append("pad")
        elif op[0] in ("addlei", "addrei", "squeeze"):
            lines.append(f"{op[0]} {op[1]}")
        else:
            lines.append(f"{op[0]} {hex_field(op[1])}")
    return lines


def run_model(program):
    """Replay a program against the Python model; return the squeeze digests."""
    duplex = model.Duplex(program.C, program.rounds, program.suffix,
                          program.N, program.S)
    digests = []

    for op in program.ops:
        name = op[0]
        if name == "add":
            duplex.add(op[1])
        elif name == "addle":
            duplex.add(model.encode_string(op[1]))
        elif name == "addre":
            duplex.add(op[1] + model.right_encode(len(op[1])))
        elif name == "addlei":
            duplex.add(model.left_encode(op[1]))
        elif name == "addrei":
            duplex.add(model.right_encode(op[1]))
        elif name == "pad":
            # The C++ apply_padding_rule() is public, but the model keeps its
            # pad10*1 step internal (it is called by __init__ and squeeze), so
            # there is no public counterpart to drive.  Reaching in is the
            # point of the op: explicit padding is otherwise untested.
            duplex._pad_and_permute()  # pylint: disable=protected-access
        elif name == "squeeze":
            digests.append(duplex.squeeze(op[1]).hex())
        else:
            raise ValueError(f"unknown op {name!r}")

    return digests


def run_driver(driver, script):
    """Run every program through one driver process; return per-program digests."""
    try:
        proc = subprocess.run([str(driver)], input=script, capture_output=True,
                              text=True, check=False)
    except OSError as e:
        sys.exit(f"cannot run {driver}: {e}\nBuild it with: make {DEFAULT_DRIVER.name}")

    if proc.returncode != 0:
        sys.exit(f"{driver} failed ({proc.returncode}): {proc.stderr.strip()}")

    results = {}
    prog_id = None
    for line in proc.stdout.splitlines():
        head, _, rest = line.partition(" ")
        if head == "program":
            prog_id = rest
            results[prog_id] = []
        elif head == "out":
            if prog_id is None:
                sys.exit(f"driver produced output before any program: {line!r}")
            results[prog_id].append(rest)
        else:
            sys.exit(f"unexpected driver output: {line!r}")

    return results


def report_failure(program, expected, got):
    """Print a diverging program: its script, then every differing squeeze."""
    print(f"FAILED: program {program.prog_id}:")
    for line in script_lines(program):
        print(f"    {line}")
    for i, (e, a) in enumerate(zip(expected, got)):
        if e != a:
            print(f"    squeeze {i}: model  = {e}")
            print(f"    squeeze {i}: driver = {a}")
    if len(expected) != len(got):
        print(f"    squeeze count: model = {len(expected)}, driver = {len(got)}")


def main():
    """Generate programs, run both sides, and report any divergence."""
    parser = argparse.ArgumentParser(
        description="Differential fuzzer for Castella::Duplex vs the SPEC.md model.")
    parser.add_argument("-n", "--num-programs", type=int, default=200,
                        help="number of programs to generate (default: 200)")
    parser.add_argument("--seed", type=seed_arg, default=DEFAULT_SEED,
                        help="PRNG seed, decimal or 0x-prefixed "
                             "(default: fixed, so runs are reproducible)")
    parser.add_argument("--driver", type=Path, default=DEFAULT_DRIVER,
                        help=f"path to the driver (default: {DEFAULT_DRIVER.name})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print each program's script and digests")
    args = parser.parse_args()

    print(f"seed = {args.seed:#x} (pass --seed to reproduce)")
    rng = random.Random(args.seed)

    programs = [gen_program(rng, f"p{i}") for i in range(args.num_programs)]
    script = "".join("\n".join(script_lines(p)) + "\n" for p in programs)

    if args.verbose:
        print(script, end="")

    actual = run_driver(args.driver, script)

    show_progress = sys.stdout.isatty()  # the \r line only helps a terminal
    num_checked = 0
    num_failed = 0
    for program in programs:
        expected = run_model(program)
        got = actual.get(program.prog_id)

        if got is None:
            print(f"FAILED: program {program.prog_id}: no driver output")
            num_failed += 1
            continue

        if got == expected:
            num_checked += len(expected)
        else:
            num_failed += 1
            report_failure(program, expected, got)

        if show_progress:
            print(f"\r{num_checked} squeezes verified", end="", flush=True)

    print(f"\r{args.num_programs} programs, {num_checked} squeezes verified, "
          f"{num_failed} failed")
    return 0 if num_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
