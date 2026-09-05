// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Emit an endless Castella duplex PRNG byte stream to stdout
/**
* \file
* The PRNG usage of the duplex.  Absorb a fixed seed string, so the stream is
* reproducible, then repeatedly squeeze the full rate to stdout.  Intended
* for piping into a statistical test battery such as PractRand:
*
*     ./duplex-prng-stream -C 4 -r 6 | RNG_test stdin64 -tlmax 16GB
*
* The stream never ends, and the consumer cuts it, since SIGPIPE terminates
* this program.  Statistical batteries are a smoke test only.  Passing means
* nothing cryptographically, and failing at 3 or more rounds would mean
* everything.
*/

#include "castella-duplex.hpp"
#include "parse_int.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <err.h>
#include <unistd.h>
#include <vector>

// {{{ options
int capacity_blocks = 4;
int num_rounds = 6;
// }}}

/// Process the command line options
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays)
void process_options(int argc, char* argv[])
{
    const char* short_options = "+C:r:";
    int c = 0;
    while ((c = getopt(argc, argv, short_options)) != -1)
    {
        switch (c) // NOLINT(hicpp-multiway-paths-covered)
        {
        case 'C':
            capacity_blocks = parse_option_int(optarg, Castella::Duplex::C_MIN,
                                               Castella::Duplex::C_MAX, "-C");
            break;

        case 'r':
            num_rounds = parse_option_int(optarg,
                                          Castella::NUM_ROUNDS_MIN<Castella::Duplex::B>(),
                                          Castella::NUM_ROUNDS_MAX, "-r");
            break;

        default:
            std::exit(EXIT_FAILURE);
        }
    }
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    process_options(argc, argv);

    Castella::Duplex duplex{capacity_blocks, num_rounds};

    duplex.add("duplex-prng-stream seed");

    std::vector<std::byte> buf(static_cast<size_t>(duplex.get_rate_size_bytes()));

    while (true)
    {
        duplex.squeeze_to(buf);
        if (std::fwrite(std::data(buf), 1, std::size(buf), stdout) != std::size(buf))
        {
            // A closed reader is not an error.
            if (errno != EPIPE)
            {
                err(EXIT_FAILURE, "fwrite");
            }
            break;
        }
    }

    return 0;
}
