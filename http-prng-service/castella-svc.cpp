// SPDX-FileCopyrightText: Steven Ward
// SPDX-License-Identifier: MPL-2.0

/// Castella HTTP PRNG service
/**
* \file
* \author Steven Ward
*/

#include "castella-duplex.hpp"
#include "config.h"
#include "httplib.h"
#include "quote_shell_always.hpp"
#include "spdlog/cfg/env.h"
#include "spdlog/spdlog.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <err.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <mutex>
#include <numeric>
#include <span>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <thread>
#include <type_traits>
#include <unistd.h>

inline constexpr std::string_view program_author = "Steven Ward";
inline constexpr std::string_view program_license = "MPL-2.0";
inline constexpr std::string_view program_version = "2026-01-30";

inline constexpr std::string_view default_host = "localhost";
inline constexpr uint16_t default_port = 8080;
const spdlog::level::level_enum default_log_level = spdlog::get_level(); // NOLINT(bugprone-throwing-static-initialization,cert-err58-cpp)

Castella::Duplex* hash_obj = nullptr;

std::mutex cv_mtx;

/**
* \c std::condition_variable_any::wait_for() accepts a \c std::stop_token, but
* \c std::condition_variable::wait_for() does not.
*/
std::condition_variable_any cv; // NOLINT(bugprone-throwing-static-initialization,cert-err58-cpp)

/// The number of consecutive bytes squeezed since high-quality entropy was
/// added to the Castella service
/**
* When `consec_bytes_sqzd ≥ max_consec_bytes_sqzd`, \c cv will awaken to get entropy.
*/
std::remove_const_t<decltype(max_consec_bytes_sqzd)> consec_bytes_sqzd = 0;

void
cleanup()
{
    delete hash_obj;
}

/// Get the default number of bytes to squeeze
unsigned int
get_default_num_bytes_to_squeeze()
{
    if (hash_obj != nullptr)
        return hash_obj->get_capacity_size_bytes() / 2;
    else
        return capacity_blocks * sizeof(Castella::block_t) / 2;
}

/// Print the version information.
void
print_version()
{
    fmt::println("{} {}", program_invocation_short_name, program_version);
    fmt::println("License {}", program_license);
    fmt::println("Written by {}", program_author);
}

/// Print the help message.
void
print_usage()
{
#define nl (void)std::putchar('\n')

    fmt::println("Usage: {} [OPTION]... [HOST]", program_invocation_short_name);
    nl;

    fmt::println("Start a Castella HTTP PRNG service.  Send SIGINT to stop it.");
    nl;

    fmt::println(R"(The server endpoints are "absorb" and "squeeze", just like for a sponge/duplex construction.)");
    nl;

    fmt::println(R"(All occurrences of "entropy" refer to high-quality entropy from getentropy(3).)");
    nl;

    fmt::println("Entropy is added to the Castella service after any of these conditions:");
    fmt::println("  1) {}s elapsed since entropy was added.", period_sec);
    fmt::println("  2) {} bytes were squeezed since entropy was added.",
            max_consec_bytes_sqzd);
    nl;

    fmt::println("OPTIONS");
    nl;

    fmt::println("  -V         Print the version information, then exit.");
    nl;

    fmt::println("  -h         Print this message, then exit.");
    nl;

    fmt::println("  -l LEVEL   Specify the log level.  (default={})",
            quote_shell_always(std::string_view{spdlog::level::to_string_view(default_log_level)}));
    fmt::println("             Valid log levels are:");
    fmt::println("             {}", std::to_array(SPDLOG_LEVEL_NAMES));
    fmt::println("             Alternatively, specify the log level in the environment variable \"SPDLOG_LEVEL\".");
    fmt::println("             Warning!  The \"trace\" log level prints the following sensitive data:");
    fmt::println("                 - The periodic entropy data added to the Castella hash object");
    fmt::println("                 - The body data of requests & responses");
    nl;

    fmt::println("  -p PORT    Specify the port.  (default={:d})", default_port);
    nl;

    fmt::println("The default HOST is {}.", quote_shell_always(default_host));
    nl;

    fmt::println("EXAMPLES");
    nl;

    fmt::println("Squeeze 32 bytes from the Castella service:");
    fmt::println(R"(    curl --show-error --silent "http://{}:{}/squeeze/32" )"
            "| basenc --wrap=0 --base58", default_host, default_port);
    nl;

    fmt::println("Squeeze bytes (default={}) from the Castella service:",
            get_default_num_bytes_to_squeeze());
    fmt::println(R"(    curl --show-error --silent "http://{}:{}/squeeze" )"
            "| basenc --wrap=0 --base58", default_host, default_port);
    fmt::println("The default number is equal to half the capacity of the Castella service.");
    nl;

    fmt::println("Send data to the Castella service to be absorbed:");
    fmt::println("    head --bytes=32 /dev/urandom | curl --data-binary @- "
            R"(--header "Content-Type: application/octet-stream" )"
            R"("http://{}:{}/absorb")", default_host, default_port);
    nl;

    fmt::println("REFERENCES");
    nl;

    fmt::println("Castella : https://github.com/planet36/Castella");
    fmt::println("HTTP server : https://github.com/yhirose/cpp-httplib");
    fmt::println("Logger : https://github.com/gabime/spdlog");
    fmt::println("Sponge/Duplex construction : https://keccak.team/sponge_duplex.html");
    nl;

#undef nl
}

void
periodic_add_entropy_func(std::stop_token token) // NOLINT(performance-unnecessary-value-param)
{
    constexpr auto period = std::chrono::seconds{period_sec};

    std::array<std::byte, periodic_entropy_size_bytes> entropy_buf{};

    static_assert(sizeof(entropy_buf) >= 8, "insufficient size of entropy buffer");

    static_assert(sizeof(entropy_buf) <= 256,
                  "getentropy will fail if more than 256 bytes are requested");

    const auto pred = [] { return consec_bytes_sqzd >= max_consec_bytes_sqzd; };

    while (!token.stop_requested())
    {
        std::unique_lock lock{cv_mtx};

        if (getentropy(std::data(entropy_buf), sizeof(entropy_buf)) < 0)
            err(EXIT_FAILURE, "getentropy");

        hash_obj->add(entropy_buf);

        if (spdlog::should_log(spdlog::level::level_enum::trace))
        {
            // XXX: This prints the entropy data.
            spdlog::trace("periodic add entropy: [{:02x}] ({})", fmt::join(entropy_buf, ""),
                          sizeof(entropy_buf));
        }
        else
        {
            spdlog::debug("periodic add entropy: {} bytes", sizeof(entropy_buf));
        }

        consec_bytes_sqzd = 0;

        entropy_buf.fill(std::byte{0}); // zeroize

        (void)cv.wait_for(lock, token, period, pred);
    }
}

void
process_req_squeeze(const httplib::Request& req, httplib::Response& res)
{
    // https://www.iana.org/assignments/media-types/application/octet-stream
    const std::string content_type{"application/octet-stream"};

    auto num_bytes_to_squeeze = get_default_num_bytes_to_squeeze();

    if (req.path_params.contains("num_bytes_to_squeeze"))
    {
        try
        {
            const auto tmp = std::stol(req.path_params.at("num_bytes_to_squeeze"));

            num_bytes_to_squeeze = std::saturating_cast<decltype(num_bytes_to_squeeze)>(tmp);
        }
        catch (const std::invalid_argument& ex)
        {
            num_bytes_to_squeeze = get_default_num_bytes_to_squeeze();
        }
        catch (const std::out_of_range& ex)
        {
            num_bytes_to_squeeze = get_default_num_bytes_to_squeeze();
        }
    }

    {
        std::unique_lock lock{cv_mtx};

        const auto digest = hash_obj->squeeze_bytes(num_bytes_to_squeeze);

        consec_bytes_sqzd = std::saturating_add(consec_bytes_sqzd, std::size(digest));

        res.set_content(reinterpret_cast<const char*>(std::data(digest)), std::size(digest),
                        content_type);
    }

    cv.notify_one();
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[])
{
    using namespace std::literals;

    if (std::atexit(cleanup) != 0)
        errx(EXIT_FAILURE, "std::atexit(cleanup) failed");

    // Do not create core dump files.
    if (constexpr rlimit rlim{.rlim_cur = 0, .rlim_max = 0};
        setrlimit(RLIMIT_CORE, &rlim) == -1)
        err(EXIT_FAILURE, "setrlimit(RLIMIT_CORE)");

    std::string host{default_host};
    auto port = default_port;

    // Try to read SPDLOG_LEVEL before getopt.
    // https://github.com/gabime/spdlog?tab=readme-ov-file#load-log-levels-from-the-env-variable-or-argv
    spdlog::cfg::load_env_levels();

    {
        const char* short_options = "+Vhl:p:";
        int c = 0;
        while ((c = getopt(argc, argv, short_options)) != -1)
        {
            switch (c)
            {
            case 'V':
                print_version();
                std::exit(EXIT_SUCCESS);
                break;

            case 'h':
                print_usage();
                std::exit(EXIT_SUCCESS);
                break;

            case 'l':
                spdlog::set_level(spdlog::level::from_str(optarg));
                break;

            case 'p':
                try
                {
                    const auto tmp = std::stol(optarg);
                    port = std::saturating_cast<decltype(port)>(tmp);
                }
                catch (const std::invalid_argument& ex)
                {
                    errx(EXIT_FAILURE, "invalid argument: %s: \"%s\"", ex.what(), optarg);
                }
                catch (const std::out_of_range& ex)
                {
                    errx(EXIT_FAILURE, "out of range: %s: \"%s\"", ex.what(), optarg);
                }
                break;

            default:
                std::exit(EXIT_FAILURE);
            }
        }
    }

    for (int i = optind; i < argc; ++i)
    {
        const std::string arg = argv[i];
        host = arg;
    }

    constexpr std::string_view function_name = "Castella";

    try
    {
        hash_obj = new Castella::Duplex(capacity_blocks, num_rounds, input_suffix,
                                        function_name, customization_str);
    }
    catch (const std::invalid_argument& ex)
    {
        errx(EXIT_FAILURE, "invalid argument: %s", ex.what());
    }

    {
        struct sigaction sa{};
        sa.sa_handler = SIG_IGN;

        (void)sigemptyset(&sa.sa_mask);

        // ignore SIGPIPE
        // (google for "Why should an HTTP server ignore the SIGPIPE signal?")
        if (sigaction(SIGPIPE, &sa, nullptr) == -1)
            err(EXIT_FAILURE, "sigaction(SIGPIPE)");
    }

    sigset_t sigset_mask{};

    if (sigemptyset(&sigset_mask) == -1)
        err(EXIT_FAILURE, "sigemptyset");

    // block/mask these signals

    if (sigaddset(&sigset_mask, SIGINT) == -1)
        err(EXIT_FAILURE, "sigaddset(SIGINT)");

    if (sigaddset(&sigset_mask, SIGTERM) == -1)
        err(EXIT_FAILURE, "sigaddset(SIGTERM)");

    if (sigaddset(&sigset_mask, SIGHUP) == -1)
        err(EXIT_FAILURE, "sigaddset(SIGHUP)");

    if (const int ret = pthread_sigmask(SIG_BLOCK, &sigset_mask, nullptr); ret != 0)
    {
        errno = ret; // pthread_sigmask does not set errno
        err(EXIT_FAILURE, "pthread_sigmask(SIG_BLOCK)");
    }

    std::jthread periodic_add_entropy_thread(periodic_add_entropy_func);

    httplib::Server svr;

    svr.Post("/absorb",
             [](const httplib::Request& req, [[maybe_unused]] httplib::Response& res)
             { hash_obj->add(std::data(req.body), std::size(req.body)); });

    // no path parameter
    svr.Get("/squeeze", process_req_squeeze);

    // path parameter given
    svr.Get("/squeeze/:num_bytes_to_squeeze", process_req_squeeze);

    svr.set_logger(
        [](const httplib::Request& req, const httplib::Response& res)
        {
            spdlog::debug("{} {} -> {}", req.method, req.path, res.status);

            // XXX: This prints the body data of requests & responses.
            spdlog::trace("[{:02x}] ({}) -> [{:02x}] ({})",
                fmt::join(std::as_bytes(std::span{req.body}), ""), std::size(req.body),
                fmt::join(std::as_bytes(std::span{res.body}), ""), std::size(res.body));
        });

    spdlog::info("Attempting to bind to http://{}:{} ...", host, port);

    if (!svr.bind_to_port(host, port))
    {
        periodic_add_entropy_thread.request_stop();

        errx(EXIT_FAILURE, "svr.bind_to_port(\"%s\", %d) failed", host.c_str(), port);
    }

    // Run the server on a separate thread.
    std::jthread server_thread(
        [&]()
        {
            spdlog::info("Begin listening on http://{}:{} ...", host, port);

            if (!svr.listen_after_bind())
                // Not thread safe, but this is an acceptable risk.
                errx(EXIT_FAILURE, "svr.listen_after_bind() failed");
        });

    while (true)
    {
        int rcvd_sig_num = 0;

        if (const int ret = sigwait(&sigset_mask, &rcvd_sig_num); ret != 0)
        {
            errno = ret; // sigwait does not set errno
            err(EXIT_FAILURE, "sigwait");
        }

        if (::isatty(STDOUT_FILENO))
            (void)std::putchar('\r'); // Over-write "^C" in the terminal.

        spdlog::info("Received signal {}: {}", rcvd_sig_num, strsignal(rcvd_sig_num));

        if ((rcvd_sig_num == SIGINT) ||
            (rcvd_sig_num == SIGTERM) ||
            (rcvd_sig_num == SIGHUP))
            break;
    }

    svr.stop();

    periodic_add_entropy_thread.request_stop();

    return EXIT_SUCCESS;
}
