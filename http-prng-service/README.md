# Castella HTTP PRNG service

An HTTP server that exposes `/absorb` and `/squeeze` endpoints backed by a Castella duplex PRNG, periodically reseeded from the OS (`getentropy`).

## Trust model

The service is **one shared pool with no caller isolation**.  Every client of the port reads and writes the same duplex state: `/absorb` mutates the state that other callers' `/squeeze` requests later draw from, and nothing distinguishes one caller from another.  This is by design for a local pool — it is not a per-caller randomness source like `getrandom(2)` or `/dev/urandom`, and it is not multi-tenant.

The default `HOST` keeps it on the loopback interface.  Bind it elsewhere only if every process that can reach that address is trusted.

The service does not begin accepting requests until it has absorbed entropy from `getentropy(3)`, so a client is never served from the initial state — which is derived only from the public constants in [config.h](config.h).

## Dependencies

[spdlog](https://github.com/gabime/spdlog) (header-only use) must be installed.

## Usage

Run `make` to build the service.

Run `./castella-svc -h` for help.

To start the service, run `./castella-svc`.

To test the service, run `sh test-client.sh` in another terminal.

To stop the service, send `SIGINT`, `SIGTERM`, or `SIGHUP` to it.  (For example, press _Ctrl+C_ in the terminal where the service is running.)

## External file

[httplib.h](https://raw.githubusercontent.com/yhirose/cpp-httplib/refs/heads/master/httplib.h) is an external dependency ([cpp-httplib](https://github.com/yhirose/cpp-httplib)) that is **committed to this repository** and updated in-tree as upstream changes.  The Makefile downloads it from the GitHub repo only as a fallback when the file is missing; because it is tracked, it is normally restored with `git checkout -- http-prng-service/httplib.h` rather than re-downloaded.
