# Castella HTTP PRNG service

An HTTP server that exposes `/absorb` and `/squeeze` endpoints backed by a Castella duplex PRNG, periodically reseeded from the OS (`getentropy`).

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
