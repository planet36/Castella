# Castella HTTP PRNG service

## Usage

Run `make` to build the service.

Run `./castella-svc -h` for help.

To start the service, run `./castella-svc`.

To test the service, run `sh test-client.sh` in another terminal.

To stop the service, send `SIGINT` to it.  (For example, press _Ctrl+C_ in the terminal where the service is running.)

## External file

[httplib.h](https://raw.githubusercontent.com/yhirose/cpp-httplib/refs/heads/master/httplib.h) is downloaded from its GitHub repo https://github.com/yhirose/cpp-httplib.
