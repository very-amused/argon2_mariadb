# Argon2-MariaDB
A library providing SQL bindings (supporting MariaDB/MySQL) for [Argon2's reference C implementation](https://github.com/P-H-C/phc-winner-argon2).

## Project State
This library is a work in progress and should NOT yet be considered production ready.

## Building
When changing the value of NO_PTHREAD, a clean build (`make clean && make`) is needed to ensure the changes are propagated across all files.
