# Argon2_MariaDB
A library providing SQL bindings (supporting MariaDB/MySQL) for [Argon2's reference C implementation](https://github.com/P-H-C/phc-winner-argon2).

## Project State
This library has not received large amounts of production testing, but should be considered ready for use in non-critical deployments.

## Building
```make```

### Build Flags
- `NO_SIMD`: disable Argon2 SIMD instructions
- `NO_PTHREAD`: disable Argon2 support for multiple threads (***WARNING***: standard builds (without NO_PTHREAD) default to a parallelism value of 4. Due to this design, I highly advise <ins>against</ins> building with NO_PTHREAD, but still provide the option.)

i.e `make NO_SIMD=true NO_PTHREAD=true` will build with no threading or SIMD support.

When changing the value of NO_PTHREAD, a clean build (`make clean && make`) is needed to ensure the change is propagated across all files.

## Installation
```make install```

## Dependencies
Runtime dependencies: mariadb or mysql, openssl 3.0+
Build dependencies: Standard GNU toolchain (compatibility with FreeBSD toolchain to be tested)
