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

## Functions

### ARGON2_PARAMS() -> string
Select a new set of Argon2\[i|d|id\] parameters encoded as a string. Params should be stored in a `varchar(255)` column.
Can be called in two forms:

- `ARGON2_PARAMS()`
Select default parameters and generate a cryptographically random salt. See `ARGON2_MARIADB_DEFAULT_PARAMS` in `params.h`.

- `ARGON2_PARAMS(mode, t_cost, m_cost, parallelism)`
Select and validate custom parameters and generate a cryptographically random salt.
Parameters:
	- `mode`: `[argon]2{i|d|id}` (string, i.e `argon2d` `2id`)
	- `t_cost`: Time cost in iterations (integer, min: 3, max: 10, i.e `4`)
	- `m_cost`: Memory cost in KiB (integer, min: 4096 = 4MiB, i.e `1 << 16` = 64MiB)
	- `parallelism`: Number of threads to use (integer, min: 1, max: 4, i.e `2`)

### ARGON2(params, password, \[encoding\]) -> string|bytes
Get the Argon2 hash of `password` using `params`.
Parameters:
  - `params`: An Argon2 parameter string in the form used by `ARGON2_PARAMS()`
	- `password`: A password string
	- `encoding`: OPTIONAL: An integer describing the desired result encoding
		- `0`: DEFAULT: A full encoded hash string compatible with other Argon2 libraries, includes parameters.
		- `1`: The hash itself in raw binary form (32 bytes).
		- `2`: The hash itself encoded in base64 (no padding).

### ARGON2_VERIFY(hash, password) -> bool
Verify whether `password` is equal to the password used to create `hash`.
Parameters:
  - `hash`: A full Argon2 encoded hash string, including parameters
	- `password`: A password string
