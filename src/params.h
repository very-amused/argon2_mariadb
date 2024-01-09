#pragma once
#include <stdint.h>
#include <stddef.h>
#include <argon2.h>

// This library uses a constant hash size of 32 bytes
#define ARGON2_MARIADB_HASH_LEN 32
#define ARGON2_MARIADB_SALT_LEN 16

// Time cost, memory cost, and threads (parallelism) provided as parameters to Argon2.
// This structure contains no dynamic allocations and can safely be freed by the caller.
typedef struct {
	argon2_type mode;
	uint32_t t_cost; // Time cost
	uint32_t m_cost; // Memory cost
	uint32_t parallelism; // Threads
	unsigned char salt[ARGON2_MARIADB_SALT_LEN];
} Argon2_MariaDB_Params;

static const Argon2_MariaDB_Params ARGON2_MARIADB_DEFAULT_PARAMS = {
	.mode = Argon2_id,
	.t_cost = 3, // 3 iterations
	.m_cost = 1 << 16, // 64MiB
#ifdef ARGON2_NO_THREADS
	.parallelism = 1
#else
	.parallelism = 4 // 4 threads
#endif
};

static const Argon2_MariaDB_Params ARGON2_MARIADB_MIN_PARAMS = {
	.t_cost = 3,
	.m_cost = 1 << 12, // 4MiB
	.parallelism = 1
};

static const Argon2_MariaDB_Params ARGON2_MARIADB_MAX_PARAMS = {
	.t_cost = 10,
	.m_cost = -1u,
	.parallelism = 4
};

// Set default params from ARGON2_MARIADB_DEFAULT_PARAMS
void Argon2_MariaDB_Params_default(Argon2_MariaDB_Params *params);
// Generate a cryptographically secure random salt.
// Relays return status from the system's SSL library.
int Argon2_MariaDB_Params_gensalt(Argon2_MariaDB_Params *params);

// Calculate the exact encoded length of params.
const size_t Argon2_MariaDB_Params_encoded_len(const Argon2_MariaDB_Params *params);

// Encode params as a UTF-8 string to result.
int Argon2_MariaDB_Params_encode(Argon2_MariaDB_Params *params, char *result, const size_t result_len);

// Decode params from result.
int Argon2_MariaDB_Params_decode(Argon2_MariaDB_Params *params, const char *result, const size_t result_len);
