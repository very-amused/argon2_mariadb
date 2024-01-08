#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// This library uses a constant hash size of 32 bytes
static const size_t ARGON2_MARIADB_HASH_LEN = 32;
static const size_t ARGON2_MARIADB_SALT_LEN = 16;

// Time cost, memory cost, and threads (parallelism) provided as parameters to Argon2.
// This structure contains no dynamic allocations and can safely be freed by the caller.
typedef struct {
	uint32_t t_cost; // Time cost
	uint32_t m_cost; // Memory cost
	uint32_t parallelism; // Threads
	unsigned char salt[ARGON2_MARIADB_SALT_LEN];
} Argon2_MariaDB_Params;

static const Argon2_MariaDB_Params ARGON2_MARIADB_DEFAULT_PARAMS = {
	.t_cost = 3, // 3 iterations
	.m_cost = 1 << 16, // 64MiB
	.parallelism = 4 // 4 threads
};

// Set default params from ARGON2_MARIADB_DEFAULT_PARAMS
void Argon2_MariaDB_Params_default(Argon2_MariaDB_Params *params);
// Generate a cryptographically secure random salt
void Argon2_MariaDB_Params_gensalt(Argon2_MariaDB_Params *params);

// Encode params as a UTF-8 string to result.
// *result will be heap-allocated and result_len set accordingly.
int Argon2_MariaDB_Params_encode(Argon2_MariaDB_Params *params, char **result, size_t *result_len);

// Decode params from result.
int Argon2_MariaDB_Params_decode(Argon2_MariaDB_Params *params, const char *result, const size_t result_len);
