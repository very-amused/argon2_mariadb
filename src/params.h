#pragma once
#include <stdint.h>
#include <stddef.h>
#include <argon2.h>

// This library uses a constant hash size of 32 bytes
#define ARGON2_MARIADB_HASH_LEN 32
#define ARGON2_MARIADB_SALT_LEN 16

// Time cost, memory cost, and threads (parallelism) provided as parameters to Argon2.
typedef struct {
	argon2_type mode;
	uint32_t t_cost; // Time cost
	uint32_t m_cost; // Memory cost
	uint32_t parallelism; // Threads
	unsigned char salt[ARGON2_MARIADB_SALT_LEN];
} Argon2MariaDBParams;

static const Argon2MariaDBParams ARGON2_MARIADB_DEFAULT_PARAMS = {
	.mode = Argon2_id,
	.t_cost = 3, // 3 iterations
	.m_cost = 1 << 16, // 64MiB
#ifdef ARGON2_NO_THREADS
	.parallelism = 1
#else
	.parallelism = 4 // 4 threads
#endif
};

static const Argon2MariaDBParams ARGON2_MARIADB_MIN_PARAMS = {
	.mode = Argon2_d,
	.t_cost = 3,
	.m_cost = 1 << 12, // 4MiB
	.parallelism = 1
};

static const Argon2MariaDBParams ARGON2_MARIADB_MAX_PARAMS = {
	.mode = Argon2_id,
	.t_cost = 10,
	.m_cost = -1u,
	.parallelism = 4
};

// Set default params from ARGON2_MARIADB_DEFAULT_PARAMS
void Argon2MariaDBParams_default(Argon2MariaDBParams *params);
// Set and validate all required numerical params (salt generation is still needed).
// Returns nonzero if validation fails.
int Argon2MariaDBParams_set(Argon2MariaDBParams *params,
		const char *mode, const size_t mode_len, uint32_t t_cost, uint32_t m_cost, uint32_t parallelism);
// Generate a cryptographically secure random salt.
// Returns nonzero on failure.
__attribute__((warn_unused_result))
int Argon2MariaDBParams_gensalt(Argon2MariaDBParams *params);

// Calculate the exact encoded length of params.
const size_t Argon2MariaDBParams_encoded_len(const Argon2MariaDBParams *params);
// Encode params as a UTF-8 string to result.
// No null termination is performed.
int Argon2MariaDBParams_encode(const Argon2MariaDBParams *params, char *result, const size_t result_len);
// Decode params from result.
int Argon2MariaDBParams_decode(Argon2MariaDBParams *params, const char *result, const size_t result_len);

// Validate params.
int Argon2MariaDBParams_validate(const Argon2MariaDBParams *params);

// argon2[i|d|id]_hash_encoded
typedef int (*Argon2MariaDBParams_encoded_hash_fn)(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism,
		const void *pwd, const size_t pwdlen,
		const void *salt, const size_t saltlen,
		const size_t hashlen,
		char *encoded, const size_t encodedlen);
// Get the appropriate argon2 encoded hash function from params->mode
#define ARGON2_MARIADB_ENCODED_HASHFN(mode, fn) \
	switch (mode) { \
	case Argon2_d: \
		fn = &argon2d_hash_encoded; \
		break; \
	case Argon2_i: \
		fn = &argon2i_hash_encoded; \
		break; \
	case Argon2_id: \
		fn = &argon2id_hash_encoded; \
	}
		
// argon2[i|d|id]_hash_raw
typedef int (*Argon2MariaDBParams_raw_hash_fn)(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism,
			const void *pwd, const size_t pwdlen,
			const void *salt, const size_t saltlen,
			void *hash, const size_t hashlen);
// Get the appropriate argon2 raw hash function from params->mode
#define ARGON2_MARIADB_RAW_HASHFN(mode, fn) \
	switch (mode) { \
	case Argon2_d: \
		fn = &argon2d_hash_raw; \
		break; \
	case Argon2_i: \
		fn = &argon2i_hash_raw; \
		break; \
	case Argon2_id: \
		fn = &argon2id_hash_raw; \
	}
