#include "params.h"
#include <math.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <base64.h>
#include <string.h>

void Argon2_MariaDB_Params_default(Argon2_MariaDB_Params *params) {
	params->mode = ARGON2_MARIADB_DEFAULT_PARAMS.mode;
	params->t_cost = ARGON2_MARIADB_DEFAULT_PARAMS.t_cost;
	params->m_cost = ARGON2_MARIADB_DEFAULT_PARAMS.m_cost;
	params->parallelism = ARGON2_MARIADB_DEFAULT_PARAMS.parallelism;
}

int Argon2_MariaDB_Params_gensalt(Argon2_MariaDB_Params *params) {
	return RAND_bytes(params->salt, ARGON2_MARIADB_SALT_LEN);
}

#define STRLEN(s) (sizeof(s) - 1) // Remove null byte
#define UINT_STRLEN(v) (v == 0 ? 1 : (size_t)(log10(v)+1))

static const size_t Argon2_MariaDB_Params_encoded_prefix_len(const Argon2_MariaDB_Params *params) {
	return STRLEN("$") + strlen(argon2_type2string(params->mode, 0))
		+ STRLEN("$v=") + UINT_STRLEN(ARGON2_VERSION_NUMBER);
}
static const size_t Argon2_MariaDB_Params_encoded_params_len(const Argon2_MariaDB_Params *params) {
	return STRLEN("$m=") + UINT_STRLEN(params->m_cost)
		+ STRLEN(",t=") + UINT_STRLEN(params->t_cost)
		+ STRLEN(",p=") + UINT_STRLEN(params->parallelism);
}
static const size_t Argon2_MariaDB_Params_encoded_salt_len(const Argon2_MariaDB_Params *params) {
	return STRLEN("$") + b64_encoded_len(sizeof(params->salt));
}

#undef UINT_STRLEN
#undef STRLEN

const size_t Argon2_MariaDB_Params_encoded_len(const Argon2_MariaDB_Params *params) {
	const size_t prefix_len = Argon2_MariaDB_Params_encoded_prefix_len(params);
	const size_t params_len = Argon2_MariaDB_Params_encoded_params_len(params);
	const size_t salt_len = Argon2_MariaDB_Params_encoded_salt_len(params);
	return prefix_len + params_len + salt_len;
}


int Argon2_MariaDB_Params_encode(const Argon2_MariaDB_Params *params, char *result, const size_t result_len) {
	// Enforce proper size of result allocation
	if (result_len != Argon2_MariaDB_Params_encoded_len(params)) {
		return 1;
	}

	const size_t prefix_len = Argon2_MariaDB_Params_encoded_prefix_len(params);
	const size_t params_len = Argon2_MariaDB_Params_encoded_params_len(params);
	const size_t salt_len = Argon2_MariaDB_Params_encoded_salt_len(params);
	
	// Encode prefix
	size_t offset = 0;
	snprintf(result, prefix_len+1, "$%s$v=%d", argon2_type2string(params->mode, 0), ARGON2_VERSION_NUMBER);
	offset += prefix_len;
	// Encode numerical params
	snprintf(result + offset, params_len+1, "$m=%u,t=%u,p=%u", params->m_cost, params->t_cost, params->parallelism);
	offset += params_len;
	// Encode salt using base64
	const size_t b64_salt_len = salt_len - 1; // disregard the $ prefix for the b64 string itself
	char encoded_salt[b64_salt_len];
	b64_encode(params->salt, sizeof(params->salt), encoded_salt, b64_salt_len);
	snprintf(result + offset, salt_len+1, "$%s", encoded_salt);

	return 0;
}

int Argon2_MariaDB_Params_decode(Argon2_MariaDB_Params *params, const char *result, const size_t result_len);
