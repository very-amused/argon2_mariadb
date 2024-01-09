#include "params.h"
#include <math.h>
#include <openssl/rand.h>
#include <argon2.h>

void Argon2_MariaDB_Params_default(Argon2_MariaDB_Params *params) {
	params->mode = ARGON2_MARIADB_DEFAULT_PARAMS.mode;
	params->t_cost = ARGON2_MARIADB_DEFAULT_PARAMS.t_cost;
	params->m_cost = ARGON2_MARIADB_DEFAULT_PARAMS.m_cost;
	params->parallelism = ARGON2_MARIADB_DEFAULT_PARAMS.parallelism;
}

int Argon2_MariaDB_Params_gensalt(Argon2_MariaDB_Params *params) {
	return RAND_bytes(params->salt, ARGON2_MARIADB_SALT_LEN);
}

const size_t Argon2_MariaDB_Params_encoded_len(const Argon2_MariaDB_Params *params) {
#define STRLEN(s) (sizeof(s) - 1) // Remove null byte
#define UINT_STRLEN(v) (v == 0 ? 1 : (size_t)(log10(v)+1))

	const size_t prefix_len = STRLEN("$argon2") + (params->mode == Argon2_id ? 2 : 1) // i|d|id
		+ STRLEN("$v=XX");
	const size_t params_len = STRLEN("$m=") + UINT_STRLEN(params->m_cost)
		+ STRLEN(",t=") + UINT_STRLEN(params->t_cost)
		+ STRLEN(",p=") + UINT_STRLEN(params->parallelism);

#undef UINT_STRLEN
#undef STRLEN

	return prefix_len;
}

int Argon2_MariaDB_Params_encode(Argon2_MariaDB_Params *params, char *result, const size_t result_len);

int Argon2_MariaDB_Params_decode(Argon2_MariaDB_Params *params, const char *result, const size_t result_len);
