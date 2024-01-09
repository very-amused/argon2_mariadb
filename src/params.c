#include "params.h"
#include <math.h>
#include <openssl/rand.h>
#include <argon2.h>
#include <base64.h>
#include <string.h>
#include <stdio.h>

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
	result[offset] = '$';
	offset++;
	const size_t b64_salt_len = salt_len - 1; // Account for $ prefix
	b64_encode(params->salt, sizeof(params->salt), result + offset, b64_salt_len);

	return 0;
}

// strtok if it was good.
// *offset and *tok_len must both be 0 when first called,
// and will be set to offset and length values (relative to s) of the next split token
static void _strtokn(const char *s, const size_t s_len, const char delim,
		size_t *offset, size_t *tok_len) {
	// Move offset past previous token + delimiter
	*offset += *tok_len + sizeof(delim);
	// Max token length
	const char max_len = s_len - *offset;
	// Token start
	const char *start = s + *offset;
	// Reset current token length
	*tok_len = 0;

	// Search until the next token is found or the string ends
	while (start[*tok_len] != delim && *tok_len < max_len) {
		(*tok_len)++;
	}
}

int Argon2_MariaDB_Params_decode(Argon2_MariaDB_Params *params, const char *encoded, const size_t encoded_len) {
	// Split tokens using the $ char
	size_t offset = 0, token_len = 0;
#define NEXT() _strtokn(encoded, encoded_len, '$', &offset, &token_len)
	NEXT();
	const size_t enc_prefix_offset = offset;
	const size_t enc_prefix_len = token_len;
	NEXT(); // Discard version field
	NEXT();
	const size_t enc_params_offset = offset;
	const size_t enc_params_len = token_len;
	NEXT();
	const size_t enc_salt_offset = offset;
	const size_t enc_salt_len = token_len;
#undef NEXT

	// Decode mode from prefix
	params->mode = -1;
	for (argon2_type t = Argon2_d; t <= Argon2_id; t++) {
		if (strncmp(encoded + enc_prefix_offset, argon2_type2string(t, 0), enc_prefix_len) == 0) {
			params->mode = t;
			break;
		}
	}
	if (params->mode == -1) {
		return 1;
	}

	// Decode numerical params
	// Copy and null-terminate for safe use with sscanf
	char enc_params[enc_params_len + 1];
	strncpy(enc_params, encoded + enc_params_offset, enc_params_len);
	enc_params[enc_params_len] = '\0';
	int status;
	status = sscanf(enc_params, "m=%u,t=%u,p=%u", &params->m_cost, &params->t_cost, &params->parallelism);
	if (status != 3) {
		return 1;
	}

	// Decode salt
	status = b64_decode(encoded + enc_salt_offset, enc_salt_len, params->salt, sizeof(params->salt));
	if (status != 0) {
		return 1;
	}

	return 0;
}
