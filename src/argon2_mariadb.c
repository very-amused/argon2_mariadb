#include "argon2_mariadb.h"
#include "argon2.h"
#include "params.h"
#include "decode.h"
#include <base64.h>
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

int ARGON2_PARAMS_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	// Declare max encoded length
	initid->max_length = Argon2MariaDBParams_encoded_len(&ARGON2_MARIADB_MAX_PARAMS);

	Argon2MariaDBParams *params;

	// Validate arg count and types
	switch (args->arg_count) {
	// Default params
	case 0:
		// Use default params
		params = malloc(sizeof(Argon2MariaDBParams));
		initid->ptr = (char *)params;
		Argon2MariaDBParams_default(params);
		break;
	// Custom params
	case 4:
		if (args->arg_type[0] != STRING_RESULT || // Mode
				args->arg_type[1] != INT_RESULT || // t_cost
				args->arg_type[2] != INT_RESULT || // m_cost
				args->arg_type[3] != INT_RESULT) { // parallelism
			strcpy(message, "ARGON2_PARAMS(mode, t_cost, m_cost, parallelism) requires a string and 3 ints");
			return 1;
		}
		params = malloc(sizeof(Argon2MariaDBParams));
		initid->ptr = (char *)params;
		// Set and validate params from args
		const char *mode = args->args[0];
		const size_t mode_len = args->lengths[0];
		const uint32_t t_cost = *((long long *)args->args[1]);
		const uint32_t m_cost = *((long long *)args->args[2]);
		const uint32_t parallelism = *((long long *)args->args[3]);
		if (Argon2MariaDBParams_set(params, mode, mode_len, t_cost, m_cost, parallelism) != 0) {
			strcpy(message, "One or more invalid arguments to ARGON2_PARAMS()");
			free(params);
			return 1;
		}
		break;
	default:
		strcpy(message, "ARGON2_PARAMS() requires 0 or 4 arguments");
		return 1;
	}

	return 0;
}

char *ARGON2_PARAMS(UDF_INIT *initid, UDF_ARGS *args,
		char *result, unsigned long *result_len,
		char *is_null, char *error) {
	Argon2MariaDBParams *params = (Argon2MariaDBParams *)initid->ptr;
	// Generate a random salt
	if (Argon2MariaDBParams_gensalt(params) != 0) {
		*error = 1;
		return NULL;
	}

	// Encode params
	*result_len = Argon2MariaDBParams_encoded_len(params);
	if (Argon2MariaDBParams_encode(params, result, *result_len) != 0) {
		*error = 1;
		return NULL;
	}
	return result;
}

void ARGON2_PARAMS_deinit(UDF_INIT *initid) {
	free(initid->ptr);
}

int ARGON2_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	// Declare max encoded length
	initid->max_length = Argon2MariaDBParams_encoded_len(&ARGON2_MARIADB_MAX_PARAMS)
		+ (sizeof("$") - 1) + b64_nopadding_encoded_len(ARGON2_MARIADB_HASH_LEN);
	// Prepare for param allocation
	Argon2MariaDBParams *params;

	// Validate args
	ARGON2_encoding encoding = ARGON2_encoding_std;
	if (args->arg_count < 2 || args->arg_count > 3) {
		strcpy(message, "ARGON2() requires 2 or 3 arguments");
		return 1;
	}
	switch (args->arg_count) {
	case 2:
		if (args->arg_type[0] != STRING_RESULT ||
				args->arg_type[1] != STRING_RESULT) {
			strcpy(message, "ARGON2(params, passwd) requires 2 strings");
			return 1;
		}
		break;
	
	case 3:
		if (args->arg_type[0] != STRING_RESULT ||
				args->arg_type[1] != STRING_RESULT ||
				args->arg_type[2] != INT_RESULT) {
			strcpy(message, "ARGON2(params, passwd, enc) requires 2 strings and an int");
			return 1;
		}
		encoding = *(long long *)args->args[2];
		bool valid = false;
		for (int i = ARGON2_encoding_std; i <= ARGON2_encoding_hashonly; i++) {
			if (encoding == i) {
				valid = true;
				break;
			}
		}
		if (!valid) {
			sprintf(message, "ARGON2() received invalid encoding %d", encoding);
			return 1;
		}
	}

	// Allocate and decode params
	params = malloc(sizeof(Argon2MariaDBParams));
	initid->ptr = (char *)params;
	if (Argon2MariaDBParams_decode(params, args->args[0], args->lengths[0]) != 0) {
		strcpy(message, "ARGON2() failed to decode params");
		free(params);
		return 1;
	}

	return 0;
}

char *ARGON2(UDF_INIT *initid, UDF_ARGS *args,
		char *result, unsigned long *result_len,
		char *is_null, char *error) {
	Argon2MariaDBParams *params = (Argon2MariaDBParams *)initid->ptr;
	const ARGON2_encoding encoding = args->arg_count > 2 ? *(long long *)args->args[2] : ARGON2_encoding_std;

	// Select argon2 function based on mode
	int argon2_code;
	switch (encoding) {
	case ARGON2_encoding_std:
	{
		// Set encoded hash length
		*result_len = argon2_encodedlen(params->t_cost, params->m_cost, params->parallelism,
				ARGON2_MARIADB_SALT_LEN, ARGON2_MARIADB_HASH_LEN,
				params->mode);
		// Select hash fn
		Argon2MariaDBParams_encoded_hash_fn hash_encoded;
		ARGON2_MARIADB_ENCODED_HASHFN(params->mode, hash_encoded);
		// Run hash fn
		argon2_code = hash_encoded(params->t_cost, params->m_cost, params->parallelism,
				args->args[1], args->lengths[1],
				params->salt, sizeof(params->salt),
				ARGON2_MARIADB_HASH_LEN,
				result, *result_len);
		break;
	}
	
	case ARGON2_encoding_raw:
	{
		// Set raw hash length
		*result_len = ARGON2_MARIADB_HASH_LEN;
		// Select hash fn
		Argon2MariaDBParams_raw_hash_fn hash_raw;
		ARGON2_MARIADB_RAW_HASHFN(params->mode, hash_raw);
		// Run hash fn
		argon2_code = hash_raw(params->t_cost, params->m_cost, params->parallelism,
				args->args[1], args->lengths[1],
				params->salt, sizeof(params->salt),
				result, *result_len);
		break;
	}

	case ARGON2_encoding_hashonly:
		// Set encoded hash length
		*result_len = argon2_encodedlen(params->t_cost, params->m_cost, params->parallelism,
				ARGON2_MARIADB_SALT_LEN, ARGON2_MARIADB_HASH_LEN,
				params->mode);
		// Select hash fn
		Argon2MariaDBParams_encoded_hash_fn hash_encoded;
		ARGON2_MARIADB_ENCODED_HASHFN(params->mode, hash_encoded);
		// Run hash fn
		argon2_code = hash_encoded(params->t_cost, params->m_cost, params->parallelism,
				args->args[1], args->lengths[1],
				params->salt, sizeof(params->salt),
				ARGON2_MARIADB_HASH_LEN,
				result, *result_len);
		if (argon2_code != ARGON2_OK) {
			break;
		}
		// Extract hash from encoded string
		char *encoded_hash;
		size_t encoded_hash_len;
		argon2_mariadb_extract_hash(result, *result_len, &encoded_hash, &encoded_hash_len);
		*result_len = encoded_hash_len;
		result = encoded_hash;
	}
	if (argon2_code != ARGON2_OK) {
		*error = 1;
		return NULL;
	}

	return result;
}

void ARGON2_deinit(UDF_INIT *initid) {
	free(initid->ptr);
}

ARGON2_VERIFY_state *ARGON2_VERIFY_state_malloc() {
	ARGON2_VERIFY_state *state = malloc(sizeof(ARGON2_VERIFY_state));
	state->params = malloc(sizeof(Argon2MariaDBParams));

	return state;
}

void ARGON2_VERIFY_state_free(ARGON2_VERIFY_state *state) {
	free(state->params);
	free(state);
}

int ARGON2_VERIFY_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	ARGON2_VERIFY_state *state;

	// Validate args
	if (args->arg_count != 2) {
		strcpy(message, "ARGON2_VERIFY() requires 2 arguments");
		return 1;
	}
	if (args->arg_type[0] != STRING_RESULT ||
			args->arg_type[1] != STRING_RESULT) {
		strcpy(message, "ARGON2_VERIFY(hash, passwd) requires 2 strings");
		return 1;
	}

	// Allocate state
	state = ARGON2_VERIFY_state_malloc();
	initid->ptr = (char *)state;
	// Decode params
	if (Argon2MariaDBParams_decode(state->params, args->args[0], args->lengths[0]) != 0) {
		strcpy(message, "ARGON2_VERIFY() failed to decode params");
		ARGON2_VERIFY_state_free(state);
		return 1;
	}

	// Decode hash
	if (argon2_mariadb_decode_hash(args->args[0], args->lengths[0], state->hash, sizeof(state->hash)) != 0) {
		strcpy(message, "ARGON2_VERIFY() failed to decode hash");
		ARGON2_VERIFY_state_free(state);
		return 1;
	}

	return 0;
}

long long ARGON2_VERIFY(UDF_INIT *initid, UDF_ARGS *args,
		char *is_null, char *error) {
	ARGON2_VERIFY_state *state = (ARGON2_VERIFY_state *)initid->ptr;
	Argon2MariaDBParams *params = state->params;

	// Select hash function
	int (*hash_raw)(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism,
			const void *pwd, const size_t pwdlen,
			const void *salt, const size_t saltlen,
			void *hash, const size_t hashlen);
	switch (params->mode) {
	case Argon2_d:
		;;
		hash_raw = &argon2d_hash_raw;
		break;
	case Argon2_i:
		;;
		hash_raw = &argon2i_hash_raw;
		break;
	case Argon2_id:
		;;
		hash_raw = &argon2id_hash_raw;
	}

	// Hash provided password using params
	unsigned char input_hash[ARGON2_MARIADB_HASH_LEN];
	int code = hash_raw(params->t_cost, params->m_cost, params->parallelism,
			args->args[1], args->lengths[1],
			params->salt, sizeof(params->salt),
			input_hash, sizeof(input_hash));
	if (code != ARGON2_OK) {
		*error = 1;
		return 0;
	}
	// Compare hash result with correct hash
	if (CRYPTO_memcmp(input_hash, state->hash, sizeof(state->hash)) != 0) {
		return 0; // hashes are not equal -> return false
	}
	return 1; // hashes are equal -> return true
}

void ARGON2_VERIFY_deinit(UDF_INIT *initid) {
	ARGON2_VERIFY_state *state = (ARGON2_VERIFY_state *)initid->ptr;
	ARGON2_VERIFY_state_free(state);
}
