#include "argon2_mariadb.h"
#include "mariadb_com.h"
#include "params.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define ERR(msg, result, result_len, error) \
	strcpy(result, msg); \
	*result_len = sizeof(msg); \
	*error = 0

int ARGON2_PARAMS_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	// Declare max encoded length
	initid->max_length = Argon2_MariaDB_Params_encoded_len(&ARGON2_MARIADB_MAX_PARAMS);

	// Validate arg count and types
	switch (args->arg_count) {
	// Default params
	case 0:
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
	Argon2_MariaDB_Params params;

	switch (args->arg_count) {
	case 0:
		;;
		// Use default params
		Argon2_MariaDB_Params_default(&params);
		break;
	
	case 4:
		;;
		// Set and validate params from args
		const char *mode = args->args[0];
		const size_t mode_len = args->lengths[0];
		const uint32_t t_cost = *((long long *)args->args[1]);
		const uint32_t m_cost = *((long long *)args->args[2]);
		const uint32_t parallelism = *((long long *)args->args[3]);
		if (Argon2_MariaDB_Params_set(&params, mode, mode_len, t_cost, m_cost, parallelism) != 0) {
			ERR("One or more invalid arguments to ARGON2_PARAMS()", result, result_len, error);
			return result;
		}
		break;
	}

	// Generate a random salt
	Argon2_MariaDB_Params_gensalt(&params);

	// Encode params
	*result_len = Argon2_MariaDB_Params_encoded_len(&params);
	if (Argon2_MariaDB_Params_encode(&params, result, *result_len) != 0) {
		ERR("ARGON2_PARAMS() failed to encode params", result, result_len, error);
	}
	return result;
}
