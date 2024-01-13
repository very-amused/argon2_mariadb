#pragma once
#include <mysql.h>
#include "params.h"

// Defined in params.h
extern const Argon2MariaDBParams ARGON2_MARIADB_DEFAULT_PARAMS;

int ARGON2_PARAMS_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *ARGON2_PARAMS(UDF_INIT *initid, UDF_ARGS *args,
		char *result, unsigned long *result_len,
		char *is_null, char *error);
void ARGON2_PARAMS_deinit(UDF_INIT *initid);

int ARGON2_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *ARGON2(UDF_INIT *initid, UDF_ARGS *args,
		char *result, unsigned long *result_len,
		char *is_null, char *error);
void ARGON2_deinit(UDF_INIT *initid);

// An encoding option for hash output which can be supplied as an optional
// third parameter to ARGON2()
typedef enum {
	ARGON2_encoding_std = 0,
	ARGON2_encoding_raw = 1,
	ARGON2_encoding_hashonly = 2
} ARGON2_encoding;

int ARGON2_VERIFY_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
long long ARGON2_VERIFY(UDF_INIT *initid, UDF_ARGS *args,
		char *is_null, char *error);
void ARGON2_VERIFY_deinit(UDF_INIT *initid);

typedef struct {
	Argon2MariaDBParams *params;
	unsigned char hash[ARGON2_MARIADB_HASH_LEN]; // Decoded hash
} ARGON2_VERIFY_state;

ARGON2_VERIFY_state *ARGON2_VERIFY_state_malloc();
void ARGON2_VERIFY_state_free(ARGON2_VERIFY_state *state);
