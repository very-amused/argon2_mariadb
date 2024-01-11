#pragma once
#include <mysql.h>
#include "params.h"

int ARGON2_PARAMS_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
char *ARGON2_PARAMS(UDF_INIT *initid, UDF_ARGS *args,
		char *result, unsigned long *result_len,
		char *is_null, char *error);
