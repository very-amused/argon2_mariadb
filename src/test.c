#include "params.h"
#include <stdio.h>

int main() {
	Argon2_MariaDB_Params params;
	int status = 0;
	Argon2_MariaDB_Params_default(&params);
	if (Argon2_MariaDB_Params_gensalt(&params) != 1) {
		printf("Failed to gen salt\n");
		return 1;
	}
	const size_t result_len = Argon2_MariaDB_Params_encoded_len(&params);
	char result[result_len + 1];
	result[result_len] = '\0';
	status = Argon2_MariaDB_Params_encode(&params, result, result_len);
	printf("%s\n", result);
	
	Argon2_MariaDB_Params decoded;
	status = Argon2_MariaDB_Params_decode(&decoded, result, result_len);
	status = Argon2_MariaDB_Params_encode(&decoded, result, result_len);
	printf("%s\n", result);

	return status;
}
