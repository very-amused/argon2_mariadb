#include "params.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// This file is not a thorough or well-structured test suite,
// this is just scratch work I used as I was developing this library.
//
// Don't PR any changes to this file. There's a 99% chance I'll shoot down any PRs for a proper
// testing suite in this library (1% would be if someone is truly able and willing to take FULL ownership
// and responsibility for the test code, including helping others with test-related issues).
//
// - KS

int main() {
	Argon2MariaDBParams params;
	int status = 0;
	Argon2MariaDBParams_default(&params);
	if (Argon2MariaDBParams_gensalt(&params) != 0) {
		return 1;
	}
	const size_t result_len = Argon2MariaDBParams_encoded_len(&params);
	char result[result_len + 1];
	result[result_len] = '\0';

	status = Argon2MariaDBParams_encode(&params, result, result_len);
	printf("encoded: %s\n", result);
	
	Argon2MariaDBParams decoded;
	status = Argon2MariaDBParams_decode(&decoded, result, result_len);
	if (status != 0) {
		return status;
	}
	status = Argon2MariaDBParams_encode(&decoded, result, result_len);
	if (status != 0) {
		return status;
	}
	printf("decoded: %s\n", result);

	// Test param validation
#define EX(p, inc, f) ((p)->f += inc, Argon2MariaDBParams_validate(p) != 0 && (((p)->f -= inc) || true) || (((p)->f -= inc) && false))
#define TEST(p, inc) Argon2MariaDBParams_validate(p) == 0 \
	&& EX(p, inc, mode) \
	&& EX(p, inc, t_cost) \
	&& EX(p, inc, m_cost) \
	&& EX(p, inc, parallelism)

	Argon2MariaDBParams min_params = ARGON2_MARIADB_MIN_PARAMS;
	Argon2MariaDBParams max_params = ARGON2_MARIADB_MAX_PARAMS;
	if (!(TEST(&min_params, -1) && TEST(&max_params, 1))) {
		printf("Failed validation\n");
		return 1;
	}
#undef TEST
#undef EX

	return status;
}
