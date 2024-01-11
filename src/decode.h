#pragma once
#include <stddef.h>

// Extract and decode a raw hash from an encoded hash string
int argon2_mariadb_decode_hash(const char *encoded, const size_t encoded_len,
		unsigned char *hash, const size_t hash_len);
