#pragma once
#include <stddef.h>

// Extract the encoded hash part of an encoded hash string
// *encoded_hash is a pointer to the hash's start inside of *encoded,
// no allocations are performed.
void argon2_mariadb_extract_hash(const char *encoded, size_t encoded_len,
		char **encoded_hash, size_t *encoded_hash_len);
// Extract and decode a raw hash from an encoded hash string
int argon2_mariadb_decode_hash(const char *encoded, size_t encoded_len,
		unsigned char *hash, const size_t hash_len);
