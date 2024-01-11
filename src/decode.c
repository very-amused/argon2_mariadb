#include "decode.h"
#include "params.h"
#include <base64.h>

// Get the last token of a string split using delim,
// not exceeding s_len.
static void _strlasttokn(const char *s, const size_t s_len, const char delim,
		size_t *offset) {
	const char *s_end = s + s_len;
	*offset = 1;

	while (*(s_end - (*offset + 1)) != delim && *offset <= s_len) {
		(*offset)++;
	}
}

void argon2_mariadb_extract_hash(const char *encoded, size_t encoded_len, char **hash, size_t *hash_len) {
	if (encoded[encoded_len-1] == '\0') {
		encoded_len--;
	}
	_strlasttokn(encoded, encoded_len, '$', hash_len);
	*hash = ((char *)encoded + encoded_len - *hash_len);

}

int argon2_mariadb_decode_hash(const char *encoded, size_t encoded_len, unsigned char *hash, const size_t hash_len) {
	if (hash_len != ARGON2_MARIADB_HASH_LEN) {
		return 1;
	}
	if (encoded[encoded_len-1] == '\0') {
		encoded_len--;
	}
	size_t hash_offset;
	_strlasttokn(encoded, encoded_len, '$', &hash_offset);

	return b64_decode(encoded + encoded_len - hash_offset, hash_offset, hash, hash_len);
}
