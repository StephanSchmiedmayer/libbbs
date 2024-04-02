#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdarg.h>

#define BBS_CIPHER_SUITE_BLS12_381_SHA_256 1
#define BBS_CIPHER_SUITE_BLS12_381_SHAKE_256 2

// Magic constants to be used as Domain Separation Tags
#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
#define BBS_CIPHER_SUITE_ID "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
#define BBS_CIPHER_SUITE_LENGTH 35
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
#define BBS_CIPHER_SUITE_ID "BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_"
#define BBS_CIPHER_SUITE_LENGTH 37
#endif

#define BBS_DEFAULT_KEY_DST BBS_CIPHER_SUITE_ID "KEYGEN_DST_"
#define BBS_API_ID          BBS_CIPHER_SUITE_ID "H2G_HM2S_"
#define BBS_API_ID_LENGTH   BBS_CIPHER_SUITE_LENGTH + 9
#define BBS_SIGNATURE_DST   BBS_API_ID "H2S_"
#define BBS_CHALLENGE_DST   BBS_API_ID "H2S_"
#define BBS_MAP_DST         BBS_API_ID "MAP_MSG_TO_SCALAR_AS_HASH_"
#define BBS_MAP_DST_LENGTH  BBS_API_ID_LENGTH + 26

// The above collision stems from the ID. Possible oversight? Should not compromise
// security too much...

// Point for the SHA suite
#if BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHA_256
static uint8_t P1[] = {
	0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46,
	0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8, 0x72, 0xb9, 0x48, 0xf1,
	0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b,
	0x4e, 0x28, 0xc9
};
#elif BBS_CIPHER_SUITE == BBS_CIPHER_SUITE_BLS12_381_SHAKE_256
static uint8_t P1[] = {
	0x89, 0x29, 0xdf, 0xbc, 0x7e, 0x66, 0x42, 0xc4, 0xed, 0x9c, 0xba, 0x08, 0x56, 0xe4, 0x93,
	0xf8, 0xb9, 0xd7, 0xd5, 0xfc, 0xb0, 0xc3, 0x1e, 0xf8, 0xfd, 0xcd, 0x34, 0xd5, 0x06, 0x48,
	0xa5, 0x6c, 0x79, 0x5e, 0x10, 0x6e, 0x9e, 0xad, 0xa6, 0xe0, 0xbd, 0xa3, 0x86, 0xb4, 0x14,
	0x15, 0x07, 0x55
};
#endif

/// @brief BBS cipher suite interface
/// @note Strategy pattern to dispatch to the correct hash function for the 
/// cipher suite, keeping the same overall control flow for the caller.
typedef struct {
	int (*expand_message_init)(void *ctx);
	int (*expand_message_update)(void *ctx, const uint8_t *msg, uint32_t msg_len);
	int (*expand_message_finalize)(void *ctx, uint8_t out[48], const uint8_t *dst, uint8_t dst_len);
} bbs_cipher_suite_t;

// Octet string lengths
#define BBS_SK_LEN 32
#define BBS_PK_LEN 96
#define BBS_SIG_LEN 80
#define BBS_PROOF_BASE_LEN 272
#define BBS_PROOF_UD_ELEM_LEN 32
#define BBS_PROOF_LEN(num_undisclosed) (BBS_PROOF_BASE_LEN + num_undisclosed * BBS_PROOF_UD_ELEM_LEN)

// Return values
#define BBS_OK 0
#define BBS_ERROR 1

// Typedefs
typedef uint8_t bbs_secret_key[BBS_SK_LEN];
typedef uint8_t bbs_public_key[BBS_PK_LEN];
typedef uint8_t bbs_signature[BBS_SIG_LEN];

// Key Generation
int bbs_keygen_full(
		bbs_secret_key sk,
		bbs_public_key pk
	);

int bbs_keygen(
		bbs_secret_key        sk,
		const uint8_t        *key_material,
		uint16_t              key_material_len,
		const uint8_t        *key_info,
		uint16_t              key_info_len,
		const uint8_t        *key_dst,
		uint8_t               key_dst_len
	);

int bbs_sk_to_pk(
		const bbs_secret_key sk,
		bbs_public_key       pk
	);

// Signing
int bbs_sign(
		const bbs_secret_key  sk,
		const bbs_public_key  pk,
		bbs_signature         signature,
		const uint8_t        *header,
		uint64_t              header_len,
		uint64_t              num_messages,
		...
	);

// Verification
int bbs_verify(
		const bbs_public_key  pk,
		const bbs_signature   signature,
		const uint8_t        *header,
		uint64_t        header_len,
		uint64_t        num_messages,
		...
	);

// Proof Generation
int bbs_proof_gen (
		const bbs_public_key  pk,
		const bbs_signature   signature,
		uint8_t              *proof,
		const uint8_t        *header,
		uint64_t              header_len,
		const uint8_t        *presentation_header,
		uint64_t              presentation_header_len,
		const uint64_t       *disclosed_indexes,
		uint64_t              disclosed_indexes_len,
		uint64_t              num_messages,
		...
	);

// Proof Verification
int bbs_proof_verify (
		const bbs_public_key  pk,
		const uint8_t        *proof,
		uint64_t              proof_len,
		const uint8_t        *header,
		uint64_t              header_len,
		const uint8_t        *presentation_header,
		uint64_t              presentation_header_len,
		const uint64_t       *disclosed_indexes,
		uint64_t              disclosed_indexes_len,
		uint64_t              num_messages,
		...
	);

#endif
