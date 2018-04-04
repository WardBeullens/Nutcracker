/*
* Copyright (c) 2017 SecureRF Corporation, All rights reserved.
* -------------------------------------------------------------------------
* This computer program is proprietary information of SecureRF Corporation.
* The receipt or possession of this program does not convey any rights to
* reproduce or disclose its contents, or to manufacture, use, or sell
* anything that it may describe, in whole or in part, except for the purposes of
* the post-quantum algorithm public review and evaluation in connection with
* the National Institute of Standards and Technology’s development of standards
* for post-quantum cryptography.  Any reproduction of this program for any other
* purpose without the express written consent of SecureRF is a violation of the
* copyright laws and may subject you to criminal prosecution.
* -------------------------------------------------------------------------
*/


//**************************************************************************
// HEADER
//**************************************************************************

 /**************************************************************************
 * NAME :       ae_crypto.h
 *
 * DESCRIPTION: Algorithms corresponding to those outlined in the
 *              WalnutDSA spec
 *
 */


//**************************************************************************
// INCLUDES
//**************************************************************************

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> 

/* Library of basic functions */
#include "ae_lib.h"

//**************************************************************************
// DEFINITIONS
//**************************************************************************

/* Number of braid strands. Defined as B8. */
#define WALNUT_BRAID                            8

#if (WALNUT_SECURITY_LEVEL == 128)

/* Size of Galois Field. Defined as GF32. */
#       define WALNUT_FIELD                     32

/* Number of bits of an element in GF(32) */
#       define GF_ELEM_BITS                     5

/* Size of hashed message for WalnutDSA using SHA256 */
#       define WALNUT_HASH_SIZE                 32

/* Minimal length of certain random braid words
   Defined in section 11.1 */
#       define WALNUT_VALUE_L                   15

/* Minimal length of the private key
   Defined in section 11.1 */
#       define WALNUT_VALUE_l                   132

#endif

#if (WALNUT_SECURITY_LEVEL == 256)

/* Size of Galois Field. Defined as GF256. */
#       define WALNUT_FIELD                     256

/* Number of bits of an element in GF256 */
#       define GF_ELEM_BITS                     8

/* Size of hashed message for WalnutDSA using SHA512 */
#       define WALNUT_HASH_SIZE                 64

/* Minimal length of certain random braid words
   Defined in section 11.2 */
#       define WALNUT_VALUE_L                   30

/* Minimal length of the private key
   Defined in section 11.2 */
#       define WALNUT_VALUE_l                   287

#endif

/* WALNUT_FIELD being undefined means that WALNUT_SECURITY_LEVEL is invalid */
#if !defined(WALNUT_FIELD)

#       error "INVALID SECURITY LEVEL. VALID OPTIONS: 128, 256"

#endif

/* Current specification calls for using braid strands 1, 3, 5, and 7
 * for encoding purposes. This is defined as WALNUT_VERSION 0x01.
 */
#define WALNUT_VERSION                          0x01

/* Number of bits to define a strand in B(8) */
#define B8_STRAND_BITS                          0x03

/* Number of bits to define a generator in B(8) */
#define B8_GENERATOR_BITS                       (B8_STRAND_BITS + 1)

/* Maximum length of a pure braid */
#define B8_MAX_PURE_BRAID_LENGTH                0x14

/* Maximum length of a cloaking element (2K) */
#define B8_MAX_CLOAKING_ELEMENT_LENGTH          0x800

/* Maximum length of any braid (16K) */
#define B8_MAX_BRAID_LENGTH                     0x4000

/* Number of T-values within the public key */
#define WALNUT_NUM_TVALUES                      WALNUT_BRAID

/* Number of matrix elements within the public key */
#define WALNUT_NUM_MATRIX_ELEMENTS              (WALNUT_BRAID * WALNUT_BRAID)

/* Number of permutation elements within the public key */
#define WALNUT_NUM_PERMUTATION_ELEMENTS         WALNUT_BRAID

/* Number of bits per T-Value */
#define WALNUT_TVALUE_BITS                      GF_ELEM_BITS

/* Number of bits per T-Value */
#define WALNUT_MATRIX_ELEMENT_BITS              GF_ELEM_BITS

/* Number of bits per permutation element */
#define WALNUT_PERMUTATION_ELEMENT_BITS         B8_STRAND_BITS

/* Number of bytes within the public key used to track version/key information */
#define WALNUT_VERSION_LENGTH                   0x03

/* Number of bytes within the public key that contain T-Values */
#define WALNUT_PUBKEY_TVALUES_LENGTH            ((WALNUT_NUM_TVALUES * WALNUT_TVALUE_BITS) / 8)

/* Number of bytes within the public key that contain matrix elements (+7 used so that value is rounded up on division) */
#define WALNUT_PUBKEY_MATRIX_LENGTH             (((WALNUT_NUM_MATRIX_ELEMENTS - WALNUT_BRAID + 1) * WALNUT_MATRIX_ELEMENT_BITS + 7) / 8)

/* Number of bytes within the public key per row of matrix elements */
#define WALNUT_PUBKEY_MATRIX_ROW_LENGTH         WALNUT_MATRIX_ELEMENT_BITS

/* Number of bytes within the public key per column of matrix elements */
#define WALNUT_PUBKEY_MATRIX_COL_LENGTH         WALNUT_PUBKEY_MATRIX_ROW_LENGTH

/* Number of bytes within the public key that contain matrix elements */
#define WALNUT_PUBKEY_PERMUTATION_LENGTH        (WALNUT_NUM_PERMUTATION_ELEMENTS * WALNUT_PERMUTATION_ELEMENT_BITS) / 8

/* Number of bytes that constitute the public key */
#define WALNUT_PUBKEY_LENGTH                    (WALNUT_VERSION_LENGTH + \
                                                  WALNUT_PUBKEY_TVALUES_LENGTH + \
                                                  WALNUT_PUBKEY_MATRIX_LENGTH + \
                                                  WALNUT_PUBKEY_PERMUTATION_LENGTH + \
                                                  WALNUT_PUBKEY_MATRIX_LENGTH)

/* Position of the version within both the public key and the signature */
#define WALNUT_VERSION_POSITION                 0x00

/* Position of the T-values within the public key */
#define WALNUT_PUBKEY_TVALUES_POSITION          (WALNUT_VERSION_POSITION + WALNUT_VERSION_LENGTH)

/* Position of the S matrix elements within the public key */
#define WALNUT_PUBKEY_S_MATRIX_POSITION         (WALNUT_PUBKEY_TVALUES_POSITION + WALNUT_PUBKEY_TVALUES_LENGTH)

/* Position of the S permutation elements within the public key */
#define WALNUT_PUBKEY_S_PERMUTATION_POSITION    (WALNUT_PUBKEY_S_MATRIX_POSITION + WALNUT_PUBKEY_MATRIX_LENGTH)

/* Position of the S' matrix elements within the public key */
#define WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION   (WALNUT_PUBKEY_S_PERMUTATION_POSITION + WALNUT_PUBKEY_PERMUTATION_LENGTH)

//**************************************************************************
// MACROS
//**************************************************************************

/* Given braid and position, get generator at that position.
   Takes into account offset of 2, as the first two braid elements are its length */
#define GET_BRAID_GENERATOR(braid, pos)         ((pos % 2) ? (braid[(pos/2) + 2] & 0x0F) : \
                                                  (braid[(pos/2) + 2] & 0xF0) >> B8_GENERATOR_BITS)

/* Given bands and position, get band a_(t,s) at that position
   Takes into account offset of 2, as the first two braid elements are its length */
//#define GET_BAND_GENERATOR(bands, pos)          (bands[(pos) + 2])
#define GET_BAND_GENERATOR(bands, Ai, pos)      (bands[(Ai)+1][(pos)])

/* Given bands and position, get band a_(t,s) at that position, then extract t
   Takes into account offset of 2, as the first two braid elements are its length */
//#define GET_BAND_GENERATOR_T(bands, pos)        (((GET_BAND_GENERATOR(bands, pos) & 0xF0)) >> B8_GENERATOR_BITS)
#define GET_BAND_GENERATOR_T(bands, Ai, pos)    (((GET_BAND_GENERATOR(bands, Ai, pos) & 0xF0)) >> B8_GENERATOR_BITS)

/* Given bands and position, get band a_(t,s) at that position, then extract s
   Takes into account offset of 2, as the first two braid elements are its length */
//#define GET_BAND_GENERATOR_S(bands, pos)        ((GET_BAND_GENERATOR(bands, pos) & 0x0F))
#define GET_BAND_GENERATOR_S(bands, Ai, pos)    ((GET_BAND_GENERATOR(bands, Ai, pos) & 0x0F))

/* Given generator gen, get its strand (absolute value of generator) */
#define GET_GENERATOR_STRAND(gen)               ((gen) & 0x07)

/* Given generator gen, get its sign */
#define GET_GENERATOR_SIGN(gen)                 ((gen) & 0x08)

/* Given braid, get its number of generators */
#define GET_NUM_BRAID_GENERATORS(braid)         (((braid)[0] << 8) | (braid)[1])

/* Given bands, get its number of band generators */
//#define GET_NUM_BANDS_GENERATORS(bands)         (GET_NUM_BRAID_GENERATORS(bands))
#define GET_NUM_BAND_GENERATORS(bands)          ((bands[0][0] << 8) | bands[0][1])

/* Given braid, get its number of bytes */
#define GET_NUM_BRAID_BYTES(braid)              (((GET_NUM_BRAID_GENERATORS(braid) + 1) / 2) + 2)

/* Given bands, get its number of bytes */
//#define GET_NUM_BANDS_BYTES(bands)              ((GET_NUM_BANDS_GENERATORS(bands)) + 2)

/* Given braid, generator, and position, set generator at position pos in braid to gen (braid[pos] = generator) */
#define SET_BRAID_GENERATOR(braid, gen, pos)    (braid[((pos) / 2) + 2] = (((pos) % 2) ? \
    ((GET_BRAID_GENERATOR(braid, (pos-1)) << B8_GENERATOR_BITS) | (gen)) : (((gen) << B8_GENERATOR_BITS) | GET_BRAID_GENERATOR(braid, ((pos)+1)))))

/* Given bands, generator, and position, set generator at position pos in bands */
#define SET_BAND_GENERATOR(bands, gen, Ai, pos) (bands[(Ai)+1][(pos)] = (gen))

/* Given t, s, and sign, make a band generator of form a_(t,s)^sign (where sign = 0, 1) */
#define MAKE_BAND_GENERATOR(t, s, sign)         (((((t) & 0x07) | ((!!sign) << B8_STRAND_BITS)) << B8_GENERATOR_BITS) \
                                                  | (((s) & 0x07) | ((!!sign) << B8_STRAND_BITS)))

/* Given a GF(2^n) lookup table, and two operands a and b, find a * b in GF(2^n) */
#define GMUL_BASE(table, a, b)                  (((a > WALNUT_FIELD-1) || (b > WALNUT_FIELD-1)) ? 0 : table[a][b])

/* Given a GF(2^n) lookup table, and one operand a, find a^-1 in GF(2^n) */
#define MINV_BASE(table, a)                     ((a > WALNUT_FIELD-1) ? 0 : table[a])

/* If WALNUT_SECURITY_LEVEL is 128, then use lookup tables in GF(32) */
#if WALNUT_SECURITY_LEVEL == 128

#       define GMUL(a, b)       (GMUL_BASE(gmul_32, (a), (b)))
#       define MINV(a)          (MINV_BASE(minv_32, (a)))

#endif

/* If WALNUT_SECURITY_LEVEL is 256, then use lookup tables in GF(256) */
#if WALNUT_SECURITY_LEVEL == 256

#       define GMUL(a, b)       (GMUL_BASE(gmul_256, (a), (b)))
#       define MINV(a)          (MINV_BASE(minv_256, (a)))

#endif

//**************************************************************************
// FUNCTIONS
//**************************************************************************

int generate_tvalues(void *tvalues);
int walnut_mmul(uint8_t d[WALNUT_BRAID][WALNUT_BRAID],
                uint8_t a[WALNUT_BRAID][WALNUT_BRAID],
                uint8_t b[WALNUT_BRAID][WALNUT_BRAID]);
int concat_braid(uint8_t *b1, uint8_t *b2, uint8_t *b1b2);
int braid_free_reduction(void *b);
int generate_braid(void *b, size_t length);
int get_braid_permutation(uint8_t *b, uint8_t *p);
int invert_braid(uint8_t *b, uint8_t *inv);
int dehornoy_reduction(uint8_t *b);
int walnut_emul(uint8_t m[WALNUT_BRAID][WALNUT_BRAID], uint8_t *p, uint8_t *braid, const uint8_t *T);
int walnut_message_encoder(const uint8_t *hashed_msg, void *encoded_msg);
int bkl_normal_form(uint8_t *b);

/**************************************************************************
* NAME :       int key_generation(*privkey, *pubkey)
*
* DESCRIPTION: Generate both the public and the private key
*
* ARGUMENTS:
*
*      INPUTS:
*              void            *privkey        buffer to store
*                                              private key
*              void            *pubkey         buffer to store
*                                              public key
*
*      OUTPUTS:
*              void            *privkey        buffer containing
*                                              private key
*              void            *pubkey         buffer containing
*                                              public key
*              int             return          on success, return 1
*
*/
int key_generation(void *privkey, void *pubkey);

/**************************************************************************
* NAME :       int signature_generation(signature, sig_length, message, length, privkey)
*
* DESCRIPTION: Generate the signature
*
* ARGUMENTS:
*
*      INPUTS:
*              void            *signature      buffer for signature and message
*              void            *sig_length     pointer to signature length
*              void            *message        message
*              size_t          length          length of message
*              void            *privkey        private key
*
*      OUTPUTS:
*              void            *signature      buffer containing signature and message
*              void            *sig_length     pointer to signature length
*              int             return          on success, return 1
*
*/
int signature_generation(void *signature, void *sig_length, const void *message, size_t length, const void *privkey);

/**************************************************************************
* NAME :       int signature_verification(pubkey, signature, sig_length)
*
* DESCRIPTION: Verify the signature
*
* ARGUMENTS:
*
*      INPUTS:
*              void            *pubkey         public key
*              void            *signature      buffer containing signature and message
*              void            *sig_length     pointer to length of signature buffer
*
*      OUTPUTS:
*              int             return          on success, return 1
*
*/
int signature_verification(void *pubkey, const void *signature, void *sig_length, unsigned char **returnmes, unsigned long long *meslen);

#ifdef KAT_INTERMEDIATES
void unpack_and_print_braid(uint8_t *braid, unsigned char *name);
void printBuffer(uint8_t *braid, size_t size,  char *name);
void unpack_and_print_matrix(uint8_t *matrix,  char *name);
#endif