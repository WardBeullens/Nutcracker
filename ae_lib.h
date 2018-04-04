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
 * NAME :       ae_lib.h
 *
 * DESCRIPTION: A collection of definitions, constants, and functions
 *              used to facilitate the operation of WalnutDSA.
 *
 */


//**************************************************************************
// INCLUDES
//**************************************************************************

#include <stdint.h>
#include "api.h"
#include <stdio.h>
#include "openssl/sha.h"

//**************************************************************************
// DEFINITIONS
//**************************************************************************

//**************************************************************************
// CONSTANTS
//**************************************************************************

 /**************************************************************************
 * NAME :       const uint8_t gmul_32[32][32]
 *
 * DESCRIPTION: Reference table for Galois field multiplication in GF(32)
 *              a * b = gmul_32[a][b]
 */
const uint8_t gmul_32[32][32];

 /**************************************************************************
 * NAME :       const uint8_t minv_32[32]
 *
 * DESCRIPTION: T-value inverses. Used when working with a negative
 *              Artin generator in GF(32).
 */
const uint8_t minv_32[32];

/**************************************************************************
* NAME :       const uint8_t gmul_256[256][256]
*
* DESCRIPTION: Reference table for Galois field multiplication in GF(256)
*              a * b = gmul_256[a][b]
*/
const uint8_t gmul_256[256][256];

/**************************************************************************
* NAME :       const uint8_t minv_256[256]
*
* DESCRIPTION: T-value inverses. Used when working with a negative
*              Artin generator in GF(256)
*/
const uint8_t minv_256[256];


//**************************************************************************
// FUNCTIONS
//**************************************************************************

/**************************************************************************
* NAME :       uint8_t get_least_common_multiple(elem, length)
*
* DESCRIPTION: Get the least common multiple of all elements in elem.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t  *elem          array of elements
*              size_t   length         number of elements in elem
*
*      OUTPUTS:
*              uint8_t return          least common multiple
*
*/
uint8_t get_least_common_multiple(uint8_t *elem, size_t length);

/**************************************************************************
* NAME :       uint8_t get_strong_random_number(max)
*
* DESCRIPTION: Returns a random number via randombytes() mod max.
*              Random number range is therefore 0 to max-1 (inclusive)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t max             maximum possible random number
*
*      OUTPUTS:
*              uint8_t return          random number
*
*/
uint8_t get_strong_random_number(uint8_t max);

/**************************************************************************
* NAME :       uint8_t get_permutation_order(p, num)
*
* DESCRIPTION: Given permutation p with num elements, return its order.
*              Order is defined as the least common multiple of the
*              disjoint cycle lengths.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p              permutation
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t return          permutation order
*
*/
uint8_t get_permutation_order(uint8_t *p, size_t num);

/**************************************************************************
* NAME :       uint8_t generate_random_permutation(p, num)
*
* DESCRIPTION: Generates the identity permutation of length num,
*              then shuffles into a random order as defined by the
*              Fisher-Yates Shuffle.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p              buffer to store permutation
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t *p              buffer with random permutation
*              uint8_t return          on success, return 1
*
*/
uint8_t generate_random_permutation(uint8_t *p, size_t num);

/**************************************************************************
* NAME :       generate_random_permutation_of_given_order(p, num, order)
*
* DESCRIPTION: Generates permutation using generate_random_permutation(),
*              and returns a permutation once its order is equivalent to
*              the order parameter.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p              buffer to store permutation
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t *p              buffer with random permutation
*              uint8_t return          on success, return 1
*
*/
uint8_t generate_random_permutation_of_given_order(uint8_t *p, size_t num, uint8_t order);

/**************************************************************************
* NAME :       uint8_t invert_permutation(p, num)
*
* DESCRIPTION: Overwrite permutation p with its inverse
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p              original permutation
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t *p              inverted permutation
*              uint8_t return          on success, return 1
*
*/
uint8_t invert_permutation(uint8_t *p, size_t num);

/**************************************************************************
* NAME :       uint8_t multiply_permutations(p3, p1, p2, num)
*
* DESCRIPTION: Multiply permutation 1 with permutation 2, and store the
*              result as permutation 3.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p1             multiplier
*              uint8_t *p2             multiplicand
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t *p3             inverted permutation
*              uint8_t return          on success, return 1
*
*/
uint8_t multiply_permutations(uint8_t *p3, uint8_t *p1, uint8_t *p2, size_t num);

/**************************************************************************
* NAME :       uint8_t compare_identitiy_permutation(p1, num)
*
* DESCRIPTION: Compare permutation p1 with the identity permutation of length num.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *p1             permutation
*              uint8_t num             number of permutation elements
*
*      OUTPUTS:
*              uint8_t return          if equal, return 1; else, return 0
*
*/
uint8_t compare_identitiy_permutation(uint8_t *p1, size_t num);

/**************************************************************************
* NAME :       uint8_t get_product_of_disjoint_cycles(pdc, permutation, length)
*
* DESCRIPTION: Get product of disjoint cycles from permutation of length elements.
*              Store result in pdc.
*
*              Assume permutation σ is (2, 4, 1, 5, 0, 7, 6, 3). To compute the
*              product of disjoint cycles of σ, the identity permutation is
*              adjusted as follows (the words "returns to #" can be substituted by
*              the phrase "goes to the starting element"):
*
*              START:           (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
*              0 goes to 2:     (0x00, 0x02, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07)
*              2 goes to 1:     (0x00, 0x02, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07)
*              1 goes to 4:     (0x00, 0x02, 0x01, 0x04, 0x03, 0x05, 0x06, 0x07)
*              4 returns to 0:  (0x00, 0x02, 0x01, 0x84, 0x03, 0x05, 0x06, 0x07)
*              3 goes to 5:     (0x00, 0x02, 0x01, 0x84, 0x03, 0x05, 0x06, 0x07)
*              5 goes to 7:     (0x00, 0x02, 0x01, 0x84, 0x03, 0x05, 0x07, 0x06)
*              7 returns to 3:  (0x00, 0x02, 0x01, 0x84, 0x03, 0x05, 0x87, 0x06)
*              6 returns to 6:  (0x00, 0x02, 0x01, 0x84, 0x03, 0x05, 0x87, 0x86)
*              END:             (0x02, 0x01, 0x04, 0x80, 0x05, 0x07, 0x83, 0x86)
*
*              Setting the upper nibble to "8" (akin to setting the MSB to 1)
*              denotes the end of a cycle.
*
*              END is read as:  (2, 1, 4, 0)(5, 7, 3)(6)
*
*              Note that the difference between the last two lines is that,
*              for each cycle, the first element is shifted to the last position.
*              This is done so that the cycle format matches that of the
*              WalnutDSA specification.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *pdc            buffer for product of disjoint cycles
*              uint8_t *permutation    permutation of length elements
*              uint8_t length          number of permutation elements
*
*      OUTPUTS:
*              uint8_t *pdc            buffer containing product of disjoint cycles
*              uint8_t return          on success, return 1
*
*/
uint8_t get_product_of_disjoint_cycles(uint8_t *pdc, uint8_t *permutation, uint8_t length);

/**************************************************************************
* NAME :       uint8_t trim_product_of_disjoint_cycles(pdc, init_length, final_length)
*
* DESCRIPTION: Function get_product_of_disjoint_cycles() allows for the output
*              of cycles of length 1. Those cycles are superfluous; therefore,
*              this function will remove them and store the new total number of
*              cycle elements at the length pointer.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *pdc            untrimmed product of disjoint cycles
*              uint8_t init_length     original number of cycle elements
*              uint8_t *final_length   buffer for final number of cycle elements
*
*      OUTPUTS:
*              uint8_t *pdc            trimmed product of disjoint cycles
*              uint8_t *final_length   buffer with final number of cycle elements
*              uint8_t return          on success, return 1
*
*/
uint8_t trim_product_of_disjoint_cycles(uint8_t *pdc, uint8_t init_length, uint8_t *final_length);

/**************************************************************************
* NAME :       uint8_t sort_product_of_disjoint_cycles(pdc, length)
*
* DESCRIPTION: Sort product of disjoint cycles such that the first element
*              of the cycle is the greatest element within the cycle.
*
*              Example 1: (0, 2, 5)             becomes (5, 0, 2)
*              Example 2: (1, 3, 4)(2, 5)       becomes (4, 1, 3)(5, 2)
*              Example 3: (0, 5, 3, 2)(1, 4, 6) becomes (5, 3, 2, 0)(6, 1, 4)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *pdc            unsorted product of disjoint cycles
*              uint8_t *length         number of cycle elements
*
*      OUTPUTS:
*              uint8_t *pdc            sorted product of disjoint cycles
*              uint8_t return          on success, return 1
*
*/
uint8_t sort_product_of_disjoint_cycles(uint8_t *pdc, uint8_t *length);

/**************************************************************************
* NAME :       uint8_t reverse_product_of_disjoint_cycles(pdc, length)
*
* DESCRIPTION: Given cycles c1, c2, ..., cn, rewrite in the order
*              cn, cn-1, ..., c1.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t *pdc            product of disjoint cycles
*              uint8_t *length         number of cycle elements
*
*      OUTPUTS:
*              uint8_t *pdc            reversed product of disjoint cycles
*              uint8_t return          on success, return 1
*
*/
uint8_t reverse_product_of_disjoint_cycles(uint8_t *pdc, uint8_t *length);

/**************************************************************************
* NAME :       uint8_t generate_integer_partition(partition, total, length)
*
* DESCRIPTION: Generate an integer partition: a list of elements whose sum
*              is equal to total.
*
*              Each element is in range min to max (inclusive).
*              (Section 5.3.2: Integer Partitions)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint16_t *partition     buffer for integer partition
*              uint16_t *num_partition buffer for number of partitions
*              uint16_t total          sum of elements in integer partition
*              uint8_t  min            minimum element value
*              uint8_t  max            maximum element value
*
*      OUTPUTS:
*              uint16_t *partition     buffer containing integer partition
*              uint16_t *num_partition buffer containing number of partitions
*              uint8_t  return         on success, return 1
*
*/
uint8_t generate_integer_partition(uint8_t *partition, uint16_t *num_partition,
                                    uint16_t total, uint8_t min, uint8_t max);

 /**************************************************************************
 * NAME :       uint8_t extract_elem(in, curr_bit, packwidth)
 *
 * DESCRIPTION: Given a buffer in and the current bit index curr_bit,
 *              return a byte containing the packed value.
 *
 *              This function takes in the number of bits that represent a
 *              packed value.  That is, log_2(MAX_ELEM).
 *
 *              This function works for any packed value that fits into a
 *              byte.  That is, packwidth can be between 1 and 8.
 *
 * ARGUMENTS:
 *
 *      INPUTS:
 *              uint8_t *in             input buffer that contains the
 *                                      packwidth-bit element
 *              uint8_t curr_bit        bit position within the input buffer
 *              uint8_t packwidth       number of bits to be extracted
 *
 *      OUTPUTS:
 *              uint8_t return          extracted element
 *
 */
uint8_t extract_elem(const uint8_t *in, size_t curr_bit, uint8_t packwidth);

/**************************************************************************
* NAME :       uint8_t pack_elem(buf, packwidth, num_elem)
*
* DESCRIPTION: Given a buffer buf, element bit size packwidth, and number
*              of elements num_elem, modify buf to be a buffer of
*              packed elements.
*
*              For example, consider an unpacked element buffer of:
*              0x03, 0x05, 0x0a, 0x02
*              A function call with packwidth=4 and num_elem=4
*              will result in a packed element buffer of:
*              0x35, 0xa2, 0x00, 0x00
*
* ARGUMENTS:
*
*      INPUTS:
*              void    *buf            buffer of unpacked elements
*              uint8_t packwidth       number of bits per element
*              size_t  num_elem        number of elements
*
*      OUTPUTS:
*              void    *buf            buffer of packed elements
*              uint8_t return          on success, return 1
*
*/
uint8_t pack_elem(void *buf, uint8_t packwidth, size_t num_elem);


#ifdef WORKING_COPY
/**************************************************************************
* NAME :       uint8_t sha2_256(data, length, hash)
*
* DESCRIPTION: Hash data of length length and store it to hash.
*
* ARGUMENTS:
*
*      INPUTS:
*              void    *data           unhashed data
*              size_t  length          length of unhashed data
*              uint8_t *hash           buffer to store hashed data
*
*      OUTPUTS:
*              uint8_t *hash           buffer of hashed data
*
*/
uint8_t sha2_256(void *data, size_t length, uint8_t *hash);

/**************************************************************************
* NAME :       uint8_t sha2_512(data, length, hash)
*
* DESCRIPTION: Hash data of length length and store it to hash.
*
* ARGUMENTS:
*
*      INPUTS:
*              void    *data           unhashed data
*              size_t  length          length of unhashed data
*              uint8_t *hash           buffer to store hashed data
*
*      OUTPUTS:
*              uint8_t *hash           buffer of hashed data
*
*/
uint8_t sha2_512(void *data, size_t length, uint8_t *hash);
#endif
