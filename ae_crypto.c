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


#include "ae_crypto.h"

#include <stdio.h>

//*****************************************************************************************************
// CONSTANTS
//*****************************************************************************************************

//*****************************************************************************************************
// LOCAL FUNCTIONS
//*****************************************************************************************************

/*****************************************************************************************************
* NAME :       static int generate_tvalues(tvalues)
*
* DESCRIPTION: E-Multiplication requires an ordered list of entries in the finite field.
*              These entries are called T-Values, and they are generated in this function.
*
*              Number of T-Values generated is given by WALNUT_NUM_TVALUES.
*
* ARGUMENTS:
*
*      INPUTS:
*              void     *tvalues        buffer for T-Values
*
*      OUTPUTS:
*              void     *tvalues        buffer containing T-Values
*              int      return          on success, return 1
*
*/
int generate_tvalues(void *tvalues)
{
    /* Loop counter */
    uint8_t i;

    /* Pointer to T-values */
    uint8_t * tvalues_ptr = tvalues;

    /* Ti != 0,1 */
    uint8_t min_tvalue = 2;

    /* Generate T-values within finite field q (written as WALNUT_FIELD) */
    for(i=0; i<WALNUT_NUM_TVALUES; i++) {
        tvalues_ptr[i] =
            rand()%(WALNUT_FIELD - min_tvalue) + min_tvalue;
    }

    /* T1 = T2 = 1 */
    tvalues_ptr[0] = 1;
    tvalues_ptr[1] = 1;

    return 1;
}

/*****************************************************************************************************
* NAME :       static int generate_braid(b, length)
*
* DESCRIPTION: Generate a random braid with a number of generators given by length. (Section 8)
*
* ARGUMENTS:
*
*      INPUTS:
*              void     *b              buffer for braid
*              size_t   length          number of braid generators
*
*      OUTPUTS:
*              void     *b              buffer containing braid
*              int      return          on success, return 1
*
*/
int generate_braid(void *b, size_t length)
{
    /* 9: To generate a random braid word of length l */

    /* Loop counter */
    size_t i;

    /* Braid pointer */
    uint8_t * braid = b;

    /* Store length to braid */
    braid[0] = (length & 0xFF00) >> 8;
    braid[1] = (length & 0x00FF);

    /* Generator */
    uint8_t generator;

    for(i=0; i<length; i++) {

        /* 9.1: Choose a random braid generator bi, where 1 <= i < N
                For zero-indexed, this is 0 <= i < N-1 */
        generator = get_strong_random_number(WALNUT_BRAID - 1);

        /* 9.2: Choose a random power, ǫ = {−1, 1} */
        /* Note that the xor 1 operation is not necessary; it just flips the randomly generated power.
           This is done to match the method in which the optimized implementation generates random powers. */
        generator |= ((get_strong_random_number(2) ^ 1) << B8_STRAND_BITS);

        /* 9.3: Append (b_ǫ)^i to the braid word */
        SET_BRAID_GENERATOR(braid, generator, i);

        /* 9.4: Iterate l times */
    }

    /* 9.5: Freely reduce the result. This is via braid_free_reduction() */

    return 1;
}

/*****************************************************************************************************
* NAME :       static int generate_braid_with_permutation(b, p)
*
* DESCRIPTION: Generate a random braid with the given permutation. (Section 9)
*
*              Note that the number of generators in the resulting braid is often small (< 30).
*              To satisfy security constraints, it may be necessary to augment this braid
*              with pure braid generators.
*
* ARGUMENTS:
*
*      INPUTS:
*              void     *b              buffer for braid
*              void     *p              permutation
*
*      OUTPUTS:
*              void     *b              buffer containing braid of permutation p
*              int      return          on success, return 1
*
*/
static int generate_braid_with_permutation(void *b, void *p)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint8_t i, j;

    /* Loop counter (possible negative number, so use int8_t) */
    int8_t k;

    /* Pointer to the braid permutation */
    uint8_t * bp = p;

    /* Product of disjoint cycles */
    uint8_t pdc[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* 9.1(a): First write σ as a product of disjoint cycles C1 · · · Cs */
    success &= get_product_of_disjoint_cycles(pdc, bp, WALNUT_NUM_PERMUTATION_ELEMENTS);

    /* 9.1(c): Convert each cycle to a product of transpositions
       9.1(d): Replace each Ci with its corresponding product of transpositions and flatten the list */

    /* Each transposition is a pair of two elements */
    typedef struct {
      uint8_t a;
      uint8_t b;
    } transposition;

    /* Initial product of transpositions */
    transposition pot_init[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Initial number of transpositions */
    uint8_t num_transpositions = WALNUT_NUM_PERMUTATION_ELEMENTS;

    for(i=0, j=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {

        /* If MSB of pdc is zero, then this element is part of a transposition */
        if((pdc[i] & 0x80) == 0) {

            /* Transposition is the pair of the current element and the next element
               Note that the next element may have its MSB set, so it must be cleared */
            pot_init[i] = (transposition) {pdc[j], (pdc[i+1] & ~0x80)};

        /* Else, the element does not have a transposition */
        } else {

            /* Fill space with invalid element */
            pot_init[i] = (transposition) {0xFF, 0xFF};

            /* Decrement number of transpositions */
            num_transpositions--;

            j = (i < WALNUT_NUM_PERMUTATION_ELEMENTS - 1) ? i+1 : 0;
        }
    }

    /* Final product of transpositions */
    transposition pot[num_transpositions];

    /* Offset to keep track of any invalid, and therefore skipped, pairs */
    j = 0;

    /* Flatten the list */
    for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {

        /* If both a and b are not 0xFF, then this is a valid pair */
        if(pot_init[i].a != 0xFF && pot_init[i].b != 0xFF) {

            /* Copy pair */
            pot[i - j] = pot_init[i];

        /* Else, increment the offset */
        } else {
            j++;
        }
    }

    /* 9.2: For each transposition t, generate a random braid b(t) that produces it */

    /* 9.2(a): Find the smallest element m and largest element M exchanged by the transposition t */

    /* Smallest elements m */
    uint8_t m[num_transpositions];
    /* Largest elements M */
    uint8_t M[num_transpositions];

    for(i=0; i<num_transpositions; i++) {

        /* Place smallest element in m; place largest element in M */
        if(pot[i].a < pot[i].b) {
            m[i] = pot[i].a;
            M[i] = pot[i].b;
        } else {
            m[i] = pot[i].b;
            M[i] = pot[i].a;
        }
    }

    /* 9.2(b): Set b(t) to be the identity braid. */
    uint8_t * bt = b;

    /* Generator */
    uint8_t generator = 0;

    /* Number of generators in final braid */
    uint16_t num_generators = 0;

    /* For each transposition t ... */
    for(i=0; i<num_transpositions; i++) {

        /* 9.2(c): For k=m to M-1 (inclusive) */
        for(k=m[i]; k<=M[i]-1; k++) {

            /* Set generator to twist b_k without a power */
            generator = k;

            /* Randomly choose a generator power */
            generator |= ((get_strong_random_number(2) ^ 1) << B8_STRAND_BITS);

            /* Store this generator to the braid */
            SET_BRAID_GENERATOR(bt, generator, num_generators);

            /* Increment number of generators */
            num_generators++;
        }

        /* 9.2(d): For k=2 to M−m−2 (inclusive) ... */
        for(k=2; k<=M[i]-m[i]; k++) {

            /* Set generator to twist b_M-k without a power */
            generator = M[i] - k;

            /* Randomly choose a generator power */
            generator |= ((get_strong_random_number(2) ^ 1) << B8_STRAND_BITS);

            /* Store this generator to the braid */
            SET_BRAID_GENERATOR(bt, generator, num_generators);

            /* Increment number of generators */
            num_generators++;
        }
    }

    /* 9.3: The result b(σ) is the product b(t1) ··· b(tr)
       The product of a pair of braids is equivalent to their concatenation.
       Because every generator for each transposition has been stored in braid *b,
       this product has already been computed. */

    /* Store the number of generators as the first two bytes */
    bt[0] = (num_generators & 0xFF00) >> 8;
    bt[1] = (num_generators & 0x00FF);

    return success;
}

/*****************************************************************************************************
* NAME :       static int get_braid_permutation(b, p)
*
* DESCRIPTION: Iterate through a braid's generators and output the resulting permutation.
*
*              The number of permutation elements is given by WALNUT_NUM_PERMUTATION_ELEMENTS.
*
* ARGUMENTS:
*
*      INPUTS:
*              void     *b              braid
*              void     *p              buffer for braid permutation
*
*      OUTPUTS:
*              void     *b              buffer containing braid permutation
*              int      return          on success, return 1
*
*/
int get_braid_permutation(uint8_t *b, uint8_t *p)
{
    /* Loop counter */
    uint16_t i;

    /* Temporary value holder */
    uint8_t tmp;

    /* Generator */
    uint8_t generator;

    /* Number of generators */
    uint16_t num_generators = GET_NUM_BRAID_GENERATORS(b);

    /* Start with the identity permutation */
    for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {
        p[i] = i;
    }

    /* Iterate through the braid and modify the permutation based upon the braid twist */
    for(i=0; i<num_generators; i++) {

        /* Get the braid generator */
        generator = GET_BRAID_GENERATOR(b, i);

        /* Remove the sign from the generator to get the strand */
        generator = GET_GENERATOR_STRAND(generator);

        /* Valid strand range is between the first and second to last strand, inclusive
           Last strand is invalid because there is no strand that follows it */
        if(generator >= WALNUT_BRAID - 1) {
            return 0;
        }

        /* Swap the permutation element at generator with the element at generator+1 */
        tmp = p[generator + 1];
        p[generator + 1] = p[generator];
        p[generator] = tmp;
    }

    return 1;
}

/*****************************************************************************************************
* NAME :       static int invert_braid(b, inv)
*
* DESCRIPTION: The inverse of a braid is a braid that, when appended to the original braid,
*              will result in the identity braid.  In other words, the inverse braid will
*              "undo" all of the generators from the original braid.
*
*              To accomplish this, the inverse braid consists of the reversed list of generators
*              from the original braid.  In addition, each generator sign is flipped.
*
*              For example, consider: b0 · b5 · b3^-1 · b2              (packed: 0x05, 0xB2)
*              The inverse would be:  b2^-1 · b3 · b5^-1 · b0^-1        (packed: 0xA3, 0xD8)
*
* ARGUMENTS:
*
*      INPUTS:
*              void     *b              braid
*              void     *inv            buffer for braid inverse
*
*      OUTPUTS:
*              void     *inv            buffer containing braid inverse
*              int      return          on success, return 1
*
*/
int invert_braid(uint8_t *b, uint8_t *inv)
{
    /* Loop counter */
    uint16_t i;

    /* Number of braid generators */
    uint16_t num_generators = GET_NUM_BRAID_GENERATORS(b);

    /* Clear the inverse braid */
    memset(inv, 0, GET_NUM_BRAID_BYTES(b));

    /* Copy number of braid generators to the inverse braid */
    inv[0]=b[0];
    inv[1]=b[1];

    /* For each braid generator */
    for(i=0; i<num_generators; i++) {

        /* Generator from original braid */
        uint8_t generator;

        /* Extract the generator from the original braid */
        generator = GET_BRAID_GENERATOR(b, i);

        /* Flip sign */
        generator ^= (1 << B8_STRAND_BITS);

        /* Inverse storage location */
        uint16_t inv_storage_location = num_generators - i - 1;

        /* Store the inverse generator to the inverse braid */
        SET_BRAID_GENERATOR(inv, generator, inv_storage_location);
    }

    return 1;
}

int concat_braid(uint8_t *b1, uint8_t *b2, uint8_t *b1b2){
    uint8_t *temp;
    temp = malloc(sizeof(uint8_t) * (GET_NUM_BRAID_BYTES(b1)+GET_NUM_BRAID_BYTES(b2)));
    concat_braid2(b1,b2,temp);
    memcpy(b1b2,temp,GET_NUM_BRAID_BYTES(temp));
    free(temp);

    return 1;
}

/*****************************************************************************************************
* NAME :       static int concat_braid(b1, b2, b1b2)
*
* DESCRIPTION: Concatenate b1 with b2, then put the result in b1b2.
*              It is valid for b1 and b1b2 to be the same pointer; this will overwrite the braid
*              at b1 with the result b1b2.  It is NOT valid for b2 and b1b2 to be the same pointer.
*
*              This is equivalent to multiplying two braids (braid multiplication).
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *b1             braid 1
*              uint8_t          *b2             braid 2
*              uint8_t          *b1b2           buffer for braid 1 · braid 2
*
*      OUTPUTS:
*              uint8_t          *b1b2           buffer containing braid 1 · braid 2
*              int              return          on success, return 1
*
*/
int concat_braid2(uint8_t *b1, uint8_t *b2, uint8_t *b1b2)
{
    /* Number of generators */
    uint16_t num_generators_b1 = GET_NUM_BRAID_GENERATORS(b1);
    uint16_t num_generators_b2 = GET_NUM_BRAID_GENERATORS(b2);

    b1b2[(GET_NUM_BRAID_GENERATORS(b1)+GET_NUM_BRAID_GENERATORS(b2)+5)/2]=0;

    /* Set each pointer to the first generator */
    b1 += 2;
    b2 += 2;
    b1b2 += 2;

    /* During copies, num_generators/2 will truncate the last element if num_generators is odd
       Therefore, always copy (num_generators+1)/2 elements */
    /* Copy the first braid */
    memcpy(&b1b2[0], &b1[0], (num_generators_b1 + 1) / 2);

    /* If num_generators_b1 is even, then the second braid can be copied directly after the first braid
       For example: ..., 0xXX, 0xXX, 0xXX, 0xUU, 0xUU, 0xUU, ...
                                             ^copy here      */
    if(num_generators_b1 % 2 == 0) {
        memcpy(&b1b2[((num_generators_b1 + 1) / 2)], &b2[0], (num_generators_b2 + 1) / 2);

    /* Else, the first braid ends in the middle of a byte
       Therefore, the second braid must be shifted by four bits
       For example: ..., 0xXX, 0xXX, 0xXX, 0xUU, 0xUU, 0xUU, ...
                                        ^copy here           */
    } else {
        /* Loop counter */
        uint16_t i;

        /* Generator to be copied */
        uint8_t generator;

        /* Position in b1b2 */
        uint16_t position;

        for(i=0; i<num_generators_b2; i++) {

            position = (num_generators_b1 + i) / 2;

            /* If i is even, the generator to be copied exists in the upper nibble of b2[i/2],
               and it is to be copied into the lower nibble of b1b2[position] */
            if(i % 2 == 0) {
                generator = (b2[i/2] & 0xF0) >> B8_GENERATOR_BITS;

                b1b2[position] = (b1b2[position] & 0xF0) | generator;

            /* Else, the generator to be copied exists in the lower nibble of b2[i/2],
               and it is to be copied into the upper nibble of b1b2[position] */
            } else {
                generator = (b2[i/2] & 0x0F);

                b1b2[position] = generator << B8_GENERATOR_BITS;
            }
        }
    }

    /* Reset the pointer */
    b1b2 -= 2;

    /* Copy the number of generators to this new braid */
    b1b2[0] = ((num_generators_b1 + num_generators_b2) & 0xFF00) >> 8;
    b1b2[1] = ((num_generators_b1 + num_generators_b2) & 0x00FF);

    return 1;
}

/*****************************************************************************************************
* NAME :       static int replace_braid_generators(braid, insertion, start, end)
*
* DESCRIPTION: Beginning with braid braid, replace generators from range start to end-1 (inclusive)
*              with the generators in braid insertion.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *braid          buffer containing original braid
*              uint8_t          *insertion      braid to be inserted
*              uint16_t         start           start position
*              uint16_t         end             end position
*
*      OUTPUTS:
*              uint8_t          *braid          buffer containing replaced braid
*              int              return          on success, return 1
*
*/
static int replace_braid_generators(uint8_t *braid, uint8_t *insertion, uint16_t start, uint16_t end)
{
    /* Track success */
    uint8_t success = 1;

    /* Number of generators currently in braid */
    uint16_t num_generators = (braid[0] << 8) | braid[1];

    /* If start is greater than the number of generators, if end is greater than
       the number of generators, or if start is greater than end, then fail */
    if(start > num_generators || end > num_generators || start > end) {
        return 0;
    }

    /* Length of end portion */
    uint16_t end_portion_length = num_generators - end;

    /* Declare end portion */
    uint8_t end_portion[((end_portion_length + 1) / 2) + 3];

    /* Set length of end portion */
    end_portion[0] = (end_portion_length & 0xFF00) >> 8;
    end_portion[1] = (end_portion_length & 0x00FF);

    /* If end is even, then the generators can be copied directly */
    if(end % 2 == 0) {

        /* Copy the end portion of the original braid into a temporary braid */
        memcpy(&end_portion[2], &braid[(end / 2) + 2], (end_portion_length + 1) / 2);

    /* Else, the generators must be shifted left by four bits */
    } else {

        /* Copy the end portion of the original braid into a temporary braid */
        memcpy(&end_portion[2], &braid[(end / 2) + 2], (end_portion_length + 2) / 2);

        /* Loop counter */
        uint16_t i;

        /* Shift each generator left by four bits (i=2 to skip the length bytes) */
        for(i=2; i<(((num_generators - end) / 2) + 2); i++) {
            end_portion[i] =
                ((end_portion[i] & 0x0F) << B8_GENERATOR_BITS) | ((end_portion[i+1] & 0xF0) >> B8_GENERATOR_BITS);
        }

        /* Shift the last generator */
        end_portion[i] = ((end_portion[i] & 0x0F) << B8_GENERATOR_BITS);
    }

    /* Change the number of generators listed to be the number of generators until start.
       By doing so, concatenating this braid with another will automatically truncate any elements
       after the start position. In practice, this creates the subbraid from the 1st generator to
       the start generator */
    braid[0] = (start & 0xFF00) >> 8;
    braid[1] = (start & 0x00FF);

    /* Append the insertion braid to the subbraid */
    success &= concat_braid(braid, insertion, braid);

    /* Append the end portion braid to the previous result */
    success &= concat_braid(braid, end_portion, braid);

    return success;
}

/*****************************************************************************************************
* NAME :       static int braid_free_reduction(b)
*
* DESCRIPTION: Free reduction is a braid reduction algorithm that removes all adjacent, inverse
*              generator pairs (Section 5.1).  An inverse pair is bn^e · bn^-e (e=1,-1),
*              where n is a braid twist.
*
*              For example, consider this list of packed generators: 0x65, 0x45, 0xDE
*              The following will be the result of each comparison:
*              0x65, 0x45, 0xDE → 0x65, 0x45, 0xDE → 0x65, 0x45, 0xDE → 0x65, 0x45, 0xDE → 0x65, 0x4E, 0xDE
*                ^^                  ^    ^                  ^^                  ^    ^            ^^
*              Note that the last pair, 0xDE, is ignored after the conclusion of comparisons.
*              After 5 and D is reduced, num_generators is decremented by two; therefore, 0xDE
*              exists outside the upper bound specified by num_generators.
*
* ARGUMENTS:
*
*      INPUTS:
*              void            *b      braid
*
*      OUTPUTS:
*              void            *b      freely reduced braid
*              int     return          on success, return 1
*
*/
int braid_free_reduction(void *b)
{
   /* Loop counters */
   uint16_t i, j;

   /* Maximum number of generators to compare */
   int16_t max = 0;

   /* Generators to compare */
   uint8_t first_generator;
   uint8_t second_generator;

   /* Pointer to braid */
   uint8_t * braid_ptr = b;

   /* Extract the number of generators from the braid */
   uint16_t num_generators = GET_NUM_BRAID_GENERATORS(braid_ptr);

   /* Set the braid pointer to the location of the first generator */
   braid_ptr += 2;

   /* Iterate over all generators in the braid */

   /* Generators are compared in pairs of i & i+1; the upper bound takes i+1 into account */
   for(i=0; i<(num_generators-1); i++) {

       /* If the halfway point hasn't been reached, then max is the distance from the first generator */
       if(i < num_generators / 2) {
           max = i + 1;

       /* Else, the halfway point has been reached, so max is the distance to the last generator */
       } else {
           max = (num_generators - 1) - i;
       }

       /* j tracks the distance from position i */
       for(j=0; j<max; j++) {

           /* If this is true, then the two generators to compare exist in the same byte */
           if((i + j) % 2 == 0) {
               first_generator = (0xF0 & braid_ptr[(i - j) / 2]) >> B8_GENERATOR_BITS;
               second_generator = (0x0F & braid_ptr[((i + j) / 2)]);

           /* Else, first_generator is the lower 4 bits of the current byte,
              and second_generator is the upper 4 bits of the next byte */
           } else {
               first_generator = (0x0F & braid_ptr[(i - j) / 2]);
               second_generator = (0xF0 & braid_ptr[((i + j + 1) / 2)]) >> B8_GENERATOR_BITS;
           }

           /* If first_generator is the not inverse of second_generator
              (bit 0, 1, or 2 not equal, or bit 3 equal), then end free reduction */
           if((GET_GENERATOR_STRAND(first_generator) != GET_GENERATOR_STRAND(second_generator))
             || (GET_GENERATOR_SIGN(first_generator) == GET_GENERATOR_SIGN(second_generator))) {

               break;

           /* Else, record that two generators will be reduced */
           } else {
               num_generators -= 2;
           }
       }

       /* If this is true, two separated generators must be stored into the same byte */
       if((i + j) % 2 == 0) {

           /* Consider this subset of the above example: 0x65, 0x45, 0xDE → 0x65, 0x4E, 0xDE
                                                                  ^    ^            ^^
              The following line will create and store the element 0x4E */
           braid_ptr[(i-j) / 2] = (0xF0 & braid_ptr[(i-j) / 2]) | second_generator;

           /* Overwrite reduced generators by shifting all unreduced generators from right to left */
           memmove(&braid_ptr[(i-j+2) / 2], &braid_ptr[(i+j+2) / 2], (num_generators - i+j-1) / 2);

       /* Else, there are no separated generators */
       } else {

           /* Overwrite reduced generators by shifting all unreduced generators from right to left */
           memmove(&braid_ptr[(i-j+1) / 2], &braid_ptr[(i+j+1) / 2], (num_generators - i+j) / 2);
       }

       /* Because elements were shifted, i must be adjusted to the new location
          of the next non-reduced element */
       i -= j;

   }

   /* Reset the pointer */
   braid_ptr = b;

   /* Store the number of generators as the first two bytes */
   braid_ptr[0] = (num_generators & 0xFF00) >> 8;
   braid_ptr[1] = (num_generators & 0x00FF);

   return 1;
}

/*****************************************************************************************************
* NAME :       static int generate_pure_braid(pb)
*
* DESCRIPTION: Generate a pure braid. (Section 8)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *pb             buffer for pure braid
*
*      OUTPUTS:
*              uint8_t          *pb             buffer containing pure braid
*              int              return          on success, return 1
*
*/
static int generate_pure_braid(uint8_t *pb)
{
    /* Random numbers */
    uint8_t i, j;

    /* Loop counter */
    uint8_t k;

    /* Generator */
    uint8_t generator;

    /* Number of pure braid generators */
    uint16_t num_generators = 0;

    /* 9.1: Choose random numbers i, j: 1 ≤ i < j < n */
    /* Condition is 0 ≤ i < j ≤ N-1 (zero-indexed) */

    /* i must be less than j; therefore, i cannot be max(j), which is N-1 */
    i = get_strong_random_number(WALNUT_BRAID - 1);

    /* i < j ≤ N-1 */
    j = get_strong_random_number(WALNUT_BRAID - (i + 1)) + (i + 1);

    /* 9.3: Iterate 0 ≤ k < j − i − 1 and append b_j−k−1 */
    for(k=0; k<j-i-1; k++) {

        /* Create b_j−k−1 */
        generator = j-k-1;

        /* Generator power is +1 (represented as 0) */
        generator |= (0 << B8_STRAND_BITS);

        /* Store this generator to the pure braid */
        SET_BRAID_GENERATOR(pb, generator, num_generators);

        /* Increment number of generators */
        num_generators++;
    }

    /* Append (b^2ǫ)_i to the braid
       (equivalent to (b^ǫ)_i · (b^ǫ)_i, so this will append (b^ǫ)_i twice) */

    /* Create b_i */
    generator = i;

    /* 9.2: Randomly choose a generator power to create (b^ǫ)_i */
    generator |= ((get_strong_random_number(2) ^ 1) << B8_STRAND_BITS);

    /* 9.4: Store this generator to the pure braid twice */
    for(k=0; k<2; k++) {

        SET_BRAID_GENERATOR(pb, generator, num_generators);

        /* Increment number of generators */
        num_generators++;
    }

    /* 9.5: Iterate 0 ≤ k < j − i − 1 and append (b^-1)_(i+k+1) */
    for(k=0; k<j-i-1; k++) {

        /* Create b_i+k+1 */
        generator = i+k+1;

        /* Generator power is -1 (represented as 1) */
        generator |= (1 << B8_STRAND_BITS);

        /* Store this generator to the pure braid */
        SET_BRAID_GENERATOR(pb, generator, num_generators);

        /* Increment number of generators */
        num_generators++;
    }

    /* Store number of generators to pure braid */
    pb[0] = (num_generators & 0xFF00) >> 8;
    pb[1] = (num_generators & 0x00FF);

    return 1;
}

/*****************************************************************************************************
* NAME :       static int generate_cloaking_element(cloak, permutation, value_L)
*
* DESCRIPTION: Generate a cloaking element (Section 4.2)
*
*              A cloaking element is a braid that disappears during E-Multiplication.  In other words,
*              when using a cloaking element, the matrix and permutation before E-Multiplication
*              is the same as the matrix and permutation after E-Multiplication.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *cloak          buffer for cloaking element
*              uint8_t          *permutation    permutation to be cloaked
*              uint8_t          value_L         number of pure braids to append to the cloaking element
*
*      OUTPUTS:
*              uint8_t          *cloak          buffer containing cloaking element
*              int              return          on success, return 1
*
*/
static int generate_cloaking_element(uint8_t *cloak, uint8_t *permutation, uint8_t value_L)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint8_t i, j;

    /* Buffer of 2K bytes */
    uint8_t buf[2048];

    /* Permutation order */
    uint8_t order;

    /* Maximum attempts to generate a random permutation of high order */
    uint8_t max_attempts = 25;

    /* Maximum possible permutation order */
    uint8_t max_order_possible = 15;

    /* Maximum encountered permutation order */
    uint8_t max_order_encountered;

    /* Permutation preimages */
    uint8_t a, b;

    /* 5.2.1: Pick a random integer 2 <= i <= N-1
              For zero-indexed, this is 1 <= i <= N-2 */
    uint8_t random = get_strong_random_number(WALNUT_BRAID - 2) + 1;

    /* 5.2.2: Compute the permutation preimages (a, b) for 1 and 2 in σ
              For zero-indexed, this is 0 and 1 */

    /* For example, consider the identity permutation: (0 1 2 3 4 5 6 7)
                       and σ, this random permutation: (4 2 5 1 6 0 7 3)
       5 is the value σ takes to 0, and 3 is the value σ takes to 1; a=5, b=3 */
    for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {
        if(permutation[i] == 0) {
            a = i;
            break;
        }
    }

    for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {
        if(permutation[i] == 1) {
            b = i;
            break;
        }
    }

    /* Random permutation */
    uint8_t random_permutation[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Final permutation */
    uint8_t final_permutation[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Generate up to max_attempts random permutations */
    for(j=0, order=0, max_order_encountered=0; j<max_attempts; j++) {

        /* 5.2.3(1): Choose a random permutation σw of high order */
        success &= generate_random_permutation_of_given_order(random_permutation, WALNUT_NUM_PERMUTATION_ELEMENTS, max_order_possible);

        /* 5.2.3(2): move i → a */
        for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {

            /* 8.1: Find the permutation preimage of a */
            if(a == random_permutation[i]) {

                /* 8.2: Swap the entries at o and i (i and random) */
                random_permutation[i] = random_permutation[random];
                random_permutation[random] = a;
                break;
            }
        }

        /* 5.2.3(3): move i + 1 → b */
        for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {

            /* 8.1: Find the permutation preimage of b */
            if(b == random_permutation[i]) {

                /* 8.2: Swap the entries at o and i (i and random+1) */
                random_permutation[i] = random_permutation[random+1];
                random_permutation[random+1] = b;
                break;
            }
        }

        /* Get the order of this permutation */
        order = get_permutation_order(random_permutation, WALNUT_NUM_PERMUTATION_ELEMENTS);

        /* If this is the highest order encountered thus far */
        if(order > max_order_encountered) {

            /* Store the order */
            max_order_encountered = order;

            /* Copy the randomly generated permutation to the final permutation buffer */
            memcpy(final_permutation, random_permutation, WALNUT_NUM_PERMUTATION_ELEMENTS);
        }

        /* If this permutation has the maximum possible order, then there is no need
           to generate more permutations. */
        if(order == max_order_possible) {

            /* Done */
            break;
        }
    }

    /* 5.2.4(a): Generate a random braid w with permutation σw */
    success &= generate_braid_with_permutation(buf, final_permutation);

    /* 5.2.4(b): Invert it (inversion is stored in cloak) */
    success &= invert_braid(buf, cloak);

    /* 5.2.5: Extend w with L pure braids */

    /* Pure braid (length + 2 to store number of generators) */
    uint8_t pb[B8_MAX_PURE_BRAID_LENGTH + 2];

    for(i=0, buf[0]=0, buf[1]=0; i<value_L; i++) {

        /* Generate a pure braid */
        success &= generate_pure_braid(pb);

        /* Append to the running product of i pure braids */
        success &= concat_braid(buf, pb, buf);
    }

    /* 9.3: Specifically, it is the freely reduced product of L pure braid generators. */
    success &= braid_free_reduction(buf);

    /* 5.2.5: Extend w with L pure braids */
    success &= concat_braid(cloak, buf, cloak);

    /* 5.2.6: Compute the cloaking element v = w · (b_i)^2 · w^-1 */

    /* Invert w to find w^-1 */
    success &= invert_braid(cloak, buf);

    /* (b_i)^2, which is equivalent to a braid of length 2
        with two generators of value i (random) */
    uint8_t bi_squared[] = {0x00, 0x02, (random << B8_GENERATOR_BITS) | random};

    /* v = w · (b_i)^2 */
    success &= concat_braid(cloak, bi_squared, cloak);

    /* v = v · w^-1     (v = w · (b_i)^2 · w^-1) */
    success &= concat_braid(cloak, buf, cloak);

    return success;
}

/*****************************************************************************************************
* NAME :       static int dehornoy_reduction(b)
*
* DESCRIPTION: Dehornoy Reduction is a method to reduce the size of a braid by finding and removing
*              complex cancellations beyond single free reduction. While solving the shortest word
*              problem in the braid group in known to be NP-Hard, Dehornoy is the best known method
*              to reducing a braid to a minimal length.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t         *b      braid
*
*      OUTPUTS:
*              uint8_t         *b      braid after Dehornoy Reduction
*              int             return  on success, return 1
*
*/


int dehornoy_reduction(uint8_t *b)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint16_t i, j, k;

    /* Generators */
    uint8_t generator;
    uint8_t first_generator;
    uint8_t second_generator;

    /* Number of generators */
    uint16_t num_generators = GET_NUM_BRAID_GENERATORS(b);

    /* When modifying generator elements, it is easiest to create the desired subbraid
       and substitute it into the original braid */
    uint8_t subbraid[num_generators * 2];

    /* Is this a handle? */
    uint8_t isHandle;

    /* Initialize number of subbraid generators to zero */
    subbraid[0] = 0;
    subbraid[1] = 0;

    /* Iterate through all the generator pairs and look for handles */
    for(i=0; i<GET_NUM_BRAID_GENERATORS(b); i++) {

        /* Assume that this is not a handle */
        isHandle = 0;

        /* second_generator is the endpoint of a potential handle */
        second_generator = GET_BRAID_GENERATOR(b, i);

        /* Work backward from second_generator to see if this is handle */
        for(j=i-1; j!=UINT16_MAX; j--) {

            /* first_generator is the opposite endpoint of a potential handle */
            first_generator = GET_BRAID_GENERATOR(b, j);

            /* If first_generator strand is one fewer than second_generator strand, then this is not a handle */
            if(GET_GENERATOR_STRAND(first_generator) == (GET_GENERATOR_STRAND(second_generator) - 1)) {
                break;
            }

            /* If first_generator strand is equivalent to second_generator strand, then this may be a handle */
            if(GET_GENERATOR_STRAND(first_generator) == (GET_GENERATOR_STRAND(second_generator))) {

                /* For this to be a handle, the generator signs must be opposite */
                isHandle = (GET_GENERATOR_SIGN(first_generator) != GET_GENERATOR_SIGN(second_generator));
                break;
            }
        }

        /* If this is a handle, then run Dehornoy Reduction */
        if(isHandle) {

            /* For every generator between the location of first_generator and second_generator (exclusive) */
            for(k=j+1; k<i; k++) {

                /* Get current generator */
                generator = GET_BRAID_GENERATOR(b, k);

                /* If the current generator strand is one greater than the generator
                   strand at the beginning of the handle, then make a substitution */
                if(GET_GENERATOR_STRAND(generator) == (GET_GENERATOR_STRAND(first_generator) + 1)) {

                    /* Generators */
                    uint8_t g1, g2, g3;

                    /* g1 is equal to the absolute value of generator, and is given the sign of second_generator */
                    g1 = GET_GENERATOR_STRAND(generator) | GET_GENERATOR_SIGN(second_generator);

                    /* g2 is equal to the absolute value of first_generator, and is given the sign of generator */
                    g2 = GET_GENERATOR_STRAND(first_generator) | GET_GENERATOR_SIGN(generator);

                    /* g3 is equal to the absolute value of generator, and is given the sign of first_generator */
                    g3 = GET_GENERATOR_STRAND(generator) | GET_GENERATOR_SIGN(first_generator);

                    /* Create a new braid with 3 generators: g1, g2, g3 */
                    uint8_t newbraid[] = {0x00, 0x03, (g1 << B8_GENERATOR_BITS) | g2, g3 << B8_GENERATOR_BITS};

                    /* Append this new braid to the subbraid */
                    success &= concat_braid(subbraid, newbraid, subbraid);

                /* Else, copy the generator as-is */
                } else {

                    /* Create a new braid with 1 generator: generator */
                    uint8_t newbraid[] = {0x00, 0x01, (generator << B8_GENERATOR_BITS)};

                    /* Append this new braid to the subbraid */
                    success &= concat_braid(subbraid, newbraid, subbraid);
                }
            }

            /* Place the subbraid into b, overwriting generators from first_generator
               location to second_generator location (inclusive) */
            success &= replace_braid_generators(b, subbraid, j, i+1);

            /* Reset number of subbraid generators */
            subbraid[0] = 0;
            subbraid[1] = 0;

            /* On next iteration, check generator at position where subbraid was inserted */
            i = j - 1;
        }
    }

    return success;
}

/*****************************************************************************************************
* NAME :       static int get_band_permutation(bands, p, num)
*
* DESCRIPTION: Given an array of num bands (not prepended with length), calculate permutation p.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *bands          bands
*              uint8_t          *p              buffer for permutation
*              uint16_t         num             number of bands
*
*      OUTPUTS:
*              uint8_t          *p              buffer containing permutation
*              int              return          on success, return 1
*
*/
static int get_band_permutation(uint8_t *bands, uint8_t *p, uint16_t num)
{
    /* Loop counter */
    uint16_t i;

    /* Temporary value */
    uint8_t tmp;

    /* Generator values */
    uint8_t generator_t;
    uint8_t generator_s;

    /* Create identity permutation */
    for(i=0; i<WALNUT_BRAID; i++) {
        p[i] = i;
    }

    /* Iterate over all band generators */
    for(i=0; i<num; i++) {

        /* Get subscript t of band generator at i */
        generator_t = (bands[i] & 0xF0) >> B8_GENERATOR_BITS;

        /* Get subscript s of band generator at i */
        generator_s = (bands[i] & 0x0F);

        /* Swap permutation elements at t and s */
        tmp = p[GET_GENERATOR_STRAND(generator_t)];
        p[GET_GENERATOR_STRAND(generator_t)] = p[GET_GENERATOR_STRAND(generator_s)];
        p[GET_GENERATOR_STRAND(generator_s)] = tmp;
    }

    return 1;
}

/*****************************************************************************************************
* NAME :       static int bkl_normal_form(b)
*
* DESCRIPTION: Birman–Ko–Lee (BKL) Normal Form was introduced in 1998 as a canonical form for a braid.
*              Every braid can be converted to BKL Normal Form, and every equivalent braid will
*              result in the same BKL output. For example, the braids b_1 b_2 b_1 and b_2 b_1 b_2
*              would result in the same output after running through BKL.
*
*              Please reference Section 4 of [3] for the algorithm description
*              (referred to herein as BKL Specification)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *b              braid before BKL conversion
*
*      OUTPUTS:
*              uint8_t          *b              braid after BKL conversion
*              int              return          on success, return 1
*
*/

/* Define this function if and only if BKL is defined */

int bkl_normal_form(uint8_t *b)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint16_t h, i, j, k, l;

    /* Generator */
    uint8_t generator;
    uint8_t generator_t;
    uint8_t generator_s;

    /* Band generators in form bands=A1·A2·...·An, where each Ai is a row in the matrix */
    uint8_t bands[GET_NUM_BRAID_GENERATORS(b) + 2][WALNUT_BRAID];

    /* Length of every band in bands */
    uint8_t band_lengths[GET_NUM_BRAID_GENERATORS(b)];

    /* δ (delta) function (BKL specification (5))
       δ = a_(n-1, n-2), a_(n-2, n-3), ..., a_(1, 0) */
    uint8_t delta[WALNUT_BRAID - 1];

    /* δ (delta) function inverse in Artin form
       δ^-1 = b_0^-1, b_1^-1, ..., b_(n-3)^-1, b_(n-2)^-1 */
    uint8_t delta_inv_artin[WALNUT_BRAID];

    /* Part of the algorithm involves substituting certain bands with delta inverse.
       These delta inverses will then be moved to their appropriate position at a later time.
       To facilitate this process, rather than substituting a band with the entire function,
       it will instead be substituted with the corresponding placeholder.
       After the placeholders are shifted into their appropriate positions, they will be substituted
       with the full functions */

    /* Delta inverse placeholder */
    uint8_t delta_inv_placeholder = 0xF0;

    /* Temporary value */
    uint8_t tmp;

    /* Permutations */
    uint8_t perm_A[WALNUT_BRAID];
    uint8_t perm_A_star[WALNUT_BRAID];
    uint8_t perm_B[WALNUT_BRAID];
    uint8_t perm_B_prime[WALNUT_BRAID];
    uint8_t perm_C[WALNUT_BRAID];
    uint8_t perm_AC[WALNUT_BRAID];
    uint8_t perm_delta[WALNUT_BRAID];

    /* Number of elements in product of disjoint cycles */
    uint8_t pdc1_length = WALNUT_BRAID;
    uint8_t pdc2_length = WALNUT_BRAID;

    /* Product of disjoint cycles */
    uint8_t pdc1[pdc1_length];
    uint8_t pdc2[pdc2_length];

    /* Triples used to calculate meets */
    uint8_t triples[WALNUT_BRAID][3];

    /* Meet length */
    uint8_t meet_length = WALNUT_BRAID;

    /* Meet */
    uint8_t meet[meet_length];

    /* Number of triples */
    uint8_t num_triples;

    /* Triples {i,j,m} listed as three-digit number ijm */
    uint16_t ijm[WALNUT_BRAID];

    /* Ai is a positive word such that Ai ϵ [0,1] */
    uint8_t Ai[WALNUT_BRAID * 2];

    /* Apply the length to delta_inv_artin */
    delta_inv_artin[0] = 0;
    delta_inv_artin[1] = WALNUT_BRAID-1;

    /* Build the δ (in band form) and δ^-1 (in Artin form) functions */
    for(i=0; i<WALNUT_BRAID-1; i++) {

        /* Create a_(t, s), where t = WALNUT_BRAID - i - 1, s = WALNUT_BRAID - i - 2 */
        generator = MAKE_BAND_GENERATOR(WALNUT_BRAID - i - 1, WALNUT_BRAID - i - 2, 0);

        /* Store generator to delta function */
        delta[i] = generator;

        /* Create b_i^-1 */
        generator = i | (1 << B8_STRAND_BITS);

        /* Set generator at i to generator */
        SET_BRAID_GENERATOR(delta_inv_artin, generator, i);
    }

    /* Initialize number of band generators to number of braid generators */
    bands[0][0] = b[0];
    bands[0][1] = b[1];

    /* Convert the braid generators into band generators */
    for(i=0; i<GET_NUM_BRAID_GENERATORS(b); i++) {

        /* Braid generator */
        generator = GET_BRAID_GENERATOR(b, i);

        /* Sign of braid generator */
        uint8_t sign = GET_GENERATOR_SIGN(generator);

        /* Remove sign from generator */
        generator = GET_GENERATOR_STRAND(generator);

        /* Create band generator a_(generator+1, generator)^sign, and store at position i in bands */
        SET_BAND_GENERATOR(bands, MAKE_BAND_GENERATOR((generator + 1), generator, sign), i, 0);

        /* Set length of this band to 1 */
        band_lengths[i] = 1;
    }

    /* Eliminate each band generator that has a negative exponent, replacing it with (δ^-1)A
       a_(t, s)^-1 = (δ^-1)(a_(n-1, n-2), a_(n-2, n-3), ..., a_(t+1, t), a_(t, s-1), ..., a_(1, 0))
                       · (a_(t-1, t-2), ..., a_(s+1, s)) */
    for(i=GET_NUM_BAND_GENERATORS(bands)-1; i!=UINT16_MAX; i--) {

        /* Subscript t of a_(t, s) */
        generator_t = GET_BAND_GENERATOR_T(bands, i, 0);

        /* Subscript s of a_(t, s) */
        generator_s = GET_BAND_GENERATOR_S(bands, i, 0);

        /* If this is an inverse band generator, replace a_(t, s)^-1 with (δ^-1)·Ai */
        if(GET_GENERATOR_SIGN(generator_t) && GET_GENERATOR_SIGN(generator_s)) {

            /* Construct Ai */

            /* Place (δ^-1) at the first position */
            Ai[0] = delta_inv_placeholder;

            /* Construct a_(n-1, n-2), a_(n-2, n-3), ..., a_(t+1, t) */
            for(j=WALNUT_BRAID-1, k=1; j>GET_GENERATOR_STRAND(generator_t); j--) {

                /* Construct a_(j, j-1) */
                Ai[k] = (MAKE_BAND_GENERATOR(j, (j-1), 0));

                /* Increment to next band position */
                k++;
            }

            /* If the strand of generator_s != 0, construct a_(t, s-1) */
            if(GET_GENERATOR_STRAND(generator_s) != 0) {

                /* Construct a_(t, s-1) */
                Ai[k] = (MAKE_BAND_GENERATOR((GET_GENERATOR_STRAND(generator_t)), (GET_GENERATOR_STRAND(generator_s) - 1), 0));

                /* Increment to next band position */
                k++;
            }

            /* If the strand of generator_s != 0,1, construct a_(s-1, s-2)...a_(1, 0) */
            if((GET_GENERATOR_STRAND(generator_s) != 0) && (GET_GENERATOR_STRAND(generator_s) != 1)) {

                for(j=GET_GENERATOR_STRAND(generator_s)-1; j>0; j--) {

                    /* Construct  a_(j, j-1) */
                    Ai[k] = (MAKE_BAND_GENERATOR(j, (j-1), 0));

                    /* Increment to next band position */
                    k++;
                }
            }

            /* Because each braid generator was converted to the form a_(q, q-1),
               the list of bands (a_(t-1, t-2), ..., a_(s+1, s)) will be empty.
               Therefore, this step can be skipped, and Ai is now fully constructed. */

            /* Store the new length to band_lengths */
            band_lengths[i] = k;

            /* With Ai constructed, replace a_(t, s)^-1 with (δ^-1)A */
            memcpy(bands[i+1], Ai, band_lengths[i]);
        }
    }

    /* Moving from right to left, shift each (δ^-1) to the left using the formulas:
         Ai(δ^k) = (δ^k)·τ^k(Ai)        (δ^-1)(δ^k)=(δ^(k-1))           τ^k(a_(t, s))=a_(t+k, s+k) */
    /* Note that the following loop does not actually shift each δ^-1 to the left.
       Rather, it applies the τ^k (tau) function to each Ai.
       k is found by counting the number of δ^-1 terms encountered from the right to the beginning of Ai.
       The δ^-1 terms will be removed at a later time. */

    /* For each row of bands */
    for(i=GET_NUM_BAND_GENERATORS(bands)-1, k=0, l=0; i!=UINT16_MAX; i--) {

        /* If a δ^-1 term has been found, or if i is at the leftmost position */
        if((GET_BAND_GENERATOR(bands, i, 0) == delta_inv_placeholder) || (i == 0)) {

            /* If the power of τ (tau) is not zero, then band values must be modified */
            if(k != 0) {

                /* For each row of bands between current τ (tau) row and previous τ (tau) row-1 (inclusive) */
                for(j=i; j<l; j++) {

                    /* For each band generator in this row (skip the first element if it is equal to the δ^-1 placeholder) */
                    for(h=(GET_BAND_GENERATOR(bands, j, 0) == delta_inv_placeholder); h<band_lengths[j]; h++) {

                        /* Subscript t of a_(t, s) */
                        generator_t = GET_BAND_GENERATOR_T(bands, j, h);

                        /* Subscript s of a_(t, s) */
                        generator_s = GET_BAND_GENERATOR_S(bands, j, h);

                        /* New subscript t (i.e. t=t-(k % WALNUT_BRAID), with some additional math to prevent underflow) */
                        generator_t = (generator_t + WALNUT_BRAID - (k % WALNUT_BRAID)) % WALNUT_BRAID;

                        /* New subscript s (i.e. s=s-(k % WALNUT_BRAID), with some additional math to prevent underflow) */
                        generator_s = (generator_s + WALNUT_BRAID - (k % WALNUT_BRAID)) % WALNUT_BRAID;

                        /* Subscript t must not be less than subscript s
                           If this is the case, then swap them (i.e. store a_(s, t)) */
                        if(generator_t < generator_s) {
                            SET_BAND_GENERATOR(bands, (MAKE_BAND_GENERATOR(generator_s, generator_t, 0)), j, h);

                        /* Else, do not swap them (i.e. store a_(t, s)) */
                        } else {
                            SET_BAND_GENERATOR(bands, (MAKE_BAND_GENERATOR(generator_t, generator_s, 0)), j, h);
                        }
                    }
                }
            }

            /* If this iteration were the result of a δ^-1 term being found */
            if(GET_BAND_GENERATOR(bands, i, 0) == delta_inv_placeholder) {

                /* Increment power of τ (tau) */
                k++;

                /* Mark that δ^-1 was last seen at position i */
                l=i;
            }
        }
    }

    /* With each (δ^k) term already in the result braid, eliminate each δ^-1 placeholder in bands */
    for(i=0; i<GET_NUM_BAND_GENERATORS(bands); i++) {

        /* If a δ^-1 placeholder has been found */
        if(GET_BAND_GENERATOR(bands, i, 0) == delta_inv_placeholder) {

            /* Eliminate the placeholder, and decrement band_lengths[i] by 1 */
            memmove(&bands[i+1][0], &bands[i+1][1], --band_lengths[i]);
        }
    }

    /* Change bands to left canonical form (BKL Specification lemma 4.3) */
    for(h=0; h<GET_NUM_BAND_GENERATORS(bands)-1; h++) {

        /* For every band from h to the band at position zero */
        for(i=h; i!=UINT16_MAX; i--) {

            /* Compute the right complement A* of A (BKL Specification lemma 4.3 (I)),
               where perm_A_star is the permutation of A* */

            /* Get permutation of band subword A */
            success &= get_band_permutation(&bands[i+1][0], perm_A, band_lengths[i]);

            /* perm_delta is the permutation of the delta function */
            success &= get_band_permutation(delta, perm_delta, WALNUT_BRAID-1);

            /* To calculate the right complement A* of band A, multiply the inverse permutation of A
               by the permutation of δ. */

            /* Invert permutation of A */
            success &= invert_permutation(perm_A, WALNUT_BRAID);

            /* Multiply permutations of A^-1 and δ to find A* */
            success &= multiply_permutations(perm_A_star, perm_A, perm_delta, WALNUT_BRAID);

            /* Invert permutation of A^-1 to return to A */
            success &= invert_permutation(perm_A, WALNUT_BRAID);

            /* Get permutation of B; for this application, this is the permutation of A+1 */
            success &= get_band_permutation(&bands[i+2][0], perm_B, band_lengths[i+1]);

            /* Compute the meet C = A* ⋀ B, where B = A+1 (BKL Specification lemma 4.3 (II)) */

            /* Make a list of triples (i,j,m) such that m=0, ..., WALNUT_BRAID-1 appears in pdc(perm_A_star) and pdc(perm_B)
               (BKL Specification lemma 4.1 (1)) */

            /* Product of disjoint cycles of A* */
            success &= get_product_of_disjoint_cycles(pdc1, perm_A_star, WALNUT_BRAID);

            /* Product of disjoint cycles of B */
            success &= get_product_of_disjoint_cycles(pdc2, perm_B, WALNUT_BRAID);

            /* Trim cycles of length 1 from pdc1 */
            success &= trim_product_of_disjoint_cycles(pdc1, WALNUT_BRAID, &pdc1_length);

            /* Trim cycles of length 1 from pdc2 */
            success &= trim_product_of_disjoint_cycles(pdc2, WALNUT_BRAID, &pdc2_length);

            /* For m=0, 1, ..., n-1, make the triple */
            for(j=0; j<WALNUT_BRAID; j++) {

                /* Initialize i and j to invalid locations */
                triples[j][0] = UINT8_MAX;
                triples[j][1] = UINT8_MAX;

                /* Check pdc1 for m (i.e. fill value i in (i,j,m)) */
                for(l=0, tmp=0; l<pdc1_length; l++) {

                    /* If the element has been found */
                    /* Rather than look for element j, look for element WALNUT_BRAID - j - 1
                       This will construct the triples with m in descending order */
                    if((WALNUT_BRAID - j - 1) == (pdc1[l] & ~0x80)) {

                        /* Store cycle number to triples */
                        triples[j][0] = tmp;

                        /* Done */
                        break;

                    /* Else if the MSB is set, then the next loop iteration will start a new cycle */
                    } else if(pdc1[l] & 0x80) {

                        /* Increment the cycle number */
                        tmp++;
                    }
                }

                /* Check pdc2 for m (i.e. fill value j in (i,j,m)) */
                for(l=0, tmp=0; l<pdc2_length; l++) {

                    /* If the element has been found */
                    /* Rather than look for element j, look for element WALNUT_BRAID - j - 1
                       This will construct the triples with m in descending order */
                    if((WALNUT_BRAID - j - 1) == (pdc2[l] & ~0x80)) {

                        /* Store cycle number to triples */
                        triples[j][1] = tmp;

                        /* Done */
                        break;

                    /* Else if the MSB is set, then the next loop iteration will start a new cycle */
                    } else if(pdc2[l] & 0x80) {

                        /* Increment the cycle number */
                        tmp++;
                    }
                }

                /* Store m (i.e. fill value m in (i,j,m)) */
                triples[j][2] = (WALNUT_BRAID - j - 1);
            }

            /* Sort the list of triples lexicographically (BKL Specification lemma 4.1 (2)) */

            /* For each triple, convert to three-digit number ijm */
            for(j=0, num_triples=0; j<WALNUT_BRAID; j++) {

                /* If this is a valid triple */
                if((triples[j][0] != UINT8_MAX && triples[j][1] != UINT8_MAX)) {

                    /* Convert triple {i,j,m} to the three-digit number ijm */
                    ijm[num_triples] = (100 * triples[j][0]) + (10 * triples[j][1]) + (1 * triples[j][2]);

                    /* Increment number of triples */
                    num_triples++;
                }
            }

            /* Assume that ijm is not sorted */
            uint8_t isSorted = 0;

            /* Sort pairs */
            while(!isSorted) {

                /* Begin by assuming pairs is sorted */
                isSorted = 1;

                /* For each pair */
                for(j=0; j<num_triples-1; j++) {

                    /* If the triple at the current pair is less than the triple at the next pair */
                    if(ijm[j] < ijm[j+1]) {

                        /* The list is not sorted */
                        isSorted = 0;

                        /* Swap the pairs */
                        uint16_t tmp_ijm = ijm[j];
                        ijm[j] = ijm[j+1];
                        ijm[j+1] = tmp_ijm;
                    }
                }
            }

            /* Find triples with identical first two entries, then extract the third entries
               (BKL Specification lemma 4.1 (3, 4)) */
            for(j=0, meet_length=0; j<num_triples; j++) {

                /* Extract the third entry m, and store it to the meet */
                meet[j] = ijm[j] % 10;

                /* If j is at the last ijm element, or if the current ij is different than the next ij,
                   then this is the end of a cycle */
                if((j == num_triples-1) || ((ijm[j] / 10) != (ijm[j+1] / 10))) {

                    /* Mark end of cycle */
                    meet[j] |= 0x80;
                }
            }

            /* Trim cycles of length 1 from meet. Result: meet = C = A* ⋀ B */
            success &= trim_product_of_disjoint_cycles(meet, num_triples, &meet_length);


            /* Compute B' such that B = CB' (BKL Specification lemma 4.3 (III)) */

            /* Create permutation of C, starting with the identity permutation */
            for(j=0; j<WALNUT_BRAID; j++) {
                perm_C[j] = j;
            }

            if(meet_length != 0) {

                /* For all elements of meet, adjust perm_C */
                for(j=0; j<meet_length-1; j++) {

                    /* Swap perm_C[meet[j]] with perm_C[meet[j+1]] (ignore MSB) */
                    tmp = perm_C[(meet[j] & ~0x80)];
                    perm_C[(meet[j] & ~0x80)] = perm_C[(meet[j+1] & ~0x80)];
                    perm_C[(meet[j+1] & ~0x80)] = tmp;

                    /* If the next element is the end of a cycle, skip it */
                    if(meet[j+1] & 0x80) {
                        j++;
                    }
                }
            }

            /* perm_C is now the permutation of C, and perm_B is the permutation of B (i.e. A+1) */
            /* Invert perm_C to find the inverse permutation of C */
            success &= invert_permutation(perm_C, WALNUT_BRAID);

            /* Compute perm_B_prime = B' = (C^-1)B */
            success &= multiply_permutations(perm_B_prime, perm_C, perm_B, WALNUT_BRAID);

            /* Compute AC (BKL Specification lemma 4.3 (IV)) */

            /* Invert C^-1 to get C */
            success &= invert_permutation(perm_C, WALNUT_BRAID);

            /* Compute perm_AC = AC */
            success &= multiply_permutations(perm_AC, perm_A, perm_C, WALNUT_BRAID);


            /* perm_AC Γ perm_B_prime, where perm_AC = AC and perm_B_prime = B' */

            /* Convert AC to a product of disjoint cycles */
            success &= get_product_of_disjoint_cycles(pdc1, perm_AC, WALNUT_BRAID);

            /* Convert B' to a product of disjoint cycles */
            success &= get_product_of_disjoint_cycles(pdc2, perm_B_prime, WALNUT_BRAID);

            /* Trim pdc1 */
            success &= trim_product_of_disjoint_cycles(pdc1, WALNUT_BRAID, &pdc1_length);

            /* Trim pdc2 */
            success &= trim_product_of_disjoint_cycles(pdc2, WALNUT_BRAID, &pdc2_length);

            /* Before converting back to bands, these cycles must be reversed
               in order to match BKL Specification Theorem 3.4 (written immediately before Corollary 3.5):
               "The associated permutation is the cycle associated to the reverse of the subscript array." */

            /* Reverse pdc1 */
            success &= reverse_product_of_disjoint_cycles(pdc1, &pdc1_length);

            /* Reverse pdc2 */
            success &= reverse_product_of_disjoint_cycles(pdc2, &pdc2_length);

            /* Convert the cycles of AC to a set of band generators */
            for(j=0, band_lengths[i]=0; j<pdc1_length; j++) {

                /* If this cycle element is not the end of a cycle */
                if(!(pdc1[j] & 0x80)) {

                    /* Subscript t of a_(t, s) */
                    generator_t = pdc1[j] & ~0x80;

                    /* Subscript s of a_(t, s) */
                    generator_s = pdc1[j+1] & ~0x80;

                    /* Set band generator */
                    SET_BAND_GENERATOR(bands, (MAKE_BAND_GENERATOR(generator_t, generator_s, 0)), i, band_lengths[i]);

                    /* Increment number of band generators */
                    band_lengths[i]++;
                }
            }

            /* Convert the cycles of B' to a set of band generators */
            for(j=0, band_lengths[i+1]=0; j<pdc2_length; j++) {

                /* If this cycle element is not the end of a cycle */
                if(!(pdc2[j] & 0x80)) {

                    /* Subscript t of a_(t, s) */
                    generator_t = pdc2[j] & ~0x80;

                    /* Subscript s of a_(t, s) */
                    generator_s = pdc2[j+1] & ~0x80;

                    /* Set band generator */
                    SET_BAND_GENERATOR(bands, (MAKE_BAND_GENERATOR(generator_t, generator_s, 0)), (i+1), band_lengths[i+1]);

                    /* Increment number of band generators */
                    band_lengths[i+1]++;
                }
            }
        }

        /* Move to the next pair of bands */
    }


    /* BKL Specification: THE ALGORITHM (4):
       Some of canonical factors at the beginning of A1·A2·...·Ak can be δ.
       Absorb them into the power of δ */
    /* Because the bands are left-weighted, all δ terms are grouped on the left.
       Therefore, scan the bands and stop once a non δ term is encountered */
    /* Note that an Ai term is δ if and only if its length is WALNUT_BRAID-1 */
    for(j=0; j<GET_NUM_BAND_GENERATORS(bands); j++) {

        /* If the number of bands at j is not WALNUT_BRAID-1, then break */
        if(band_lengths[j] != WALNUT_BRAID-1) {
            break;
        }
    }

    /* Subtract the number of δ terms found from the power k */
    k = k - j;

    /* Clear the result braid */
    memset(b, 0, GET_NUM_BRAID_BYTES(b));

    /* For each δ^-1 in k */
    for(i=0; i<k; i++) {

        /* Append δ^-1 to the braid result */
        success &= concat_braid(b, delta_inv_artin, b);
    }

    /* Convert all band generators to Artin generators, and store them to the result braid */
    for(i=j, Ai[0]=0; i<GET_NUM_BAND_GENERATORS(bands); i++) {

        if(band_lengths[i] != 0) {

            /* For all band generators in this row */
            for(j=0; j<band_lengths[i]; j++) {

                /* Set k, the number of generators to add to the result braid, to zero */
                k=0;

                /* Subscript t of a_(t, s) */
                generator_t = GET_BAND_GENERATOR_T(bands, i, j);

                /* Subscript s of a_(t, s) */
                generator_s = GET_BAND_GENERATOR_S(bands, i, j);

                /* For all values between t-1 and s+1 (inclusive) */
                for(l=generator_t-1; l!=generator_s; l--) {

                    /* In Ai, set braid generator to value l at position k */
                    SET_BRAID_GENERATOR(Ai, l, k);

                    /* Increment position */
                    k++;
                }

                /* In Ai, set braid generator to value of subscript s at position k */
                SET_BRAID_GENERATOR(Ai, generator_s, k);

                /* Increment position */
                k++;

                /* For all values between s+1 and t-1 (inclusive) */
                for(l=generator_s+1; l!=generator_t; l++) {

                    /* In Ai, set braid generator to value l^-1 at position k */
                    SET_BRAID_GENERATOR(Ai, (l | (1 << B8_STRAND_BITS)), k);

                    /* Increment position */
                    k++;
                }

                /* Store number of generators to Ai */
                Ai[1] = k;

                /* Append braid Ai to result braid b */
                success &= concat_braid(b, Ai, b);
            }
        }
    }

    return success;
}

/*****************************************************************************************************
* NAME :       static int stochastic_rewriting(b)
*
* DESCRIPTION: Stochastic Rewriting is a new method which is useful for smaller processors
*              because it just involves random rewriting from lookup tables. (Section 5.3.2)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *b              braid before stochastic rewriting
*
*      OUTPUTS:
*              uint8_t          *b              braid after stochastic rewriting
*              int              return          on success, return 1
*
*/

/* Define this function if and only if STOCHASTIC is defined */
#if defined(STOCHASTIC) || defined(STOCHASTIC_WO_DEHORNOY)

static int stochastic_rewriting(uint8_t *b)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint16_t i, j, l, m;

    /* Generators */
    uint8_t generator;
    uint8_t first_generator;
    uint8_t second_generator;

    /* Intermediate value */
    uint8_t u;

    /* Minimum braid chunk size */
    uint8_t minchunk = 5;

    /* Maximum braid chunk size */
    uint8_t maxchunk = 10;

    /* Random braid chunk size */
    uint8_t randchunk = 0;

    /* Random offset */
    uint8_t randoffset = 0;

    /* Number of matches */
    uint8_t matches;

    /* Locations of matches */
    uint8_t match_locations[maxchunk];

    /* Temporary braid */
    uint8_t tmp[maxchunk];

    /* Y Generators */
    uint8_t Y_generators[GET_NUM_BRAID_GENERATORS(b) * 3];

    /* References A: Stochastic Rewriting "Y" Generator Relations (Partition {4, 3})
       The first and second column signify the number of generators in the rest of the row.
       Note that each "F" is a placeholder to fill the packed byte. */
    uint8_t Y_generator_relations[79][7] = {
        {0, 4, 0x36, 0xBE},
        {0, 4, 0xE3, 0x6B},
        {0, 4, 0x63, 0xEB},
        {0, 5, 0x10, 0x38, 0x8F},
        {0, 5, 0x21, 0x39, 0x9F},
        {0, 5, 0x54, 0x6C, 0xCF},
        {0, 5, 0x65, 0x6D, 0xDF},
        {0, 5, 0x81, 0x03, 0x8F},
        {0, 5, 0x92, 0x13, 0x9F},
        {0, 5, 0xC5, 0x46, 0xCF},
        {0, 5, 0xD6, 0x56, 0xDF},
        {0, 5, 0x00, 0xB8, 0x9F},
        {0, 5, 0x11, 0xB9, 0xAF},
        {0, 5, 0x44, 0xEC, 0xDF},
        {0, 5, 0x55, 0xED, 0xEF},
        {0, 5, 0x90, 0x0B, 0x8F},
        {0, 5, 0xA1, 0x1B, 0x9F},
        {0, 5, 0xD4, 0x4E, 0xCF},
        {0, 5, 0xE5, 0x5E, 0xDF},
        {0, 5, 0x22, 0xBA, 0xBF},
        {0, 5, 0x55, 0xED, 0xEF},
        {0, 5, 0xB2, 0x2B, 0xAF},
        {0, 5, 0xE5, 0x5E, 0xDF},
        {0, 5, 0x32, 0x3A, 0xAF},
        {0, 5, 0x65, 0x6D, 0xDF},
        {0, 6, 0x09, 0x31, 0x8B},
        {0, 6, 0x1A, 0x32, 0x9B},
        {0, 6, 0x35, 0xEB, 0x6D},
        {0, 6, 0x09, 0x61, 0x8E},
        {0, 6, 0x1A, 0x62, 0x9E},
        {0, 6, 0x2B, 0x63, 0xAE},
        {0, 6, 0x4D, 0x65, 0xCE},
        {0, 6, 0xB0, 0x93, 0x18},
        {0, 6, 0xB1, 0xA3, 0x29},
        {0, 6, 0xD3, 0x5E, 0xB6},
        {0, 6, 0xE0, 0x96, 0x18},
        {0, 6, 0xE1, 0xA6, 0x29},
        {0, 6, 0xE2, 0xB6, 0x3A},
        {0, 6, 0xE4, 0xD6, 0x5C},
        {0, 6, 0x30, 0x9B, 0x18},
        {0, 6, 0x31, 0xAB, 0x29},
        {0, 6, 0x5E, 0x36, 0xDB},
        {0, 6, 0x60, 0x9E, 0x18},
        {0, 6, 0x61, 0xAE, 0x29},
        {0, 6, 0x62, 0xBE, 0x3A},
        {0, 6, 0x64, 0xDE, 0x5C},
        {0, 8, 0x0A, 0x09, 0x28, 0x29},
        {0, 8, 0x1B, 0x1A, 0x39, 0x3A},
        {0, 8, 0x4E, 0x4D, 0x6C, 0x6D},
        {0, 8, 0x90, 0xA0, 0x92, 0x82},
        {0, 8, 0xA1, 0xB1, 0xA3, 0x93},
        {0, 8, 0xD4, 0xE4, 0xD6, 0xC6},
        {0, 8, 0x1A, 0x0A, 0x18, 0x28},
        {0, 8, 0x2B, 0x1B, 0x29, 0x39},
        {0, 8, 0x5E, 0x4E, 0x5C, 0x6C},
        {0, 8, 0x09, 0x2B, 0x18, 0x3A},
        {0, 8, 0x09, 0x4D, 0x18, 0x5C},
        {0, 8, 0x1A, 0x4D, 0x29, 0x5C},
        {0, 8, 0x2B, 0x4D, 0x3A, 0x5C},
        {0, 8, 0x09, 0x5E, 0x18, 0x6D},
        {0, 8, 0x1A, 0x5E, 0x29, 0x6D},
        {0, 8, 0x2B, 0x5E, 0x3A, 0x6D},
        {0, 8, 0xA0, 0x92, 0xB1, 0x83},
        {0, 8, 0xC0, 0x94, 0xD1, 0x85},
        {0, 8, 0xC1, 0xA4, 0xD2, 0x95},
        {0, 8, 0xC2, 0xB4, 0xD3, 0xA5},
        {0, 8, 0xD0, 0x95, 0xE1, 0x86},
        {0, 8, 0xD1, 0xA5, 0xE2, 0x96},
        {0, 8, 0xD2, 0xB5, 0xE3, 0xA6},
        {0, 8, 0x2B, 0x09, 0x3A, 0x18},
        {0, 8, 0x4D, 0x09, 0x5C, 0x18},
        {0, 8, 0x4D, 0x1A, 0x5C, 0x29},
        {0, 8, 0x4D, 0x2B, 0x5C, 0x3A},
        {0, 8, 0x5E, 0x09, 0x6D, 0x18},
        {0, 8, 0x5E, 0x1A, 0x6D, 0x29},
        {0, 8, 0x5E, 0x2B, 0x6D, 0x3A},
        {0, 9, 0x34, 0xD3, 0x5C, 0xB5, 0xCF},
        {0, 9, 0xC3, 0x4D, 0x35, 0xCB, 0x5F},
        {0, 9, 0x4D, 0x34, 0xDB, 0x5C, 0xBF}
    };

    /* 5.3.2.1: Freely reduce the braid if it has not already been reduced. */
    success &= braid_free_reduction(b);

    /* 5.3.2.2(1): Convert the braid to "Y generators" */

    /* Initialize Y Generator braid to have length 0 */
    Y_generators[0] = 0;
    Y_generators[1] = 0;

    /* Initialize tmp braid to have length 0 */
    tmp[0] = 0;
    tmp[1] = 0;

    /* Partition {4, 3} */
    uint8_t p[] = {4, 3};

    /* Create an array the same length as the number of partitions of N-1 */
    uint8_t r[sizeof(p) + 1];

    /* Initialize this array with the sum of the partitions */
    r[0] = 0;
    for(i=1; i<sizeof(p)+1; i++) {
        r[i] = r[i-1] + p[i-1];
    }

    /* Run through every generator in braid b */
    for(l=0; l<GET_NUM_BRAID_GENERATORS(b); l++) {

        /* Get generator in braid b at position l */
        generator = GET_BRAID_GENERATOR(b, l);

        /* Determine which partition contains generator k */
        j = 0;
        while(r[j] <= GET_GENERATOR_STRAND(generator)) {
            j++;
        }
        j--;

        /* Build the response */
        u = GET_GENERATOR_STRAND(generator) - r[j];

        if(u < p[j] - 1) {

            /* answer will have two elements */
            tmp[1] = 0x02;

            /* If the Artin generator is an inverse, then invert the Y result
               Note that double negation (!!) is used to make a non-zero value 1, and to keep zero as 0 */

            /* NON-INV: {r[j]+u, 1}     INV: {r[j]+u+1, 1} */
            SET_BRAID_GENERATOR(tmp, (r[j] + u + (!!GET_GENERATOR_SIGN(generator))), 0);

            /* NON-INV: {r[j]+u+1, -1}  INV: {r[j]+u, -1} */
            SET_BRAID_GENERATOR(tmp, ((r[j] + u + (!GET_GENERATOR_SIGN(generator))) | (1 << B8_STRAND_BITS)), 1);

        } else {

            /* answer will have one element */
            tmp[1] = 0x01;

            /* If the Artin generator is an inverse, then invert the Y result */

            /* NON-INV: {r[j]+u, 1}     INV: {r[j]+u, -1} */
            SET_BRAID_GENERATOR(tmp, ((r[j] + u) | GET_GENERATOR_SIGN(generator)), 0);
        }

        /* Append result to braid of Y Generators */
        success &= concat_braid(Y_generators, tmp, Y_generators);
    }

    /* 5.3.2.2(2): Freely reduce the result. */
    success &= braid_free_reduction(Y_generators);

    /* Initialize number of partitions to its maximum possible value */
    uint16_t num_partition = (GET_NUM_BRAID_GENERATORS(Y_generators) / minchunk) + 1;

    /* Instantiate a partition list with num_partition elements */
    uint8_t partition[num_partition];

    /* Pointer to the beginning of the list of partitions */
    uint8_t * partition_ptr = partition;

    /* Repeat the process 3 times */
    for(m=0; m<3; m++) {

        /* 5.3.2.3: Partition the braid into chunks of random sizes between 5-10 generators each. */
        success &= generate_integer_partition(partition, &num_partition, GET_NUM_BRAID_GENERATORS(Y_generators), minchunk, maxchunk);

        /* Iterate through chunks of the Y generator braid */
        for(l=0; l<GET_NUM_BRAID_GENERATORS(Y_generators); l+=randchunk) {

            /* Get the current random chunk size, then increment the partition pointer to the next position for later iterations */
            randchunk = *(partition_ptr++);

            /* 5.3.2.4: For each partition, choose a random offset into the partition (from the first to second-last) */
            randoffset = get_strong_random_number(randchunk - 1);

            /* 5.3.2.5(1): Take the offset and offset+1 generators */
            first_generator = GET_BRAID_GENERATOR(Y_generators, (l + randoffset));
            second_generator = GET_BRAID_GENERATOR(Y_generators, (l + randoffset + 1));

            /* 5.3.2.5(2): Look up a replacement in the replacement table */

            /* Iterate through each row of Y_generator_relations */
            for(i=0; i<(sizeof(Y_generator_relations) / sizeof(Y_generator_relations)[0]); i++) {

                /* Iterate through each column of row i in Y_generator_relations */
                for(j=0, matches=0; j<Y_generator_relations[i][1]-1; j++) {

                    /* If first_generator is equal to the current position in Y_generator_relations,
                       and if second_generator is equal to the next position in Y_generator_relations,
                       then this is a match. */
                    if((first_generator == GET_BRAID_GENERATOR(Y_generator_relations[i], j))
                        && (second_generator == GET_BRAID_GENERATOR(Y_generator_relations[i], (j+1)))) {

                        /* Store match location, and increment number of matches */
                        match_locations[matches++] = j;
                    }
                }

                /* If a match was found in this row */
                if(matches) {

                    /* If multiple matches were found */
                    if(matches > 1) {

                        /* Pick a random match */
                        matches = get_strong_random_number(matches) + 1;
                    }

                    /* Convert 1-indexed match position to 0-indexed match position */
                    matches--;

                    /* Extract match location */
                    j = match_locations[matches];

                    /* Left portion of replacement */
                    uint8_t left[GET_NUM_BRAID_BYTES(Y_generator_relations[i])];

                    /* Right portion of replacement */
                    uint8_t right[GET_NUM_BRAID_BYTES(Y_generator_relations[i])];

                    /* Inverse left portion of replacement */
                    uint8_t left_inv[GET_NUM_BRAID_BYTES(Y_generator_relations[i])];

                    /* Inverse right portion of replacement */
                    uint8_t right_inv[GET_NUM_BRAID_BYTES(Y_generator_relations[i])];

                    /* Empty braid */
                    uint8_t empty[] = {0x00, 0x00};

                    /* Copy the entire row into both left and right */
                    memcpy(left, Y_generator_relations[i], GET_NUM_BRAID_BYTES(Y_generator_relations[i]));
                    memcpy(right, Y_generator_relations[i], GET_NUM_BRAID_BYTES(Y_generator_relations[i]));

                    /* Get left portion of replacement */
                    success &= replace_braid_generators(left, empty, j, (GET_NUM_BRAID_GENERATORS(left)));

                    /* Get right portion of replacement */
                    success &= replace_braid_generators(right, empty, 0, j+2);

                    /* Invert left portion of replacement */
                    success &= invert_braid(left, left_inv);

                    /* Invert right portion of replacement */
                    success &= invert_braid(right, right_inv);

                    /* Concatenate left_inv with right_inv, and store result in tmp */
                    success &= concat_braid(left_inv, right_inv, tmp);

                    /* 5.2.3.6: Replace those two generators with the relation. */
                    success &= replace_braid_generators(Y_generators, tmp, (l + randoffset), (l + randoffset + 2));

                    /* Because a substitution was made, the chunk size randchunk must be adjusted */
                    /* Two braid generators were removed, the braid generators in left_inv were appended,
                       and the braid generators in right_inv were appended */
                    randchunk = randchunk - 2 + GET_NUM_BRAID_GENERATORS(left_inv) + GET_NUM_BRAID_GENERATORS(right_inv);

                    /* End replacement */
                    break;
                }
            }
        }

        /* Reset the partition pointer to its original position */
        partition_ptr = partition;

        /* 5.2.3.7(a): Once you reach the last partition, freely reduce. */
        success &= braid_free_reduction(Y_generators);

        /* 5.2.3.7(b): Return to step 3 in order to repeat the process 3 times */
    }

    /* 5.3.2.8(1): After the third repetition, convert back to Artin generators. */

    /* Clear size of b */
    b[0] = 0;
    b[1] = 0;

    /* Create an array the same length as the number of partitions N-1 */
    /* Already exists as r[] */

    /* Initialize this array with the sum of partitions */
    /* Already initialized */

    /* Run through every Y generator in Y_generators */
    for(l=0; l<GET_NUM_BRAID_GENERATORS(Y_generators); l++) {

        /* Get current generator */
        generator = GET_BRAID_GENERATOR(Y_generators, l);

        /* Determine which partition contains generator k */
        j=0;
        while(r[j] <= GET_GENERATOR_STRAND(generator)) {
            j++;
        }
        j--;

        /* Build the response */
        u = GET_GENERATOR_STRAND(generator) - r[j];

        /* Clear size of tmp */
        tmp[0] = 0;
        tmp[1] = 0;

        for(i=0; i<p[j]-u; i++) {

            /* {r[j]+u+i, 1} */
            uint8_t local[] = {0x00, 0x01, ((r[j]+u+i) << B8_GENERATOR_BITS)};

            /* answer = answer + {r[j]+u+i, 1} */
            success &= concat_braid(tmp, local, tmp);
        }

        /* If the Y generator is an inverse, then invert the Artin result */
        if(GET_GENERATOR_SIGN(generator)) {

            /* Inverse braid */
            uint8_t inv[GET_NUM_BRAID_BYTES(tmp)];

            /* Invert the braid */
            success &= invert_braid(tmp, inv);

            /* Copy the inverse braid into the original braid */
            memcpy(tmp, inv, GET_NUM_BRAID_BYTES(inv));
        }

        /* Append answer to the braid */
        success &= concat_braid(b, tmp, b);
    }

    /* 5.2.3.8(2): Freely reduce. */
    success &= braid_free_reduction(b);

    return success;
}

#endif


/*****************************************************************************************************
* NAME :       static int walnut_emul(m, p, braid, T)
*
* DESCRIPTION: The one-way function E-Multiplication (Section 7) is an action that starts with a matrix
*              and permutation, a braid, and results in a new matrix and permutation. E-Multiplication
*              is iterative, and by definition is applied one braid generator at a time.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          m[][]           initial matrix
*              uint8_t          *p              initial permutation
*              uint8_t          *braid          braid
*              const uint8_t    *T              T-values
*
*      OUTPUTS:
*              uint8_t          m[][]           matrix after E-Multiplication
*              uint8_t          *p              permutation after E-Multiplication
*              int              return          on success, return 1
*
*/
int walnut_emul(uint8_t m[WALNUT_BRAID][WALNUT_BRAID], uint8_t *p,
                uint8_t *braid, const uint8_t *T)
{
    /* Loop counters */
    size_t counter, j;

    /* Number of generators */
    uint16_t num_generators = GET_NUM_BRAID_GENERATORS(braid);

    for(counter=0; counter<num_generators; counter++) {

        /* CB matrix elements */
        uint8_t a, b, c;

        /* Generator */
        uint8_t generator = GET_BRAID_GENERATOR(braid, counter);

        /* Get strand, which is the absolute value of generator */
        uint8_t i = GET_GENERATOR_STRAND(generator);

        /* Valid strand range is between the first and second to last strand, inclusive.
           Last strand is invalid because there is no strand that follows it. */
        if(i >= WALNUT_BRAID - 1) {
            return 0;
        }

        /* Get sign of generator */
        uint8_t e = GET_GENERATOR_SIGN(generator);

        /* Note that the pseudocode uses negative values (e.g. b = -a).
           In a Galois Field, for any value v, {v + (-v) = 0}.
           Because addition in GF(2^n) is equivalent to xor, this can be
           rewritten: {v xor (-v) = 0}. Since any value xor'd with itself
           is zero, it can be stated that v is equivalent to -v. */

        /* If the generator is not inverted */
        if(e == 0) {
            a = T[p[i]];
            b = a;
            c = 1;

        /* Else, the generator is inverted */
        } else {
            a = 1;
            b = MINV(T[p[i+1]]);
            c = b;
        }

        /* Iterate down columns and matrix-multiply each value */
        /* Note that addition in GF(2^n) is equivalent to xor */
        if(i != 0) {
            for(j=0; j<WALNUT_BRAID; j++) {
                m[j][i-1] ^= GMUL(m[j][i], a);
            }
        }

        for(j=0; j<WALNUT_BRAID; j++) {
            m[j][i+1] ^= GMUL(m[j][i], c);
        }

        for(j=0; j<WALNUT_BRAID; j++) {
            m[j][i] = GMUL(m[j][i], b);
        }

        /* Temporary value holder */
        uint8_t temp;

        /* Swap permutation based on the generator */
        temp = p[i];
        p[i] = p[i+1];
        p[i+1] = temp;
    }

    return 1;
}

/*****************************************************************************************************
* NAME :       static int walnut_mmul(d, a, b)
*
* DESCRIPTION: Standard matrix multiplication.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t         d[][]   buffer for product matrix
*              uint8_t         a[][]   multiplier matrix
*              uint8_t         b[][]   multiplicand matrix
*
*      OUTPUTS:
*              uint8_t         d[][]   buffer with product matrix
*              int             return  on success, return 1
*
*/
int walnut_mmul(uint8_t d[WALNUT_BRAID][WALNUT_BRAID],
                uint8_t a[WALNUT_BRAID][WALNUT_BRAID],
                uint8_t b[WALNUT_BRAID][WALNUT_BRAID])

{
    /* Loop counters */
    uint8_t i, j, k;

    for(i=0; i<WALNUT_BRAID; i++) {
        for(j=0; j<WALNUT_BRAID; j++) {

            /* Initialize product at [i][j] to zero */
            d[i][j] = 0;
            for(k=0; k<WALNUT_BRAID; k++) {

                /* Ensure that operands are within WALNUT_FIELD */
                if(a[i][k] >= WALNUT_FIELD || b[k][j] >= WALNUT_FIELD) {
                    return 0;
                }

                /* Multiply a[i][k] by b[k][j]. Repeat down the row of a
                   and the column of b, while summing the products.
                   Recall that addition in GF(2^n) is equivalent to xor. */
                d[i][j] ^= GMUL(a[i][k], b[k][j]);
            }
        }
    }

    return 1;
}

/*****************************************************************************************************
* NAME :       static int walnut_message_encoder(hashed_msg, encoded_msg)
*
* DESCRIPTION: The WalnutDSA Message Encoder translates a sequence of bits into a braid. The encoding
*              method uses pure generators specified in Section 5.1. These generators are used to map
*              the data in hashed_msg to a braid. The resulting braid is processed via free reduction.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t          *hashed_msg     hashed message
*              void             *encoded_msg    buffer for encoded message
*      OUTPUTS:
*              void             *encoded_msg    buffer containing encoded message
*              int              return          on success, return 1
*
*/
int walnut_message_encoder(const uint8_t *hashed_msg, void *encoded_msg)
{
    /* Collection of pure braid generators (Section 5.1)
       First two columns contain number of generators in its row.
       Remaining columns contain generators in packed form. */
    uint8_t pure_braid_generators[16][12] = {
                    /* g1 */
                    {0, 14, 0x65, 0x43, 0x21, 0x00, 0x9A, 0xBC, 0xDE },
                    /* g2 */
                    {0, 10, 0x65, 0x43, 0x22, 0xBC, 0xDE },
                    /* g3 */
                    {0, 6,  0x65, 0x44, 0xDE},
                    /* g4 */
                    {0, 2,  0x66},

                    /* g1 ^ 2 */
                    {0, 16, 0x65, 0x43, 0x21, 0x00, 0x00, 0x9A,
                            0xBC, 0xDE },
                    /* g2 ^ 2 */
                    {0, 12, 0x65, 0x43, 0x22, 0x22, 0xBC, 0xDE },
                    /* g3 ^ 2 */
                    {0, 8,  0x65, 0x44, 0x44, 0xDE},
                    /* g4 ^ 2 */
                    {0, 4,  0x66, 0x66},

                    /* g1 ^ 3 */
                    {0, 18, 0x65, 0x43, 0x21, 0x00, 0x00, 0x00, 0x9A,
                            0xBC, 0xDE },
                    /* g2 ^ 3 */
                    {0, 14, 0x65, 0x43, 0x22, 0x22, 0x22, 0xBC, 0xDE },
                    /* g3 ^ 3 */
                    {0, 10, 0x65, 0x44, 0x44, 0x44, 0xDE},
                    /* g4 ^ 3 */
                    {0, 6,  0x66, 0x66, 0x66},

                    /* g1 ^ 4 */
                    {0, 20, 0x65, 0x43, 0x21, 0x00, 0x00, 0x00, 0x00,
                            0x9A, 0xBC, 0xDE },
                    /* g2 ^ 4 */
                    {0, 16, 0x65, 0x43, 0x22, 0x22, 0x22, 0x22, 0xBC,
                            0xDE },
                    /* g3 ^ 4 */
                    {0, 12, 0x65, 0x44, 0x44, 0x44, 0x44, 0xDE},
                    /* g4 ^ 4 */
                    {0, 8,  0x66, 0x66, 0x66, 0x66},
    };

    /* Loop counter */
    uint8_t i;

    /* Track success */
    uint8_t success = 1;

    /* Pointer to encoded message */
    uint8_t * em = encoded_msg;

    /* Extracted block */
    uint8_t block;

    /* Set encoded message length to zero */
    em[0] = 0;
    em[1] = 0;

    block = 0;

    /* 5.1.1: Break the message M into l 4-bit blocks. */
    for(i=0; i<WALNUT_HASH_SIZE * 2; i++) {

        /* Extract block from hashed_msg */
        /* Note the minus two from the hashed_msg pointer. This is needed because the GET_BRAID_GENERATOR
           macro expects the first two bytes of an array to be its length. However, hashed_msg does not
           have these two length bytes; to reuse this macro, shift the pointer to the left by two. */
        block = GET_BRAID_GENERATOR((hashed_msg-2), i);

        /* 5.1.2(a,b,c): Copy generators based on block into the encoded message */
        success &= concat_braid(em, pure_braid_generators[block], em);
    }

    /* 5.1.3: The encoded message E(M) is the freely reduced product of these l block results */
    success &= braid_free_reduction(em);

    return success;
}

/*****************************************************************************************************
* NAME :       static int generate_private_key(*b, *T)
*
* DESCRIPTION: Generate private key. Integer N and finite field Fq are predefined as
*              WALNUT_BRAID and WALNUT_FIELD, respectively.
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t         *b              buffer to store
*                                              private key braid
*              uint8_t         *T              buffer to store
*                                              T-values
*
*      OUTPUTS:
*              uint8_t         *b              buffer containing
*                                              private key braid
*              uint8_t         *T              buffer containing
*                                              T-values
*              int             return          on success, return 1
*
*/
static int generate_private_key(uint8_t *b, uint8_t *T)
{
    /* Track success */
    uint8_t success = 1;

    /* Permutations */
    uint8_t perm1[WALNUT_BRAID];
    uint8_t perm2[WALNUT_BRAID];

    /* Second braid */
    uint8_t *b2;

    /* 4.1: Choose an integer N ≥ 8 and associated braid group Bn
                Defined as WALNUT_BRAID */

    /* 4.2: Choose a finite field Fq of q ≥ 32 elements.
                Defined as WALNUT_FIELD */

    /* 4.3: Compute the value L from the security level, which determines the minimal length of
            certain random braid words.
            L = ⌈SecurityLevel/(2 · log_2(N(N - 1))⌉.
                Defined as WALNUT_VALUE_L */

    /* 4.4: Compute the value l from the security level, which determines the minimal length of
            the private key.
            l = [SecurityLevel + log_2(l) - log_2(N - 1) - log_2((l - 2 + N) choose (N - 1))]
                Defined as WALNUT_VALUE_l */

    /* 4.5: Choose a random set of T-values */
    success &= generate_tvalues(T);

#ifdef KAT_INTERMEDIATES
    printf("n: %d\nq: %d\nL: %d\n", WALNUT_BRAID, WALNUT_FIELD, WALNUT_VALUE_L);
    printBuffer(T, WALNUT_BRAID, "T-values");
    printf("l: %d\n", WALNUT_VALUE_l);
#endif

    do {
        /* 4.6(1): Generate a random braid of length l */
        success &= generate_braid(b, WALNUT_VALUE_l);

        /* Get braid permutation */
        success &= get_braid_permutation(b, perm1);

    /* 4.6(2): This braid must not be a purebraid, so regenerate if the permutation is trivial (i.e. identity) */
    } while(compare_identitiy_permutation(perm1, WALNUT_BRAID));

    /* 4.7: Freely reduce this braid */
    success &= braid_free_reduction(b);

    /* If the last generator occurs on the upper four bits of a byte,
       then set the lower four bits to zero */
    if(GET_NUM_BRAID_GENERATORS(b) % 2) {
        SET_BRAID_GENERATOR(b, 0, GET_NUM_BRAID_GENERATORS(b));
    }

    do {
        /* 4.8(1): Generate a second random braid of length l */
        success &= generate_braid(b + GET_NUM_BRAID_BYTES(b), WALNUT_VALUE_l);

        /* 4.8(2): Freely reduce this braid */
        success &= braid_free_reduction(b + GET_NUM_BRAID_BYTES(b));

        /* Get braid permutation */
        success &= get_braid_permutation(b + GET_NUM_BRAID_BYTES(b), perm2);

    /* 4.8(3): Regenerate if this braid has the identity permutation or both braids have the same permutation */
    } while(compare_identitiy_permutation(perm2, WALNUT_BRAID) || !memcmp(perm1, perm2, WALNUT_BRAID));

    /* If the last generator occurs on the upper four bits of a byte,
       then set the lower four bits to zero */
    b2 = b + GET_NUM_BRAID_BYTES(b);

    if(GET_NUM_BRAID_GENERATORS(b2) % 2) {
        SET_BRAID_GENERATOR(b2, 0, GET_NUM_BRAID_GENERATORS(b2));
    }

    /* 4.9: Priv(S) is the first freely reduced braid, which has permutation σ_Priv(S),
            and Priv(S') is the second freely reduced braid, which has permutation σ_Priv(S') */

    return success;
}

/*****************************************************************************************************
* NAME :       static int generate_public_key(*priv, *pub, *T)
*
* DESCRIPTION: Generate public key. Run E-Multiplication with the identity matrix,
*              identity permutation, and private key braid *priv.
*
*              The resulting matrix and permutation are packed as Pub(S)
*              and stored in *pub after version, N, q, and *T, respectively.
*
*              (version = WALNUT_VERSION, N = WALNUT_BRAID, q = WALNUT_FIELD)
*
* ARGUMENTS:
*
*      INPUTS:
*              uint8_t         *priv           private key
*              uint8_t         *pub            buffer to store
*                                              public key
*              uint8_t         *T              T-values
*
*      OUTPUTS:
*              uint8_t         *pub            buffer containing
*                                              public key
*              int             return          on success, return 1
*
*/
static int generate_public_key(uint8_t *priv, uint8_t *pub, uint8_t *T)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counter */
    uint8_t i;

    /* IdN, where IdN is the NxN identity matrix */
    uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID];

    /* IdSN, where IdSN is the identity permutation in SN */
    uint8_t permutation[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Fill the matrix and permutation */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Set row i of the matrix to be that of the identity matrix */
        memset(matrix[i], 0, WALNUT_BRAID);
        matrix[i][i] = 1;

        /* Set the next element of the identity permutation */
        permutation[i] = i;
    }

    /* 4.1: Pub(S) = (IdN, IdSN) ⋆ Priv(S)
            See section 7 for more information on E-Multiplication */
    success &= walnut_emul(matrix, permutation, priv, T);

    /* 4.3(1): Publish the Public Key with the following data: N, q, Pub(S) */

    /* Publish N */
    pub[WALNUT_VERSION_POSITION] = WALNUT_BRAID;

    /* Publish upper byte of q */
    pub[WALNUT_VERSION_POSITION + 1] = (WALNUT_FIELD & 0xFF00) >> 8;

    /* Publish lower byte of q */
    pub[WALNUT_VERSION_POSITION + 2] = (WALNUT_FIELD & 0x00FF);

    /* Pub(S) consists of the matrix and permutation output of E-Multiplication */
    /* Manipulate the matrix and publish all but the last row */
    for(i=0; i<WALNUT_BRAID-1; i++) {

        /* Pack each row of the matrix */
        success &= pack_elem(matrix[i], WALNUT_MATRIX_ELEMENT_BITS, WALNUT_BRAID);

        /* Publish each row of the matrix */
        memcpy(&pub[WALNUT_PUBKEY_S_MATRIX_POSITION + (i * WALNUT_PUBKEY_MATRIX_ROW_LENGTH)],
            matrix[i], WALNUT_PUBKEY_MATRIX_ROW_LENGTH);
    }

    /* Publish non-zero element from last row */
    /* This element is placed in the public key directly after the seven packed rows of the matrix
       In addition, the element is shifted left so that it is appended, rather than prepended, with zeros */
    pub[WALNUT_PUBKEY_S_MATRIX_POSITION + ((WALNUT_BRAID-1) * WALNUT_PUBKEY_MATRIX_ROW_LENGTH)] =
        matrix[(WALNUT_BRAID-1)][(WALNUT_BRAID-1)] << (8 - WALNUT_MATRIX_ELEMENT_BITS);

    /* Pack the permutation */
    success &= pack_elem(permutation, WALNUT_PERMUTATION_ELEMENT_BITS, WALNUT_NUM_PERMUTATION_ELEMENTS);

    /* Publish the permutation */
    memcpy(&pub[WALNUT_PUBKEY_S_PERMUTATION_POSITION], permutation, WALNUT_PUBKEY_PERMUTATION_LENGTH);


    /* Repeat the process for Pub(S') */
    /* Fill the matrix and permutation */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Set row i of the matrix to be that of the identity matrix */
        memset(matrix[i], 0, WALNUT_BRAID);
        matrix[i][i] = 1;

        /* Set the next element of the identity permutation */
        permutation[i] = i;
    }

    /* 4.2: Pub(S') = (IdN, IdSN) ⋆ Priv(S')
            See section 6 for more information on E-Multiplication */
    success &= walnut_emul(matrix, permutation, priv + GET_NUM_BRAID_BYTES(priv), T);


    /* 4.3(2): Publish the Public Key with the remaining data: T-Values, Matrix Part of Pub(S') */

    /* Manipulate the matrix of Pub(S') and publish all but the last row */
    for(i=0; i<WALNUT_BRAID-1; i++) {

        /* Pack each row of the matrix */
        success &= pack_elem(matrix[i], WALNUT_MATRIX_ELEMENT_BITS, WALNUT_BRAID);

        /* Publish each row of the matrix */
        memcpy(&pub[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION + (i * WALNUT_PUBKEY_MATRIX_ROW_LENGTH)],
            matrix[i], WALNUT_PUBKEY_MATRIX_ROW_LENGTH);
    }

    /* Publish non-zero element from last row */
    pub[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION + ((WALNUT_BRAID-1) * WALNUT_PUBKEY_MATRIX_ROW_LENGTH)] =
        matrix[WALNUT_BRAID-1][(WALNUT_BRAID-1)] << (8 - WALNUT_MATRIX_ELEMENT_BITS);

    /* Pack the T-values */
    success &= pack_elem(T, WALNUT_TVALUE_BITS, WALNUT_NUM_TVALUES);

    /* Publish the T-values */
    memcpy(&pub[WALNUT_PUBKEY_TVALUES_POSITION], T, WALNUT_PUBKEY_TVALUES_LENGTH);

    return success;
}

//**************************************************************************
// GLOBAL FUNCTIONS
//**************************************************************************

int key_generation(void *privkey, void *pubkey)
{
    /* Track success */
    uint8_t success = 1;

    /* Pointer to the private key */
    uint8_t * priv = privkey;

    /* Pointer to the public key */
    uint8_t * pub = pubkey;

    /* Buffer for T-values */
    uint8_t Tvalues[WALNUT_NUM_TVALUES];

    /* Generate the private key */
    success &= generate_private_key(priv, Tvalues);

    /* Generate the public key */
    success &= generate_public_key(priv, pub, Tvalues);

    return success;
}
 
int signature_generation(void *signature, void *sig_length, const void *message, size_t length, const void *privkey)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counter */
    uint16_t i;

    /* Buffer to store hash */
    uint8_t hash[WALNUT_HASH_SIZE];

    /* Buffer to store encoded message */
    uint8_t encoded_message[(WALNUT_HASH_SIZE * B8_MAX_PURE_BRAID_LENGTH) + 2];

    /* Buffer to store signature. Because signature rewriting may temporarily produce a large braid,
       ensure that the buffer is large enough to hold all of its data. */
    uint8_t sig_buffer[B8_MAX_BRAID_LENGTH];

    /* Buffer for permutations */
    uint8_t permutation[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Pointer to private key */
    uint8_t * priv = (uint8_t *)privkey;

    /* Pointer to signature */
    uint8_t * sig = signature;

    /* Pointer to signature length */
    long long * sl = sig_length;

    /* Clear all data from the signature buffer */
    memset(sig_buffer, 0, sizeof(sig_buffer));

    /* 5.1: Generate the encoded message E(M) as per section 5.1 */

    /* If the security level is 128, use SHA2-256 */
#if WALNUT_SECURITY_LEVEL == 128

    /* Hash the message */
    SHA256(message, length, hash);
       
#endif

    /* If the security level is 256, use SHA2-512 */
#if WALNUT_SECURITY_LEVEL == 256

    /* Hash the message */
    SHA512(message, length, hash);

#endif

#ifdef KAT_INTERMEDIATES
    	printBuffer(hash, WALNUT_HASH_SIZE, "Hash in crypto_sign");
#endif

    /* Encode the hashed message */
    success &= walnut_message_encoder(hash, encoded_message);

    /* 5.2: Generate cloaking elements v1, v2, v3 as defined in section 5.2 */
    uint8_t v1[B8_MAX_CLOAKING_ELEMENT_LENGTH];
    uint8_t v2[B8_MAX_CLOAKING_ELEMENT_LENGTH];
    uint8_t v3[B8_MAX_CLOAKING_ELEMENT_LENGTH];

    /* Set data at v1, v2, v3 to zero */
    memset(v1, 0, B8_MAX_CLOAKING_ELEMENT_LENGTH);
    memset(v2, 0, B8_MAX_CLOAKING_ELEMENT_LENGTH);
    memset(v3, 0, B8_MAX_CLOAKING_ELEMENT_LENGTH);

    /* v1 cloaks for the identity permutation */
    /* Create the identity permutation */
    for(i=0; i<WALNUT_NUM_PERMUTATION_ELEMENTS; i++) {
        permutation[i] = i;
    }

    /* Generate a cloaking element for the identity permutation */
    success &= generate_cloaking_element(v1, permutation, WALNUT_VALUE_L);

#ifdef KAT_INTERMEDIATES
    	unpack_and_print_braid(v1, "Cloaking element v1");
#endif

    /* v2 cloaks for σPriv(S') */
    success &= get_braid_permutation(priv + GET_NUM_BRAID_BYTES(priv), permutation);

    /* Generate a cloaking element for σPriv(S') */
    success &= generate_cloaking_element(v2, permutation, WALNUT_VALUE_L);

#ifdef KAT_INTERMEDIATES
    	unpack_and_print_braid(v2, "Cloaking element v2");
#endif

    /* v3 cloaks for σPriv(S) */
    success &= get_braid_permutation(priv, permutation);

    /* Generate a cloaking element for σPriv(S) */
    success &= generate_cloaking_element(v3, permutation, WALNUT_VALUE_L);

#ifdef KAT_INTERMEDIATES
    	unpack_and_print_braid(v3, "Cloaking element v3");
#endif

    /* Generate inverse of the private key */
    uint8_t priv_inverse[GET_NUM_BRAID_BYTES(priv)];

    success &= invert_braid(priv, priv_inverse);

    /* 5.3: Compute the signature Sig = R(v3 · Priv(S)^-1 · v1 · E(M) · Priv(S') · v2) */

    /* Sig = v3 · Priv(S)^-1) */
    success &= concat_braid(v3, priv_inverse, sig_buffer);

    /* Sig = Sig · v1   (= v3 · Priv(S)^-1 · v1) */
    success &= concat_braid(sig_buffer, v1, sig_buffer);

    /* Sig = Sig · E(M)   (= v3 · Priv(S)^-1 · v1 · E(M)) */
    success &= concat_braid(sig_buffer, encoded_message, sig_buffer);

    /* Sig = Sig · Priv(S')   (= v3 · Priv(S)^-1 · v1 · E(M) · Priv(S')) */
    success &= concat_braid(sig_buffer, priv + GET_NUM_BRAID_BYTES(priv), sig_buffer);

    /* Sig = Sig · v2   (= v3 · Priv(S)^-1 · v1 · E(M) · Priv(S') · v2) */
    success &= concat_braid(sig_buffer, v2, sig_buffer);

    /* Freely reduce this signature */
    success &= braid_free_reduction(sig_buffer);

#ifdef KAT_INTERMEDIATES
    	unpack_and_print_braid(sig_buffer, "Signature w/free reduction pre-rewriting");
#endif

    /* 5.3: A braid rewritten as per 5.3 */

    /* If the rewriting method chosen is BKL */
#ifdef BKL

    /* 5.3.1: Rewrite the signature as per BKL Normal Form */
    success &= bkl_normal_form(sig_buffer);

    printf("len8 = %d \n",GET_NUM_BRAID_GENERATORS(sig_buffer));

    success &= braid_free_reduction(sig_buffer);

#ifdef KAT_INTERMEDIATES
    	unpack_and_print_braid(sig_buffer, "Signature after BKL pre-dehornoy");
#endif

#elif defined(STOCHASTIC) || defined(STOCHASTIC_WO_DEHORNOY)

    /* 5.3.2: Rewrite the signature as per Stochastic Rewriting */
    success &= stochastic_rewriting(sig_buffer);

    success &= braid_free_reduction(sig_buffer);

#ifdef KAT_INTERMEDIATES
	unpack_and_print_braid(sig_buffer, "Signature after stochastic rewriting");
#endif

#endif

#if defined(STOCHASTIC) || defined(BKL)

    /* 5.3.3: Rewrite the signature as per Dehornoy Reduction */
    success &= dehornoy_reduction(sig_buffer);

#ifdef KAT_INTERMEDIATES
	unpack_and_print_braid(sig_buffer, "Signature after dehornoy");
#endif

#endif

    /* If the last generator occurs on the upper four bits of a byte,
       then set the lower four bits to zero */
    if(GET_NUM_BRAID_GENERATORS(sig_buffer) % 2) {
        SET_BRAID_GENERATOR(sig_buffer, 0, GET_NUM_BRAID_GENERATORS(sig_buffer));
    }

    /* Get current signature byte length */
    *sl = GET_NUM_BRAID_BYTES(sig_buffer);

    /* Append the message to the end of the signature */
    memcpy(&sig_buffer[*sl], (uint8_t *)message, length);

    /* Add the message length to the signature length */
    *sl += length;

    /* Copy the data in signature buffer to signature */
    memcpy(sig, sig_buffer, *sl);

    return success;
}

int signature_verification(void *pubkey, const void *signature, void *sig_length, unsigned char **returnmes, unsigned long long *meslen)
{
    /* Track success */
    uint8_t success = 1;

    /* Loop counters */
    uint16_t i, j;

    /* Pointer to the public key */
    uint8_t * pub = pubkey;

    /* Pointer to the signature */
    uint8_t * sig = (uint8_t *)signature;

    /* Pointer to the signature length */
    long long * sl = sig_length;

    /* Buffer to store encoded message */
    uint8_t encoded_message[(WALNUT_HASH_SIZE * B8_MAX_PURE_BRAID_LENGTH) + 2];

    /* Matrix 1 (M1) */
    uint8_t matrix1[WALNUT_BRAID][WALNUT_BRAID];

    /* Permutation 1 (σ1) */
    uint8_t permutation1[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* Matrix 2 (M2) */
    uint8_t matrix2[WALNUT_BRAID][WALNUT_BRAID];

    /* Permutation 2 (σ2) */
    uint8_t permutation2[WALNUT_NUM_PERMUTATION_ELEMENTS];

    /* MatrixPart(Pub(S')) */
    uint8_t matrixpart[WALNUT_BRAID][WALNUT_BRAID];

    /* Matrix 3 (M3) */
    uint8_t matrix3[WALNUT_BRAID][WALNUT_BRAID];

    /* Check if either of the first two signature bytes (corresponding to number of generators) was corrupted.
       Even if this check passes, it is possible that the bytes were corrupted in another manner.
       In that case, it will be detected when M2 and M3 are checked for equality. */
    if(GET_NUM_BRAID_BYTES(sig) > *sl) {

        /* Allow memory to be deallocated outside of this function */
        *returnmes = malloc(0);
        *meslen = 0;

        /* Return failure */
        return 0;
    }

    /* Message length = length of the signature, minus number of braid bytes */
    uint16_t message_length = *sl - (GET_NUM_BRAID_BYTES(sig));

    /* Extract the message from the end of the signature */
    uint8_t message[message_length];
    memcpy(message, &sig[(GET_NUM_BRAID_BYTES(sig))], message_length);

    /* Copy the message to the external pointer for SUPERCOP validation */
    *returnmes = malloc(message_length);
    memcpy(*returnmes, message, message_length);
    *meslen = message_length;

    /* Hash the message */
    uint8_t hash[WALNUT_HASH_SIZE];

    /* If the security level is 128, use SHA2-256 */
#if WALNUT_SECURITY_LEVEL == 128

    /* Hash the message */
    SHA256(message, message_length, hash);

#endif

    /* If the security level is 256, use SHA2-512 */
#if WALNUT_SECURITY_LEVEL == 256

    /* Hash the message */
    SHA512(message, message_length, hash);

#endif

#ifdef KAT_INTERMEDIATES
	printBuffer(hash, WALNUT_HASH_SIZE, "Hash in crypto_sign");
#endif

    /* 6.1: Compute E(M) as per section 5.1 */
    success &= walnut_message_encoder(hash, encoded_message);

    /* 6.2: Evaluate (M1, σ1) = (IdN, IdSN ) ⋆ E(M)
        where IdN is the N × N identity matrix and IdSN is the identity permutation in SN */

    /* Initialize matrix1 to IdN and permutation1 to IdSN */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Set this matrix row to all zeros */
        memset(matrix1[i], 0, WALNUT_BRAID);

        /* Set this matrix row at offset i to 1 */
        matrix1[i][i] = 1;

        /* Set the permutation at i to i */
        permutation1[i] = i;
    }

    /* Extract the T-values from the public key */
    uint8_t Tvalues[WALNUT_NUM_TVALUES];
    for(i=0; i<WALNUT_NUM_TVALUES; i++) {

        /* Starting at the position of the first T-value, extract each T-value of width WALNUT_TVALUE_BITS */
        Tvalues[i] = extract_elem(&pub[WALNUT_PUBKEY_TVALUES_POSITION], i * WALNUT_TVALUE_BITS, WALNUT_TVALUE_BITS);
    }

    /* Evaluate (M1, σ1) = (IdN, IdSN ) ⋆ E(M) */
    success &= walnut_emul(matrix1, permutation1, encoded_message, Tvalues);

#ifdef KAT_INTERMEDIATES
	printBuffer(matrix1, WALNUT_BRAID*WALNUT_BRAID, "E(hash) * Identity Matrix");
#endif

    /* 6.3: Evaluate (M2, σ2) = Pub(S) ⋆ Sig */

    /* Extract the matrix and the permutation of Pub(S) from the public key */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Skip the last row of the matrix */
        for(j=0; j<WALNUT_BRAID && i!=WALNUT_BRAID-1; j++) {

            /* Starting at the position of the first matrix element, extract each element of width WALNUT_MATRIX_ELEMENT_BITS */
            matrix2[i][j] = extract_elem(&pub[WALNUT_PUBKEY_S_MATRIX_POSITION],
                WALNUT_MATRIX_ELEMENT_BITS * (j + (i * WALNUT_BRAID)), WALNUT_MATRIX_ELEMENT_BITS);
        }

        /* Starting at the position of the first permutation element, extract each element of width WALNUT_PERMUTATION_ELEMENT_BITS */
        permutation2[i] = extract_elem(&pub[WALNUT_PUBKEY_S_PERMUTATION_POSITION],
            i * WALNUT_PERMUTATION_ELEMENT_BITS, WALNUT_PERMUTATION_ELEMENT_BITS);
    }

    /* Initialize the last row of the matrix as all zeros */
    memset(matrix2[WALNUT_BRAID-1], 0, WALNUT_BRAID);

    /* Set the last element of the matrix to the last element from the public key matrix */
    matrix2[WALNUT_BRAID-1][WALNUT_BRAID-1] = extract_elem(&pub[WALNUT_PUBKEY_S_MATRIX_POSITION],
        WALNUT_MATRIX_ELEMENT_BITS * ((WALNUT_BRAID - 1) * WALNUT_BRAID), WALNUT_MATRIX_ELEMENT_BITS);

    /* Evaluate (M2, σ2) = Pub(S) ⋆ Sig */
    success &= walnut_emul(matrix2, permutation2, sig, Tvalues);

    /* 6.4: Compute the matrix multiplication M3 = M1 · MatrixPart(Pub(S')) */

    /* Extract the matrix of Pub(S') from the public key */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Skip the last row of the matrix */
        for(j=0; j<WALNUT_BRAID && i!=WALNUT_BRAID-1; j++) {

            /* Starting at the position of the first matrix element, extract each element of width WALNUT_MATRIX_ELEMENT_BITS */
            matrixpart[i][j] = extract_elem(&pub[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION],
                WALNUT_MATRIX_ELEMENT_BITS * (j + (i * WALNUT_BRAID)), WALNUT_MATRIX_ELEMENT_BITS);
        }
    }

    /* Initialize the last row of the matrix as all zeros */
    memset(matrixpart[WALNUT_BRAID-1], 0, WALNUT_BRAID);

    /* Set the last element of the matrix to the last element from the public key matrix */
    matrixpart[WALNUT_BRAID-1][WALNUT_BRAID-1] = extract_elem(&pub[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION],
        WALNUT_MATRIX_ELEMENT_BITS * ((WALNUT_BRAID - 1) * WALNUT_BRAID), WALNUT_MATRIX_ELEMENT_BITS);

    /* Compute the matrix multiplication M3 = M1 · MatrixPart(Pub(S')) */
    success &= walnut_mmul(matrix3, matrix1, matrixpart);

#ifdef KAT_INTERMEDIATES
    printBuffer(matrix2, WALNUT_BRAID*WALNUT_BRAID, "Public Key * Signature");
	printBuffer(matrix3, WALNUT_BRAID*WALNUT_BRAID, "E(hash) * Public Key");
#endif

    /* 6.5: Compare M2 and M3 for equality. If M2 = M3 then the signature is valid. */
    for(i=0; i<WALNUT_BRAID; i++) {
        for(j=0; j<WALNUT_BRAID; j++) {

            /* If two corresponding elements do not match, then the signature is invalid */
            if(matrix2[i][j] != matrix3[i][j]) {
                success = 0;
            }
        }
    }

    return success;
}

void unpack_and_print_braid(uint8_t *braid, unsigned char *name)
{
	int i=0, count = 0;
	printf("%s\n", name);

	for(i=0; i < GET_NUM_BRAID_GENERATORS(braid); i++)
	{
		count++;
		uint8_t generator = GET_BRAID_GENERATOR(braid, i);
		if(GET_GENERATOR_SIGN(generator))
			printf("-");
		printf("%d\t", GET_GENERATOR_STRAND(generator));

		if(count == 8)
		{
			printf("\n");
			count = 0;
		}
	}
	printf("\n");

	fflush(stdout);
}

void printBuffer(uint8_t *braid, size_t size,  char *name)
{
	printf("%s:\n",name);

	int i = 0, count = 0;
	for(i=0; i<size; i++)
	{
        count++;
		printf("%02x,\t", braid[i]);
        if(count == 8)
        {
            printf("\n");
            count = 0;
        }
	}	
	printf("\n");
}

void unpack_and_print_matrix(uint8_t *matrix,  char *name)
{
	int i,j, count = 0;
	printf("%s\n", name);

	for(i=0; i < 3; i++)
	{
		printf("%02x\t", matrix[i]);
	}
	printf("\n");

	for(i=0; i<8; i++) {
		count++;
		printf("%02x\t", extract_elem(&matrix[3], i * 5, 5));
	}

	printf("\n");

	for(i=0; i<WALNUT_BRAID; i++) {
	        for(j=0; j<WALNUT_BRAID; j++) {
	        	printf("%02x\t", extract_elem(&matrix[8],
	        	                5 * (j + (i * WALNUT_BRAID)), 5));
	        }
	        printf("\n");
	}

	printf("\n");
}