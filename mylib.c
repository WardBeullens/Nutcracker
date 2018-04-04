#include "mylib.h"

/*
    Make one of the pure braid generators (or its inverse)
*/
void getPureBraidGenerator(uint8_t i, uint8_t j, uint8_t inverse, uint8_t *pb){
        /* Loop counter */
    uint8_t k;

    /* Generator */
    uint8_t generator;

    /* Number of pure braid generators */
    uint16_t num_generators = 0;

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
    generator |= ((inverse & 1) << B8_STRAND_BITS);

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
    pb[0] = 0;
    pb[1] = num_generators;
}

/*
    Appends the (i,n)-th pure braid generator to the braid b

    If i == 0, we dont append anything,

    If i >= n , we append the inverse of the ((i-n),n)-th pure braid generator
*/
void appendPureBraidGenerator(uint8_t *b, int i, int n){
	int inverse=0;
	uint8_t pbg[20];
	uint8_t copy[BRAID_LEN];

	if(i>=n){
		inverse = 1;
		i -= n;
	}
	if(i==0){
		return;
	}
	i--;
	getPureBraidGenerator(i,n-1,inverse,pbg);
	memcpy(copy,b,2+(GET_NUM_BRAID_GENERATORS(b)+1)/2);
	concat_braid(copy,pbg,b);
}

/*
    Sets a matrix to the identity matrix
*/
void setIdentityMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]){
	int i;
	for(i=0; i<WALNUT_BRAID; i++) {
        /* Set row i of the matrix to be that of the identity matrix */
        memset(matrix[i], 0, WALNUT_BRAID);
        matrix[i][i] = 1;
    }
}

/*
    checks if a matrix is the identity matrix
*/
int isIdentityMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]){
    int i,j;
    for(i=0; i<WALNUT_BRAID; i++) {
        for(j=0 ; j<WALNUT_BRAID; j++){
            if(matrix[i][j] != (i==j)){
                return 0;
            }
        }
    }
    return 1;
}

/* 
    Sets a permutation to the identity permutation
*/
void setIdentityPermutation(uint8_t permutation[WALNUT_BRAID]){
	int i;
	for(i=0; i<WALNUT_BRAID; i++) {
        permutation[i] = i;
    }
}

/*
    Prints a matrix
*/
void printMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]){
	int i,j;
	for(i=0; i<WALNUT_BRAID; i++){
		for(j=0; j<WALNUT_BRAID; j++){
			printf("%3d ", matrix[i][j]);
		}
		printf("\n");
	}
	printf("\n");
}

/* 
    Prints a set of T-values
*/
void printTvalues(uint8_t tvals[WALNUT_BRAID]){
	int i;
	for(i=0; i<WALNUT_BRAID ; i++){
		printf("%2d ", tvals[i]);
	}
	printf("\n");
}

void swapRows(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t row1, uint8_t row2){
	int i;
	uint8_t temp;
	for (i = 0; i < WALNUT_BRAID; i++)
	{
		temp = matrix[row1][i];
		matrix[row1][i] = matrix[row2][i];
		matrix[row2][i] = temp;
	}
}

void multiplyRow(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], int row, uint8_t scalar){
	uint8_t i;
	for(i=0 ; i<WALNUT_BRAID ; i++){
		matrix[row][i] = GMUL(matrix[row][i],scalar);
	}
}

void rowOp(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t rowFrom, uint8_t rowTo, uint8_t scalar){
	uint8_t i;
	for(i=0 ; i<WALNUT_BRAID ; i++){
		matrix[rowTo][i] ^= GMUL(matrix[rowFrom][i],scalar);
	}
}

/* 
    Makes a copy of a matrix, and puts the first rows in row reduced echelon form.
*/
void echelonForm(uint8_t matrixIn[WALNUT_BRAID][WALNUT_BRAID], uint8_t matrixOut[WALNUT_BRAID][WALNUT_BRAID], uint8_t rows){
	int i,j,r,col,row;
	col = 0;

	for(i=0; i<WALNUT_BRAID; i++){
		for(j=0; j<WALNUT_BRAID; j++){
			matrixOut[i][j] = matrixIn[i][j];
		}
	}

	for(row=0; row<rows ; row++){
		if(col >= WALNUT_BRAID){
			return;
		}

		r = row;
		while(matrixOut[r][col]==0){
			r++;
			if (r == rows){
				r = row;
				col ++;
				if(col == WALNUT_BRAID){
					return;
				}
			}
		}

		if(r != row){
			swapRows(matrixOut,r,row);
		}

		multiplyRow(matrixOut,row,MINV(matrixOut[row][col]));

		for(i=0 ; i<rows ; i++){
			if(i != row){
				rowOp(matrixOut,row,i,matrixOut[i][col]);
			}
		}

		col++;
	}
}

/* 
    Inverts a matrix 
*/
void invertMatrix(uint8_t matrixIn[WALNUT_BRAID][WALNUT_BRAID], uint8_t matrixOut[WALNUT_BRAID][WALNUT_BRAID]){
    int i,r,col,row;
    col = 0;

    uint8_t copy[WALNUT_BRAID][WALNUT_BRAID];

    copyMatrix(matrixIn,copy);

    setIdentityMatrix(matrixOut);

    for(row=0; row<WALNUT_BRAID ; row++){
        if(col >= WALNUT_BRAID){
            return;
        }

        r = row;
        while(copy[r][col]==0){
            r++;
            if (r == WALNUT_BRAID){
                r = row;
                col ++;
                if(col == WALNUT_BRAID){
                    return;
                }
            }
        }

        if(r != row){
            swapRows(copy,r,row);
            swapRows(matrixOut,r,row);
        }

        multiplyRow(matrixOut,row,MINV(copy[row][col]));
        multiplyRow(copy,row,MINV(copy[row][col]));

        for(i=0 ; i<WALNUT_BRAID ; i++){
            if(i != row){
                rowOp(matrixOut,row,i,copy[i][col]);
                rowOp(copy,row,i,copy[i][col]);
            }
        }

        col++;
    }
}

/*
    Prints a permutation
*/
void printPermutation(uint8_t permutation[WALNUT_BRAID]){
	int i;
	for(i=0; i<WALNUT_BRAID ; i++){
    	printf("%d ", permutation[i]);
    }
    printf("\n");
}

/*
    Extract the T-values from a public key
*/
void extractTvalues(uint8_t *Tvalues , uint8_t *publicKey){
	int i;
	for(i=0; i<WALNUT_NUM_TVALUES; i++) {
        /* Starting at the position of the first T-value, extract each T-value of width WALNUT_TVALUE_BITS */
        Tvalues[i] = extract_elem(&publicKey[WALNUT_PUBKEY_TVALUES_POSITION], i * WALNUT_TVALUE_BITS, WALNUT_TVALUE_BITS);
    }
}

/*
    Generates a random braid word of certain length that only involves the first n strands
*/
int generateRandomBraid(void *b, size_t length, int n)
{
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
        generator = rand()%(n - 1);

        /* 9.2: Choose a random power, ǫ = {−1, 1} */
        /* Note that the xor 1 operation is not necessary; it just flips the randomly generated power.
           This is done to match the method in which the optimized implementation generates random powers. */
        generator |= ((rand()%(2) ^ 1) << B8_STRAND_BITS);

        /* 9.3: Append (b_ǫ)^i to the braid word */
        SET_BRAID_GENERATOR(braid, generator, i);
    }
    return 1;
}

/* 
    Copies the contents of one matrix to a different matrix
*/
void copyMatrix(uint8_t from[WALNUT_BRAID][WALNUT_BRAID], uint8_t to[WALNUT_BRAID][WALNUT_BRAID]){
	int i,j;
	for(i=0; i<WALNUT_BRAID ; i++){
		for(j=0; j<WALNUT_BRAID ; j++){
			to[i][j] = from[i][j];
		}
	}
}

/*
    Computes a vector x matrix procuct and stores it in result
*/
void vmmul(uint8_t vector[WALNUT_BRAID], uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID] , uint8_t result[WALNUT_BRAID]){
	int i,j;
	memset(result,0,WALNUT_BRAID*sizeof(uint8_t));

	for(i=0; i<WALNUT_BRAID; i++){
		for(j=0; j<WALNUT_BRAID; j++){
			result[j] ^= GMUL(vector[i],matrix[i][j]);
		}
	}
}

/*
    Computes a vector x matrix product and stores it in result

    The matrix is represented by a N by 32 by N array. The (i,alpha,j)-th element of the array is the (i,j)-th element of the matrix times the finite field element alpha.
    With this array we can rapidly compute the vector x matrix product, without doing any multiplications in the finite field.
*/
void vmmulX(uint8_t vector[WALNUT_BRAID], uint8_t matrixRows[WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID] , uint8_t result[WALNUT_BRAID]){
	int i;
	memset(result,0,WALNUT_BRAID*sizeof(uint8_t));

	for(i=0; i<WALNUT_BRAID; i++){
		*((uint64_t *) result) ^= *((uint64_t *) matrixRows[i][vector[i]]);
	}
}

/*
    Computes a matrix x matrix procuct and stores it in result

    The second matrix is represented by a N by 32 by N array. The (i,alpha,j)-th element of the array is the (i,j)-th element of the matrix times the finite field element alpha.
    With this array we can rapidly compute the vector x matrix product, without doing any multiplications in the finite field.
*/
void mmulX(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t matrixRows[WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID] , uint8_t result[WALNUT_BRAID][WALNUT_BRAID]){
    int i,j;
    memset(result,0,WALNUT_BRAID*WALNUT_BRAID*sizeof(uint8_t));

    for(i=0; i<WALNUT_BRAID; i++){
        for(j=0; j<WALNUT_BRAID; j++){
            *((uint64_t *) result[i]) ^= *((uint64_t *) matrixRows[j][matrix[i][j]]);
        }
    }
}

/*
    Transposes the matrix in place
*/
void transpose(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]){
	int i,j;
	uint8_t temp;
	for (i = 0; i < WALNUT_BRAID; i++)
	{
		for(j = i+1; j<WALNUT_BRAID; j++){
			temp = matrix[i][j];
			matrix[i][j] = matrix[j][i];
			matrix[j][i] = temp;
		}
	}
}

/*
    Creates a signature without using any cloacking elements. This is used by the forger to produce shorter signatures.
*/
int signature_generation_no_cloaking(void *signature, void *sig_length, const void *message, size_t length, const void *privkey)
{
    /* Track success */
    uint8_t success = 1;

    /* Buffer to store hash */
    uint8_t hash[WALNUT_HASH_SIZE];

    /* Buffer to store encoded message */
    uint8_t encoded_message[(WALNUT_HASH_SIZE * B8_MAX_PURE_BRAID_LENGTH) + 2];

    /* Buffer to store signature. Because signature rewriting may temporarily produce a large braid,
       ensure that the buffer is large enough to hold all of its data. */
    uint8_t sig_buffer[B8_MAX_BRAID_LENGTH];

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

    printf("Before BKL: %d \n",GET_NUM_BRAID_GENERATORS(sig_buffer));

    /* 5.3.1: Rewrite the signature as per BKL Normal Form */
//	success &= bkl_normal_form(sig_buffer);

    printf("After BKL: %d \n",GET_NUM_BRAID_GENERATORS(sig_buffer));

    success &= braid_free_reduction(sig_buffer);

    printf("Before Dehornoy: %d \n",GET_NUM_BRAID_GENERATORS(sig_buffer));

    /* 5.3.3: Rewrite the signature as per Dehornoy Reduction */
//    success &= dehornoy_reduction(sig_buffer);

    printf("After Dehornoy: %d \n",GET_NUM_BRAID_GENERATORS(sig_buffer));


    /* 5.3: A braid rewritten as per 5.3 */

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

/*
    Given a matrix, this function computes all scalar multiples of all the rows of this matrix
*/
void precomputeMatrixRows(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t rows[WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID]){
    int i,j,k;
    for(i=0; i<WALNUT_BRAID; i++){
        for(j=0 ; j<WALNUT_FIELD; j++){
            for(k=0; k<WALNUT_BRAID; k++){
                rows[i][j][k] = GMUL(j,matrix[i][k]);
            }
        }
    }
}