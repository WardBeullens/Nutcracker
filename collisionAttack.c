#include "collisionAttack.h"

/* 
    Takes a hash digest, and converts it into a "plausible" message.
*/
void writeMessage(unsigned char *input, unsigned char *message){
	unsigned long long entropy = *((unsigned long long *)input);

	if(((int)input[31])&1){
		sprintf(message,"I would like to receive %llu free samples of delicious cookies.", entropy );
	}
	else{
		sprintf(message,"I pledge to donate %llu USD to Ward Beullens.", entropy );
	}
}

/*
    The function that we will do a collision search on.

    This function takes a hash diget as input and
    1) converts it into a plausible message,
    2) encodes this message into a braid with the Walnut encoding mechanism,
    3) calculates an E-multiplication with this braid and
    4) hashes the resulting matrix.
*/
void collisionAttackFunction(unsigned char *input, void* context){
	int i; 
	collisionAttackContext *ctx = context;
	uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t matrix2[WALNUT_BRAID][WALNUT_BRAID];
	unsigned char message[200];

    // Convert hash into a plausible message
	writeMessage(input,message);

    // compute emultiplication of encoding  of the message
	uint8_t hash[WALNUT_HASH_SIZE];
	#if WALNUT_SECURITY_LEVEL == 128
    	SHA256(message, strlen(message) , hash);
    #else
    	SHA512(message, strlen(message) , hash);
    #endif

    setIdentityMatrix(matrix);

    for(i=0 ; i<WALNUT_HASH_SIZE ; i+=2 ){
    	mmulX(matrix,  ctx->matrixRows[hash[i]],matrix2);
    	mmulX(matrix2, ctx->matrixRows[hash[i+1]],matrix);
    }

    // Hash the result
    SHA256((unsigned char *) matrix,WALNUT_BRAID*WALNUT_BRAID,input);
}

/*
    This function does a precomputation that is used to speed up the collisionAttackFunction

    For each byte, this function precomputes the E-multiplication of the encoding of this byte, and stores all the scalar multiples of the rows of this matrix.
*/
void fillMatrices(collisionAttackContext *ctx){
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
    int i;
    uint8_t braid[1000];
    uint8_t permutation[WALNUT_BRAID];
    setIdentityPermutation(permutation);

    for(i=0 ; i<256 ; i++){
    	braid[0] = 0;
    	braid[1] = 0;
		concat_braid(braid, pure_braid_generators[i>>4], braid);
		concat_braid(braid, pure_braid_generators[i&15], braid);

		setIdentityMatrix(ctx->matrices[i]);
		walnut_emul(ctx->matrices[i],permutation,braid,ctx->Tvalues);

		precomputeMatrixRows(ctx->matrices[i],ctx->matrixRows[i]);
    }
}

/* 
    This demonstrates the collision finding attack of section 4.
*/
void collisionAttack(){
	uint8_t publicKey[BRAID_LEN];
	uint8_t signature[BRAID_LEN];
	long long signature_len;

	// Receieve a public key and a single valid signature.
    // (the signature is not used by this attack)
	AttackSetup(publicKey,signature,&signature_len);

	collisionAttackContext ctx;
	// Read the T-values, P(s_1) and P(s_2) from the public key and the signature
    // (P(s_1) and P(s_2) are not used by this attack)
	extractTvalues(ctx.Tvalues,publicKey);

    // Do some precomputation
	fillMatrices(&ctx);


    // Initialize the search object
	collisionSearch search;
	initSearch(&search,collisionAttackFunction,&ctx,50000,20);

	unsigned char hash1[32],hash2[32];

    // Continue searching until a 'good' collision is found. (i.e. a collision between a free cookie message and a payment message.)
	while(1){
		long iterations = findCollisionMT(&search,hash1,hash2,4);
        if(iterations == 0){
            printf("collision attack failed \n");
            break;
        }

		printf("iterations: %ld \n",iterations);
        // reconstruct the colliding messages and print them.
		unsigned char message1[200],message2[200];
		writeMessage(hash1,message1);
		writeMessage(hash2,message2);
		printf("message1 :\"%s\" \n", message1);
		printf("message2 :\"%s\" \n", message2);

        // Check if the collision was 'good'
		if( ((int)hash1[31]&1) != ((int)hash2[31]&1)){
			break;
		}
	}
    endSearch(&search);
}