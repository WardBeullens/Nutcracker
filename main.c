#include "main.h"

/*
	Produce P(b) for a random braid b of length n.
*/
void findTarget(uint8_t target[WALNUT_BRAID][WALNUT_BRAID], uint8_t perm[WALNUT_BRAID], uint8_t *braid ,int n,uint8_t *Tvalues){
	do {
        /* 4.6(1): Generate a random braid of length n */
        generateRandomBraid(braid, WALNUT_VALUE_l, n);

        /* Get braid permutation */
        get_braid_permutation(braid, perm);

    /* 4.6(2): This braid must not be a purebraid, so regenerate if the permutation is trivial (i.e. identity) */
    } while(compare_identitiy_permutation(perm, WALNUT_BRAID));

    setIdentityMatrix(target);
    setIdentityPermutation(perm);

    walnut_emul(target,perm,braid,Tvalues);
}

/*
	Demonstrates reversing E-multiplication
*/
void solveREMDemo(){
	int result;
	uint8_t secretKey[BRAID_LEN], forgedKey[BRAID_LEN];
	uint8_t publicKey[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t Tvalues[WALNUT_BRAID];
	uint8_t pkPerm[WALNUT_BRAID];

	// generate Tvalues and produce a target secret key
	generate_tvalues(Tvalues);
	findTarget(publicKey,pkPerm,secretKey,WALNUT_BRAID,Tvalues);

	printMatrix(publicKey);

	// reverse E-multiplication
	result = SolveREM(publicKey,pkPerm,Tvalues,forgedKey,WALNUT_BRAID);

	// print result
	if(result){
		printf("Forgery success! \n");
	}
	else{
		printf("Forgery fail. \n");
	}

	uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];

	// print P(secret braid)
	setIdentityMatrix(matrix);
	setIdentityPermutation(permutation);
	walnut_emul(matrix,permutation,secretKey,Tvalues);
	printf("public key: \n");
	printMatrix(matrix);

	// print P(forged braid)
	setIdentityMatrix(matrix);
	setIdentityPermutation(permutation);
	walnut_emul(matrix,permutation,forgedKey,Tvalues);
	printf("P(forgery): \n");
	printMatrix(matrix);

	// print length of the secret braid and the forged braid
	printf("The secretKey is %d generators long \n", GET_NUM_BRAID_GENERATORS(secretKey));
	printf("The forged key is %d generators long \n", GET_NUM_BRAID_GENERATORS(forgedKey));

	dehornoy_reduction(forgedKey);
	dehornoy_reduction(secretKey);

	printf("After Dehornoy reduction, the secret key is %d generators long \n", GET_NUM_BRAID_GENERATORS(secretKey));
	printf("After Dehornoy reduction, the forged key is %d generators long \n", GET_NUM_BRAID_GENERATORS(forgedKey));
}

#define MESSAGE_LEN 50

/*
	Takes a key pair, produces a signature for a random message, and verifies the signature.

	If cloacking == 0, the signing algorithm does not include cloaking elements in the signature. 
*/
void signRandomMessage(uint8_t *secretKey, uint8_t *publicKey, int cloaking){
	int i,result;
	unsigned char message[MESSAGE_LEN];
	long long unsigned int message_len;
	unsigned char *returnedMessage;
	uint8_t signature[BRAID_LEN];
	long long signature_len;

	// Choose random message
	for(i=0; i<MESSAGE_LEN ; i++){
		message[i] = rand();
	}

	// Sign message
	if(cloaking == 0){
		signature_generation_no_cloaking(signature, &signature_len, message , MESSAGE_LEN  , secretKey);
	}
	else {
		signature_generation(signature, &signature_len, message , MESSAGE_LEN  , secretKey);
	}	

	// report the length of the signature
	printf("Signature is %d generators long. \n", GET_NUM_BRAID_GENERATORS(signature));

	// Verify message
	result = signature_verification(publicKey, signature , &signature_len , &returnedMessage , &message_len);

	if(result){
		printf("Signature is valid\n");
	}
	else {
		printf("Signature is NOT valid !!!\n");
	}
}

/*
	Generates a key pair, and signs a random message with it.
*/
void walnutDemo(int cloaking){

	uint8_t secretKey[BRAID_LEN];
	uint8_t publicKey[BRAID_LEN];

	// Generate keys
	key_generation(secretKey,publicKey);

	// Sign a random message
	signRandomMessage(secretKey,publicKey,cloaking);	
}

/*
Generates a public key and a single signature.
*/
void AttackSetup(uint8_t *publicKey , uint8_t *signature , long long *signature_len){
	int i;

	uint8_t secretKey[BRAID_LEN];

	unsigned char message[MESSAGE_LEN];

	// Generate keys
	key_generation(secretKey,publicKey);

	// Choose random message
	for(i=0; i<MESSAGE_LEN ; i++){
		message[i] = rand();
	}

	// Sign message
	signature_generation(signature, signature_len, message , MESSAGE_LEN  , secretKey);
}

/*
Given a public key and a single signature for any message, extract 
-PM1: the public matrix of the first secret braid
-PM2: the public matrix of the second secret braid
-PP2: the public permutation of the first secret braid
-PP2: the public permutation of the second secret braid (This requires the signature, because this is not included in the public key)
*/
void extractMatricesAndPermutations(uint8_t PM1[WALNUT_BRAID][WALNUT_BRAID],uint8_t PM2[WALNUT_BRAID][WALNUT_BRAID],uint8_t PP1[WALNUT_BRAID],uint8_t PP2[WALNUT_BRAID], uint8_t *publicKey, uint8_t *signature , uint8_t * Tvalues){
	int i,j;
	uint8_t dummyMatrix[WALNUT_BRAID][WALNUT_BRAID];
	setIdentityMatrix(dummyMatrix);

	/* Extract the matrix and the permutation of Pub(S) from the public key */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Skip the last row of the matrix */
        for(j=0; j<WALNUT_BRAID && i!=WALNUT_BRAID-1; j++) {

            /* Starting at the position of the first matrix element, extract each element of width WALNUT_MATRIX_ELEMENT_BITS */
            PM1[i][j] = extract_elem(&publicKey[WALNUT_PUBKEY_S_MATRIX_POSITION],
                WALNUT_MATRIX_ELEMENT_BITS * (j + (i * WALNUT_BRAID)), WALNUT_MATRIX_ELEMENT_BITS);
        }

        /* Starting at the position of the first permutation element, extract each element of width WALNUT_PERMUTATION_ELEMENT_BITS */
        PP1[i] = extract_elem(&publicKey[WALNUT_PUBKEY_S_PERMUTATION_POSITION],
            i * WALNUT_PERMUTATION_ELEMENT_BITS, WALNUT_PERMUTATION_ELEMENT_BITS);
    }

    /* Initialize the last row of the matrix as all zeros */
    memset(PM1[WALNUT_BRAID-1], 0, WALNUT_BRAID);

    /* Set the last element of the matrix to the last element from the public key matrix */
    PM1[WALNUT_BRAID-1][WALNUT_BRAID-1] = extract_elem(&publicKey[WALNUT_PUBKEY_S_MATRIX_POSITION],
        WALNUT_MATRIX_ELEMENT_BITS * ((WALNUT_BRAID - 1) * WALNUT_BRAID), WALNUT_MATRIX_ELEMENT_BITS);


    /* Extract the matrix of Pub(S') from the public key */
    for(i=0; i<WALNUT_BRAID; i++) {

        /* Skip the last row of the matrix */
        for(j=0; j<WALNUT_BRAID && i!=WALNUT_BRAID-1; j++) {

            /* Starting at the position of the first matrix element, extract each element of width WALNUT_MATRIX_ELEMENT_BITS */
            PM2[i][j] = extract_elem(&publicKey[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION],
                WALNUT_MATRIX_ELEMENT_BITS * (j + (i * WALNUT_BRAID)), WALNUT_MATRIX_ELEMENT_BITS);
        }
    }

     /* Initialize the last row of the matrix as all zeros */
    memset(PM2[WALNUT_BRAID-1], 0, WALNUT_BRAID);

    /* Set the last element of the matrix to the last element from the public key matrix */
    PM2[WALNUT_BRAID-1][WALNUT_BRAID-1] = extract_elem(&publicKey[WALNUT_PUBKEY_S_PRIME_MATRIX_POSITION],
        WALNUT_MATRIX_ELEMENT_BITS * ((WALNUT_BRAID - 1) * WALNUT_BRAID), WALNUT_MATRIX_ELEMENT_BITS);

    // Permutation of S' is equal to permutation of S composed with the permutation of the signature 
    memcpy(PP2,PP1,sizeof(uint8_t[WALNUT_BRAID]));
    walnut_emul(dummyMatrix,PP2,signature,Tvalues);
}

/*
	Demonstrates a key recovery attack against the WALNUT signature scheme
*/
void Attack(){
	uint8_t Tvalues[WALNUT_BRAID];
	uint8_t PM1[WALNUT_BRAID][WALNUT_BRAID], PM2[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t PP1[WALNUT_BRAID],PP2[WALNUT_BRAID];
	uint8_t publicKey[BRAID_LEN];
	uint8_t forgedKey[BRAID_LEN];
	uint8_t signature[BRAID_LEN];
	uint8_t s1[BRAID_LEN];
	uint8_t s2[BRAID_LEN];
	long long signature_len;

	// Receieve a public key and a single valid signature.
	AttackSetup(publicKey,signature,&signature_len);

	// Read the T-values, P(s_1) and P(s_2) from the public key and the signature
	extractTvalues(Tvalues,publicKey);
	extractMatricesAndPermutations(PM1,PM2,PP1,PP2,publicKey,signature,Tvalues);

	// Solve the REM problem twice to obtain s_1' and s_2'    
	SolveREM(PM1,PP1,Tvalues,s1,WALNUT_BRAID);
	SolveREM(PM2,PP2,Tvalues,s2,WALNUT_BRAID);

	braid_free_reduction(s1);
	braid_free_reduction(s2);

	printf("length of s_1': %d\n", GET_NUM_BRAID_GENERATORS(s1));
	printf("length of s_2': %d\n", GET_NUM_BRAID_GENERATORS(s2));

	// convert s1 and s2 into an equivalent secret key
	memcpy(forgedKey,s1,GET_NUM_BRAID_BYTES(s1));
	memcpy(&forgedKey[GET_NUM_BRAID_BYTES(forgedKey)],s2,GET_NUM_BRAID_BYTES(s2));

	printf("Make 5 forged signatures\n");
	signRandomMessage(forgedKey,publicKey,0);
	signRandomMessage(forgedKey,publicKey,0);
	signRandomMessage(forgedKey,publicKey,0);
	signRandomMessage(forgedKey,publicKey,0);
	signRandomMessage(forgedKey,publicKey,0);
}

/*
	Demonstrates a forgery attack against the WALNUT signature scheme
*/
void ForgeryAttack(){
	int i;
	uint8_t Tvalues[WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];
	uint8_t PM1[WALNUT_BRAID][WALNUT_BRAID], PM2[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t PP1[WALNUT_BRAID],PP2[WALNUT_BRAID];
	uint8_t publicKey[BRAID_LEN];
	uint8_t signature[BRAID_LEN];
	long long signature_len;
	unsigned char message[MESSAGE_LEN];

	// Receieve a public key and a single valid signature.
	AttackSetup(publicKey,signature,&signature_len);

	// Read the T-values, P(s_1) and P(s_2) from the public key and the signature
	extractTvalues(Tvalues,publicKey);
	extractMatricesAndPermutations(PM1,PM2,PP1,PP2,publicKey,signature,Tvalues);

	// find a braid "impurePart" that maps P(s_1) to a matrix-permutation pair (PM1,PP1), with PP1 = the identity permutation
	uint8_t impurePart[BRAID_LEN];
	makePure(PM1,PP1,Tvalues,impurePart);

	// Choose random message to forge a signature for
	for(i=0; i<MESSAGE_LEN ; i++){
		message[i] = rand();
	}

	uint8_t PM1inv[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t hashMat[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t prod[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t targetMat[WALNUT_BRAID][WALNUT_BRAID];
	unsigned char returnedMessage[100];
	long long message_len;

	/* Hash and encode the message */
    uint8_t hash[WALNUT_HASH_SIZE];
    uint8_t encoded_message[BRAID_LEN];
    #if WALNUT_SECURITY_LEVEL == 128
    	SHA256(message, MESSAGE_LEN , hash);
    #else
    	SHA512(message, MESSAGE_LEN , hash);
    #endif
    walnut_message_encoder(hash, encoded_message);

    // compute hashMat, the matrix part of P(E(message)).
    setIdentityMatrix(hashMat);
    setIdentityPermutation(permutation);
    walnut_emul(hashMat,permutation,encoded_message,Tvalues);

    // Compute targetMat = PM1^-1 * hashMat * PM2, the target of the REM solver
	invertMatrix(PM1,PM1inv);
    walnut_mmul(prod,hashMat,PM2);
    walnut_mmul(targetMat,PM1inv,prod);

    // Compute the remaining part of the signature braid with REM solver
    uint8_t purePart[BRAID_LEN];
    uint8_t forgedSignature[BRAID_LEN];
    SolveREM(targetMat,PP2,Tvalues,purePart,WALNUT_BRAID);
    concat_braid(impurePart,purePart,forgedSignature);

    // Complete the signature by appending the message
    for(i=0 ; i<MESSAGE_LEN ; i++){
    	forgedSignature[GET_NUM_BRAID_BYTES(forgedSignature)+i] = message[i];
    }

    // Verify the signature
	int result;
	long long inLen = GET_NUM_BRAID_BYTES(forgedSignature)+MESSAGE_LEN;
	result = signature_verification(publicKey, forgedSignature , &inLen , (unsigned char **) &returnedMessage , &message_len);

	printf("signature is %d Artin generators long \n\n", GET_NUM_BRAID_GENERATORS(forgedSignature));
	printf("Verifying signature in ...\n");
	sleep(2);
	printf("3\n");
	sleep(1);
	printf("2\n");
	sleep(1);
	printf("1\n");
	sleep(1);

	if(result){
		printf("Signature is valid\n");
	}
	else {
		printf("Signature is NOT valid !!!\n");
	}
}


/* 
	Prints the current time
*/
void printTime(){
	time_t rawtime;
	struct tm * timeinfo;

	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "Current local time and date: %s", asctime (timeinfo) );
}

int main()
{
	srand(1);
	printTime();

	// Demonstrates Walnut
	//walnutDemo(1);

	// Doing a collision search to find two messages that have the same signatures.
	//collisionAttack();

	// Demonstrates solving a REM instance 
	//solveREMDemo();

	// A key recovery attack by solving two REM instances
	//Attack();

	// A universal signature forgery by solving one REM instance
	ForgeryAttack();

	printTime();
	printf("\nDone!\n");

	return 0;
}
