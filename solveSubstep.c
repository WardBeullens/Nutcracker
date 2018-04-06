
#include "solveSubstep.h"

#define GENERATORS_OF_SUBGROUP 70
#define SEARCH_LEN_A 12
#define SEARCH_LEN_B 30
#define SUBGROUP_CHAINS 50000
#define GEN_BRAID_LEN BRAID_LEN/20

typedef struct SearchAcontext{
	uint8_t matrixRows[2*GENERATORS_OF_SUBGROUP][WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID];
	uint8_t targetvec[WALNUT_BRAID];
	uint8_t targetcovec[WALNUT_BRAID];
	uint8_t n;
} SearchAcontext;

/*
	Given a hash, derive an s in B_N from this,
	compute a representation of the coset  
	A_{n-1} (1,e)  * s  or
	A_{n-1} Target * s
	And hash this result to get the next hash.

	This function is constructed such that from a collision in this function we can (sometimes) find a braid s
	such that Target * s is in A_{n-1}.
*/
void nextHashA(unsigned char *hash, void *context){
	SearchAcontext *ctx = context;
	int i,gens;
	uint8_t vector1[WALNUT_BRAID];
	uint8_t vector2[WALNUT_BRAID];
	uint8_t buffer[WALNUT_BRAID];
	int n = ctx->n;

	// decide whether we are in the A_{n-1} (1,e)  * s  case or not
	if((hash[31]&1)==1){
		memcpy(vector2,ctx->targetvec,WALNUT_BRAID);
	}
	else {
		memset(vector2,0,WALNUT_BRAID);
		vector2[n-2]=1;
	}

    // Act on the coset representation (vector,covector) with NUMBER_OF_GENS random pure braid generators.
	for(gens =0 ; gens < SEARCH_LEN_A/2 ; gens++){
		vmmulX(vector2,ctx->matrixRows[hash[gens]%(2*GENERATORS_OF_SUBGROUP)],vector1);
	    vmmulX(vector1,ctx->matrixRows[(hash[gens]>>4)%(2*GENERATORS_OF_SUBGROUP)],vector2);
	}

	// Move the vector into a buffer.
	for(i = 0; i<WALNUT_BRAID ; i++){
		buffer[i] = vector2[i];
	}

	// Hash the buffer
	SHA256(buffer,WALNUT_BRAID,hash); 
}

/*
	Given a hash, derive an s in B_N from this,
	compute a representation of the coset  
	A_{n-1} (1,e)  * s  or
	A_{n-1} Target * s
	And hash this result to get the next hash.

	This function is constructed such that from a collision in this function we can (sometimes) find a braid s
	such that Target * s is in A_{n-1}.
*/
void nextHashB(unsigned char *hash, void *context){
	REMcontext *ctx = context;
	int i,gens;
	uint8_t covector1[WALNUT_BRAID];
	uint8_t covector2[WALNUT_BRAID];
	uint8_t buffer[WALNUT_BRAID];
	int n = ctx->n;

	// decide whether we are in the A_{n-1} (1,e)  * s  case or not
	if((hash[31]&1)==1){
		memcpy(covector2,&ctx->targetcovec[0],WALNUT_BRAID);
	}
	else {
		memset(covector2,0,WALNUT_BRAID);
		covector2[n-1]=1;
	}

    // Act on the coset representation (vector,covector) with NUMBER_OF_GENS random pure braid generators.
	for(gens =0 ; gens < SEARCH_LEN_B/2 ; gens++){
	    vmmulX(covector2,ctx->matrixCols[hash[gens]%(2*n)],covector1);
		vmmulX(covector1,ctx->matrixCols[(hash[gens]>>4)%(2*n)],covector2);
	}

	// Move the vector and covector into a buffer. Append with zeros
	for(i = 0; i<WALNUT_BRAID ; i++){
		buffer[i] = covector2[i];
	}

	// Hash the buffer
	SHA256(buffer,WALNUT_BRAID,hash); 
}

/*void findChainA(unsigned char *start, unsigned char *end, long *len, SearchAcontext *ctx){
	int i;
	uint32_t num = 1;
	*len = 1;
	int n = ctx->n;

	// Determine the number of bits that has to be zero to be a distinguished point
	#if WALNUT_SECURITY_LEVEL == 128
		int bits = (3*n)-16;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 10;
		}
	#else
		int bits = (4*n)-16;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 13;
		}
	#endif

	uint32_t mask = (1<<bits)-1;

	// Determine the maximal length of a chain.
	uint32_t limit = 20*(1<<bits);

	// Pick a random starting point
	for (i = 0; i < 32; i++)
	{
		start[i] = rand();
		end[i] = start[i];
	}

	// Iterate until we have a distinguished point
	while(num){
		nextHashA(end,ctx);
		num = ((uint32_t)end[0])+(((uint32_t)end[1])<<8)+(((uint32_t)end[2])<<16);
		num &= mask;
		(*len)++;

		// If the length limit is reached we are probably stuck in a loop, so we abort and try again.
		if(*len > limit){
			printf("chain is too long \n");
			findChainA(start,end,len,ctx);
			return;
		}
	}
}*/

/*
	Given two good hash values that produce the same output when given to nextHash function, this function produces a braid that solves one of the steps of the REM problem.
*/
void extractBraidB(uint8_t *hash1,uint8_t *hash2, uint8_t *braid, int n){
	uint8_t tempBraid1[BRAID_LEN];
	uint8_t tempBraid2[BRAID_LEN];
	int i;

	tempBraid1[0] = 0;
	tempBraid1[1] = 0;
	tempBraid2[0] = 0;
	tempBraid2[1] = 0;

	braid[0] = 0;
	braid[1] = 0;

	for (i=0 ; i<SEARCH_LEN_B/2 ; i++){
		appendPureBraidGenerator(tempBraid1,hash1[i]%(2*n),n);
		appendPureBraidGenerator(tempBraid1,(hash1[i]>>4)%(2*n),n);

		appendPureBraidGenerator(braid,hash2[i]%(2*n),n);
		appendPureBraidGenerator(braid,(hash2[i]>>4)%(2*n),n);
	}

	invert_braid(braid,tempBraid2);
	concat_braid(tempBraid1,tempBraid2,braid);
	braid_free_reduction(braid);
}

void appendGenerator(uint8_t *braid, int i, uint8_t gens[GENERATORS_OF_SUBGROUP][GEN_BRAID_LEN]){
	int invert = 0;
	if(i>=GENERATORS_OF_SUBGROUP){
		invert = 1;
		i -= GENERATORS_OF_SUBGROUP;
	}

	uint8_t temp1[BRAID_LEN];
	uint8_t temp2[GEN_BRAID_LEN];
	memcpy(temp1,braid,BRAID_LEN);
	if(invert){
		invert_braid(gens[i],temp2);
	}
	else {
		memcpy(temp2,gens[i],GEN_BRAID_LEN);
	}

	concat_braid(temp1,temp2,braid);
}

/*
	Given two good hash values that produce the same output when given to nextHash function, this function produces a braid that solves one of the steps of the REM problem.
*/
void extractBraidA(uint8_t *hash1,uint8_t *hash2, uint8_t *braid, uint8_t gens[GENERATORS_OF_SUBGROUP][GEN_BRAID_LEN]){
	uint8_t tempBraid1[BRAID_LEN];
	uint8_t tempBraid2[BRAID_LEN];
	int i;

	tempBraid1[0] = 0;
	tempBraid1[1] = 0;
	tempBraid2[0] = 0;
	tempBraid2[1] = 0;
	braid[0] = 0;
	braid[1] = 0;

	for (i=0 ; i<SEARCH_LEN_A/2 ; i++){
		appendGenerator(tempBraid1,hash1[i]%(2*GENERATORS_OF_SUBGROUP),gens);
		appendGenerator(tempBraid1,(hash1[i]>>4)%(2*GENERATORS_OF_SUBGROUP),gens);

		appendGenerator(braid,hash2[i]%(2*GENERATORS_OF_SUBGROUP),gens);
		appendGenerator(braid,(hash2[i]>>4)%(2*GENERATORS_OF_SUBGROUP),gens);
	}

	invert_braid(braid,tempBraid2);
	concat_braid(tempBraid1,tempBraid2,braid);
	braid_free_reduction(braid);
	printf("len = %d \n", GET_NUM_BRAID_GENERATORS(braid));
}


int SearchB(REMcontext *ctx, uint8_t *partialAnswer , uint8_t gens[GENERATORS_OF_SUBGROUP][GEN_BRAID_LEN], uint8_t matrices[GENERATORS_OF_SUBGROUP][WALNUT_BRAID][WALNUT_BRAID], uint8_t *Tvalues){
	int paFound = 0;
	int paLen = BRAID_LEN+1;
	int gensFound;
	uint8_t permutation[WALNUT_BRAID];
	setIdentityPermutation(permutation);
	unsigned char hash1[32],hash2[32];
	uint8_t answerStepBraid[BRAID_LEN];
	long iterations;
	int n = ctx->n;

	printf("####### SUBSTEPB %d #######\n",n);

	int collisions = 0;
	int usefulCollisions = 0;

    //Set first gen-matrix pair to identity.
	gens[0][0] = 0;
	gens[0][1] = 0;
	setIdentityMatrix(matrices[0]);
	gensFound = 1;

	// Determine the number of bits that has to be zero to be a distinguished point
	#if WALNUT_SECURITY_LEVEL == 128
		int bits = (3*n)-10;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 10;
		}
	#else
		int bits = (4*n)-12;
		if(bits < 0){
			bits = 0;
		}

		//if(n > 6){
		//	bits = 13;
		//}
	#endif

	collisionSearch search;
	initSearch(&search,nextHashB,ctx,SUBGROUP_CHAINS,bits);

	while(1){
		if(n>=6){
			iterations = findCollisionMT(&search,hash1,hash2,4);
		}
		else{
			iterations = findCollision(&search,hash1,hash2);
		}
		collisions ++;

		if(iterations == 0){
			break;
		}

		// Check if the collision is useful
		if((hash1[31]&1) + (hash2[31]&1) == 1){
			usefulCollisions ++;

			// Extract the solution for this step from the collision
			if((hash1[31]&1)!=0){
				extractBraidB(hash1,hash2,answerStepBraid,n);
			} 
			else{
				extractBraidB(hash2,hash1,answerStepBraid,n);
			}

			// If the solution is shorter then the previous best solution we store it
			if(GET_NUM_BRAID_GENERATORS(answerStepBraid) <= paLen){
				memcpy(partialAnswer,answerStepBraid,BRAID_LEN);
				paLen = GET_NUM_BRAID_GENERATORS(partialAnswer);
				paFound = 1;
			}
		}
		else if ((hash1[31]&1)==0 && gensFound < GENERATORS_OF_SUBGROUP){
			extractBraidB(hash1,hash2,gens[gensFound],n);
			setIdentityMatrix(matrices[gensFound]);
			walnut_emul(matrices[gensFound],permutation,gens[gensFound],Tvalues);
			if(isIdentityMatrix(matrices[gensFound]) == 0){
				gensFound++;
			}
		}
		if((gensFound >= GENERATORS_OF_SUBGROUP) && paFound){
			break;
		}
	}
	endSearch(&search);
	return iterations;
}

long SearchA(uint8_t *restAnswer , uint8_t newTarget[WALNUT_BRAID][WALNUT_BRAID], uint8_t gens[GENERATORS_OF_SUBGROUP][GEN_BRAID_LEN], uint8_t matrices[GENERATORS_OF_SUBGROUP][WALNUT_BRAID][WALNUT_BRAID], int n){
	uint8_t inv[WALNUT_BRAID][WALNUT_BRAID];
	SearchAcontext ctx;
	ctx.n = n;	
	getVectors(newTarget,ctx.targetvec,ctx.targetcovec,n);

	printf("targetvec = \n");

	int i;
	for(i=0 ; i<WALNUT_BRAID ; i++){
		printf("%3d ",ctx.targetvec[i]);
	}
	printf("\n");

	// Compute the scalar products of the rows of the matrices
	for(i=0 ; i<GENERATORS_OF_SUBGROUP ; i++){
		precomputeMatrixRows(matrices[i],ctx.matrixRows[i]);
		invertMatrix(matrices[i],inv);
		precomputeMatrixRows(inv,ctx.matrixRows[GENERATORS_OF_SUBGROUP+i]);
	}

	uint8_t permutation[WALNUT_BRAID];
	setIdentityPermutation(permutation);
	unsigned char hash1[32],hash2[32];
	uint8_t answerStepBraid[BRAID_LEN];
	long iterations = 0;

	#if WALNUT_SECURITY_LEVEL == 128
		int bits = (3*n)-16;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 10;
		}
	#else
		int bits = (4*n)-16;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 13;
		}
	#endif

	int collisions = 0;
	int usefulCollisions = 0;

	collisionSearch search;
	initSearch(&search,nextHashA,&ctx,SUBGROUP_CHAINS,bits);

	printf("####### SUBSTEP A %d #######\n",n);

	while(1){
		if(n>=7){
			iterations = findCollisionMT(&search,hash1,hash2,4);
		}
		else{
			iterations = findCollision(&search,hash1,hash2);
		}
		collisions ++;

		if(iterations == 0){
			break;
		}

		// Check if the collision is useful
		if((hash1[31]&1) + (hash2[31]&1) == 1){
			usefulCollisions ++;

			// Extract the solution for this step from the collision
			if((hash1[31]&1)!=0){
				extractBraidA(hash1,hash2,answerStepBraid,gens);
			} 
			else{
				extractBraidA(hash2,hash1,answerStepBraid,gens);
			}
	
			memcpy(restAnswer,answerStepBraid,BRAID_LEN);
			break;
		}
	}
	endSearch(&search);
	return iterations;

}


int solveSubsteps(uint8_t target[WALNUT_BRAID][WALNUT_BRAID], int n, uint8_t *Tvalues,int chains, uint8_t *answerBraid){
	uint8_t newTarget[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];
	setIdentityPermutation(permutation);

	// Build the context object
	REMcontext ctx;
	buildContext(&ctx,n,target,Tvalues);

	uint8_t partialAnswer[BRAID_LEN];
	uint8_t gens[GENERATORS_OF_SUBGROUP][GEN_BRAID_LEN];
	uint8_t matrices[GENERATORS_OF_SUBGROUP][WALNUT_BRAID][WALNUT_BRAID];

	long iterationsB = SearchB(&ctx,partialAnswer, gens, matrices, Tvalues);
	if(iterationsB == 0){
		return 0;
	}

	copyMatrix(target,newTarget);
	walnut_emul(newTarget,permutation,partialAnswer,Tvalues);

	printf("newTarget after B : \n");
	printMatrix(newTarget);

	uint8_t restAnswer[BRAID_LEN];
	long iterationsA = SearchA(restAnswer,newTarget,gens,matrices,n);
	if(iterationsA == 0){
		return 0;
	}

	walnut_emul(newTarget,permutation,restAnswer,Tvalues);

	printf("newTarget after A : \n");
	printMatrix(newTarget);

	uint8_t restrest[BRAID_LEN];
	uint8_t answerStep[BRAID_LEN];
	concat_braid(partialAnswer,restAnswer,answerStep);

	if(solveStep(newTarget, n-1 , Tvalues, chains, restrest)==0){
		return 0;
	}

	concat_braid(answerStep,restrest,answerBraid);


	printf("Number of iterations in step %dB: %ld \n", n,  iterationsB);

	printf("Number of iterations in step %dA: %ld \n", n,  iterationsA);

	return 1;
}