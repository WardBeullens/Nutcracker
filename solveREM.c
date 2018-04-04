#include "solveREM.h"

#define NUMBER_OF_GENS 50
#define MAX_USEFUL_COLLISIONS 1
#define MAX_USEFUL_COLLISIONS_FACTOR 1
#define MAX_COLLISIONS 500
#define MAX_CHAINS 50000

//#define VERBOSE  

/*
	Given a hash, derive an s in B_N from this,
	compute a representation of the coset  
	A_{n-1} (1,e)  * s  or
	A_{n-1} Target * s
	And hash this result to get the next hash.

	This function is constructed such that from a collision in this function we can (sometimes) find a braid s
	such that Target * s is in A_{n-1}.
*/
void nextHash(unsigned char *hash, void *context){
	REMcontext *ctx = context;
	int i,gens;
	uint8_t vector1[WALNUT_BRAID];
	uint8_t vector2[WALNUT_BRAID];
	uint8_t covector1[WALNUT_BRAID];
	uint8_t covector2[WALNUT_BRAID];
	uint8_t buffer[2*WALNUT_BRAID];
	int n = ctx->n;

	// decide whether we are in the A_{n-1} (1,e)  * s  case or not
	if((hash[31]&1)==1){
		memcpy(vector2,ctx->targetvec,WALNUT_BRAID);
		memcpy(covector2,ctx->targetcovec,WALNUT_BRAID);
	}
	else {
		memset(vector2,0,WALNUT_BRAID);
		memset(covector2,0,WALNUT_BRAID);
		vector2[n-2]=1;
		covector2[n-1]=1;
	}

    // Act on the coset representation (vector,covector) with NUMBER_OF_GENS random pure braid generators.
	for(gens =0 ; gens < NUMBER_OF_GENS/2 ; gens++){
		vmmulX(vector2,ctx->matrixRows[hash[gens]%(2*n)],vector1);
	    vmmulX(vector1,ctx->matrixRows[(hash[gens]>>4)%(2*n)],vector2);

	    vmmulX(covector2,ctx->matrixCols[hash[gens]%(2*n)],covector1);
		vmmulX(covector1,ctx->matrixCols[(hash[gens]>>4)%(2*n)],covector2);
	}

	// Move the vector and covector into a buffer
	for(i = 0; i<WALNUT_BRAID ; i++){
		buffer[i] = vector2[i];
		buffer[WALNUT_BRAID+i] = covector2[i];
	}

	// Hash the buffer
	SHA256(buffer,2*WALNUT_BRAID,hash); 
}

/*
	Given a matrix in A_n, get two vectors that represent its right coset by A_n-1
*/
void getVectors(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t vector[WALNUT_BRAID], uint8_t covector[WALNUT_BRAID], int n){
	int i;
	uint8_t echelonMatrix[WALNUT_BRAID][WALNUT_BRAID];

	for(i=0; i<WALNUT_BRAID; i++){
		vector[i] = matrix[n-2][i];
	}

	echelonForm(matrix,echelonMatrix,n-1);

	for(i=0; i<WALNUT_BRAID; i++){
		covector[i] = echelonMatrix[i][n-1];
	}
}

/*
	Given a matrix-permutation pair (M,sigma), find a braid b such that the permutation part
	of (M,sigma) * b is trivial.
	Returns b and (M,sigma) * b
*/
void makePure(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID],uint8_t permutation[WALNUT_BRAID], uint8_t *Tvalues, uint8_t *b){
	int i,counter,temp;
	uint8_t perm[WALNUT_BRAID];
	memcpy(perm,permutation,WALNUT_BRAID);

	// Do bubbleSort to find a braid b whose permutation is the inverse of perm.
    i=0;
    counter = 0;
    while(i<WALNUT_BRAID-1){
    	if(perm[i]>perm[i+1]){
    		SET_BRAID_GENERATOR(b,i,counter);
    		counter++;
    		temp = perm[i];
    		perm[i] = perm[i+1];
    		perm[i+1] = temp;

    		i = 0;
    	}
    	else{
    		i++;
    	}
    }
    b[0] = 0;
    b[1] = counter;

    // Do E-Multiplication by b
    walnut_emul(matrix,permutation,b,Tvalues);
}

/*
	Given two good hash values that produce the same output when given to nextHash function, this function produces a braid that solves one of the steps of the REM problem.
*/
void extractBraid(uint8_t *hash1,uint8_t *hash2, uint8_t *braid, int n){
	uint8_t tempBraid1[BRAID_LEN];
	uint8_t tempBraid2[BRAID_LEN];
	int i;

	tempBraid1[0] = 0;
	tempBraid1[1] = 0;
	tempBraid2[0] = 0;
	tempBraid2[1] = 0;

	braid[0] = 0;
	braid[1] = 0;

	for (i=0 ; i<NUMBER_OF_GENS/2 ; i++){
		appendPureBraidGenerator(tempBraid1,hash1[i]%(2*n),n);
		appendPureBraidGenerator(tempBraid1,(hash1[i]>>4)%(2*n),n);

		appendPureBraidGenerator(braid,hash2[i]%(2*n),n);
		appendPureBraidGenerator(braid,(hash2[i]>>4)%(2*n),n);
	}

	invert_braid(braid,tempBraid2);
	concat_braid(tempBraid1,tempBraid2,braid);
	braid_free_reduction(braid);
}

/*
	This function builds a context object that contains the neccessary information to solve one of the steps of the REM problem
*/
void buildContext(REMcontext *ctx, int n , uint8_t target[WALNUT_BRAID][WALNUT_BRAID], uint8_t *Tvalues){
	int i;
	uint8_t pure_braid[17];
	uint8_t matrices[16][WALNUT_BRAID][WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];

	// set n, the number of the step (counting down from WALNUT_BRAID)
	ctx->n = n;

	// Compute a representation of the coset of the target.
	getVectors(target,ctx->targetvec,ctx->targetcovec,n);

	// Compute the matrices that correspond to P(pbg) where pbg are the generators of the pure braid group.
	setIdentityMatrix(matrices[0]);
	setIdentityMatrix(matrices[n]);
    setIdentityPermutation(permutation);
	for(i=1 ; i<n ; i++){
		setIdentityMatrix(matrices[i]);
		getPureBraidGenerator(i-1,n-1,0,pure_braid);
		walnut_emul(matrices[i],permutation,pure_braid,Tvalues);

		setIdentityMatrix(matrices[n+i]);
		getPureBraidGenerator(i-1,n-1,1,pure_braid);
		walnut_emul(matrices[n+i],permutation,pure_braid,Tvalues);

		#ifdef VERBOSE
			printf("(%d , %d):\n",i-1,n-1);
		    printMatrix(matrices[i]);
		#endif
	}

	// Compute the scalar products of the rows of the matrices
	for(i=0 ; i<n ; i++){
		precomputeMatrixRows(matrices[i],ctx->matrixRows[i]);
		precomputeMatrixRows(matrices[n+i],ctx->matrixRows[n+i]);

		transpose(matrices[i]);
		transpose(matrices[n+i]);

		precomputeMatrixRows(matrices[i],ctx->matrixCols[n+i]);
		precomputeMatrixRows(matrices[n+i],ctx->matrixCols[i]);
	}
}

/*
	Recursively solves the REM problem.

	Given a target in A_n, it computes a braid such that target * answerStepBraid is in A_{n-1}.
	Then the function calls itself to solve the rest of the problem.
*/
int solveStep(uint8_t target[WALNUT_BRAID][WALNUT_BRAID], int n, uint8_t *Tvalues,int chains, uint8_t *answerBraid){
	int i,result;
	uint8_t answerStepBraid[BRAID_LEN];
	uint8_t bestAnswerStepBraid[BRAID_LEN];
	uint8_t restBraid[BRAID_LEN];
	unsigned char hash1[32],hash2[32];
	uint8_t newTarget[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];
	setIdentityPermutation(permutation);
	long iterations = 0;
	int collisions;

	// We haven't found a solution, so we set the length of the best solution to something very long
	bestAnswerStepBraid[0] = 255;
	bestAnswerStepBraid[1] = 255;

	// Build the context object
	REMcontext ctx;
	buildContext(&ctx,n,target,Tvalues);

	printf("########### STEP %d ###########\n",n);
	printMatrix(target);
	if(n==6 || n == 5){
		return solveSubsteps(target,n,Tvalues,chains,answerBraid);
	}

	// Compute the maximal number of useful collisions
	uint32_t maxUsefulCollisions = MAX_USEFUL_COLLISIONS;
	for(i=WALNUT_BRAID ; i>n ; i--){
		maxUsefulCollisions *= MAX_USEFUL_COLLISIONS_FACTOR;
	}

	uint32_t usefulCollisions = 0;

	#if WALNUT_SECURITY_LEVEL == 128
		int bits = (5*n)-20;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 10;
		}
	#else
		int bits = (8*n)-25;
		if(bits < 0){
			bits = 0;
		}

		if(n > 6){
			bits = 15;
		}
	#endif

	collisionSearch search;
	initSearch(&search,nextHash,&ctx,chains,bits);

	for(collisions =0 ; collisions < MAX_COLLISIONS ; collisions++){
		if(n<=4){
			iterations = findCollision(&search,hash1,hash2);
		}
		else{
			iterations = findCollisionMT(&search,hash1,hash2,4);
		}
		if(iterations == 0){
			break;
		}

		if((hash1[31]&1) + (hash2[31]&1) == 1){
			usefulCollisions ++;

			// Extract the solution for this step from the collision
			if((hash1[31]&1)!=0){
				extractBraid(hash1,hash2,answerStepBraid,n);
			} 
			else{
				extractBraid(hash2,hash1,answerStepBraid,n);
			}

			// If the solution is shorter then the previous best solution we store it
			if(GET_NUM_BRAID_GENERATORS(answerStepBraid) <= GET_NUM_BRAID_GENERATORS(bestAnswerStepBraid)){
				memcpy(bestAnswerStepBraid,answerStepBraid,BRAID_LEN);
			}

			// If we have found maxUsefulCollisions we proceed to the next step
			if(usefulCollisions >= maxUsefulCollisions){
				// Compute and print the target for the next step
				copyMatrix(target,newTarget);
				walnut_emul(newTarget,permutation,bestAnswerStepBraid,Tvalues);
				printMatrix(newTarget);

				restBraid[0]=0;
				restBraid[1]=0;
				result = 1;
				if (n>2){
					// Solve the rest of the problem
				   	result = solveStep(newTarget,n-1,Tvalues,chains,restBraid);
				}
				if(result == 1){
					// Concatenate the rest of the solution with the solution for this step.
				   	concat_braid(bestAnswerStepBraid,restBraid,answerBraid);
				   	printf("Number of iterations in step %d : %ld \n", n,  iterations);
				   	return 1;
				}
			}
		}

	}

	if(usefulCollisions>0){
		// Compute and print the target for the next step
		copyMatrix(target,newTarget);
		walnut_emul(newTarget,permutation,bestAnswerStepBraid,Tvalues);
		//printMatrix(newTarget);

		restBraid[0]=0;
		restBraid[1]=0;
		result = 1;
		if (n>2){
			// Solve the rest of the problem
		   	result = solveStep(newTarget,n-1,Tvalues,chains,restBraid);
		}
		if(result == 1){
			// Concatenate the rest of the solution with the solution for this step.
		   	concat_braid(bestAnswerStepBraid,restBraid,answerBraid);
		   	printf("Number of iterations in step %d : %ld \n", n,  iterations);
		   	return 1;
		}
	}

	return 0;
}

/*
	Creates a braid that transports the first 2 T-values to the last 2 spots.
*/
void getTransportBraid(uint8_t *b, uint8_t n){
	uint8_t i;
	memset(b,0,100);
	b[0] = 0;
	b[1] = 2*(n-2);

	for(i=0 ; i<WALNUT_BRAID-2; i++){
		SET_BRAID_GENERATOR(b,i+1,i);
	}

	for(i=0 ; i<WALNUT_BRAID-2; i++){
		SET_BRAID_GENERATOR(b,i,((uint8_t) ((n-2)+i)));
	}
}

/* 
	Solves the REM problem
*/
int SolveREM(uint8_t Matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t Permutation[WALNUT_BRAID], uint8_t *Tvalues, uint8_t *b, int n){
	int res;
	uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t permutation[WALNUT_BRAID];

	uint8_t impurePart[BRAID_LEN];
	uint8_t purePart[BRAID_LEN];
	uint8_t transportBraid[BRAID_LEN];
	uint8_t transportBraidinv[BRAID_LEN];

	getTransportBraid(transportBraid,n);
	invert_braid(transportBraid,transportBraidinv);

	uint8_t transportMatrix[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t transportPermutation[WALNUT_BRAID];
	uint8_t transportMatrixinv[WALNUT_BRAID][WALNUT_BRAID];
	uint8_t transportPermutationinv[WALNUT_BRAID];

	setIdentityMatrix(transportMatrix);
	setIdentityPermutation(transportPermutation);
	walnut_emul(transportMatrix,transportPermutation,transportBraid,Tvalues);
	invertMatrix(transportMatrix,transportMatrixinv);
	memcpy(transportPermutationinv,transportPermutation,WALNUT_BRAID);
	invert_permutation(transportPermutationinv,WALNUT_BRAID);

	uint8_t newTvalues[WALNUT_BRAID];
	multiply_permutations(newTvalues,Tvalues,transportPermutation,WALNUT_BRAID);

	walnut_mmul(matrix,transportMatrixinv,Matrix);
	multiply_permutations(permutation,transportPermutationinv,Permutation,WALNUT_BRAID);

	makePure(matrix,permutation,newTvalues,impurePart);

	res = solveStep(matrix,n,newTvalues,MAX_CHAINS,purePart);

	uint8_t br1[BRAID_LEN];
	uint8_t br2[BRAID_LEN];

	concat_braid(impurePart,purePart,br1);
	concat_braid(br1,transportBraidinv,br2);

	invert_braid(br2,b);

	return res;
}