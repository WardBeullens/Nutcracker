#ifndef SOLVEREM_H
#define SOLVEREM_H

#include <stdio.h>
#include <time.h> 
#include "ae_lib.h"
#include "ae_crypto.h"
#include "mylib.h"
#include "solveSubstep.h"
#include "collisionSearch.h"

typedef struct REMcontext{
	uint8_t matrixRows[16][WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID];
	uint8_t matrixCols[16][WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID];
	uint8_t targetvec[WALNUT_BRAID];
	uint8_t targetcovec[WALNUT_BRAID];
	uint8_t n;
} REMcontext;


void makePure(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID],uint8_t permutation[WALNUT_BRAID], uint8_t *Tvalues, uint8_t *b);
int SolveREM(uint8_t Matrix[WALNUT_BRAID][WALNUT_BRAID],uint8_t Permutation[WALNUT_BRAID], uint8_t *Tvalues, uint8_t *b, int n);
int solveStep(uint8_t target[WALNUT_BRAID][WALNUT_BRAID], int n, uint8_t *Tvalues,int chains, uint8_t *answerBraid);
void buildContext(REMcontext *ctx, int n , uint8_t target[WALNUT_BRAID][WALNUT_BRAID], uint8_t *Tvalues);
void getVectors(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t vector[WALNUT_BRAID], uint8_t covector[WALNUT_BRAID], int n);

#endif