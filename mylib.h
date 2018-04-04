#ifndef MYLIB_H
#define MYLIB_H

#include "ae_crypto.h"

#define BRAID_LEN 10000

void getPureBraidGenerator(uint8_t i, uint8_t j , uint8_t inverse, uint8_t *braid);

void setIdentityMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]);
int isIdentityMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]);
void setIdentityPermutation(uint8_t permutation[WALNUT_BRAID]);
void CBOne(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t permutation[WALNUT_BRAID]);
void printMatrix(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]);
void printPerm(uint8_t permutation[WALNUT_BRAID]);
void printTvals(uint8_t tvals[WALNUT_BRAID]);
void echelonForm(uint8_t matrixIn[WALNUT_BRAID][WALNUT_BRAID], uint8_t matrixOut[WALNUT_BRAID][WALNUT_BRAID], uint8_t rows);
int generateRandomBraid(void *b, size_t length, int n);
void appendPureBraidGenerator(uint8_t *b, int i, int n);

void copyMatrix(uint8_t from[WALNUT_BRAID][WALNUT_BRAID], uint8_t to[WALNUT_BRAID][WALNUT_BRAID]);
void vmmul(uint8_t vector[WALNUT_BRAID], uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID] , uint8_t result[WALNUT_BRAID]);
void vmmulX(uint8_t vector[WALNUT_BRAID], uint8_t matrixRows[WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID] , uint8_t result[WALNUT_BRAID]);
void transpose(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID]);

void extractTvalues(uint8_t *Tvalues , uint8_t *publicKey);
int signature_generation_no_cloaking(void *signature, void *sig_length, const void *message, size_t length, const void *privkey);

void precomputeMatrixRows(uint8_t matrix[WALNUT_BRAID][WALNUT_BRAID], uint8_t rows[WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID]);

void invertMatrix(uint8_t matrixIn[WALNUT_BRAID][WALNUT_BRAID], uint8_t matrixOut[WALNUT_BRAID][WALNUT_BRAID]);

#endif