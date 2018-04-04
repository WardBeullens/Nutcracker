#ifndef SOLVESUBSTEP_H
#define SOLVESUBSTEP_H

#include "solveREM.h"
#include "mylib.h"
#include "collisionSearch.h"

int solveSubsteps(uint8_t target[WALNUT_BRAID][WALNUT_BRAID], int n, uint8_t *Tvalues,int chains, uint8_t *answerBraid);

#endif