#ifndef COLLISION_ATTACK_H
#define COLLISION_ATTACK_H

#include <stdint.h>
#include <unistd.h>
#include "mylib.h"
#include "collisionSearch.h"

typedef struct collisionAttackContext {
	uint8_t Tvalues[WALNUT_BRAID];
	uint8_t matrices[256][WALNUT_BRAID][WALNUT_BRAID];
	uint8_t matrixRows[256][WALNUT_BRAID][WALNUT_FIELD][WALNUT_BRAID];
} collisionAttackContext;

void collisionAttack();

#endif