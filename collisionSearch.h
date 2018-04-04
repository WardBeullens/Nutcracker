#ifndef COLLISION_SEARCH_H
#define COLLISION_SEARCH_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct collisionSearch {
	void (*funct)(unsigned char*,void *);
	void *ctx;
	int chains;
	int bits;
	long iterations;
	unsigned char hash1[32];
	unsigned char hash2[32];

	unsigned char **start;
	unsigned char **end;
	long *len;

	int chainsFound;
	int collisionsFound;

	pthread_mutex_t mutex;
	int busy;
} collisionSearch;

void initSearch(collisionSearch *search, void funct(unsigned char*, void *), void *ctx, int chains, int bits);

void endSearch(collisionSearch *search);

long findCollision(collisionSearch *search, unsigned char *hash1, unsigned char *hash2);
long findCollisionMT(collisionSearch *search, unsigned char *hash1, unsigned char *hash2 , int numberOfThreads);

#endif