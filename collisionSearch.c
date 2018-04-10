/*
	Collision finding algorithm of Van Oorschot and Wiener 
*/

#include "collisionSearch.h"

/*
	Produces a chain of function iterations that starts in a random point, and ends in a distinguished point.
*/
void findChain(collisionSearch *search, unsigned char *start, unsigned char *end, long *len){
	int i;
	uint32_t num = 1;
	*len = 1;

	uint32_t mask = (1<<search->bits)-1;

	// Determine the maximal length of a chain.
	uint32_t limit = 20*(1<<search->bits);

	// Pick a random starting point
	for (i = 0; i < 32; i++)
	{
		start[i] = rand();
		end[i] = start[i];
	}

	// Iterate until we have a distinguished point
	while(num){
		search->funct(end,search->ctx);
		num = ((uint32_t)end[0])+(((uint32_t)end[1])<<8)+(((uint32_t)end[2])<<16);
		num &= mask;
		(*len)++;

		// If the length limit is reached we are probably stuck in a loop, so we abort and try again.
		if(*len > limit){
			printf("chain is too long \n");
			findChain(search,start,end,len);
			return; 
		}
	}
}

/*
	Given two chains (start1,len1) and (start2,len2) that end in the same distinguished point, this function extracts the two input values (hash1 and hash2) that produce the same output.
*/
void extractCollision(collisionSearch *search, unsigned char *start1, long len1 , unsigned char *start2, long len2, unsigned char *hash1, unsigned char *hash2){
	unsigned char START1[32],START2[32];

	// Copy the staring points.
	memcpy(START1,start1,32);
	memcpy(START2,start2,32);
	start1 = START1;
	start2 = START2;

	// If chain 1 is longer we iterate until both chains have same length
	while(len1>len2){
		len1--;
		search->funct(start1,search->ctx);
	}

	// If chain 2 is longer we iterate until both chains have same length
	while(len2>len1){
		len2--;
		search->funct(start2,search->ctx);
	}

	// If start1 = start2 we were very unlucky and we cannot extract a collision
	if(memcmp(start1,start2,32)==0){
		printf("Failed to extract collision! \n");
		return;
	}

	// We iterate on the chains untill a collision is found
	while(len1 >0){
		len1--;
		memcpy(hash1,start1,32);
		memcpy(hash2,start2,32);
		search->funct(start1,search->ctx);
		search->funct(start2,search->ctx);
		if (memcmp(start1,start2,32)==0){
			return;
		}
	}

	// Something is seriously wrong!
	printf("Invalid input to extractCollision function! \n");
}

/*
	Initialize a search object
*/
void initSearch(collisionSearch *search, void funct(unsigned char*, void *), void *ctx, int chains, int bits){
	search->funct = funct;
	search->ctx = ctx;
	search->chains = chains;
	search->chainsFound = 0;
	search->collisionsFound = 0;
	search->bits = bits;
	pthread_mutex_init(&search->mutex,NULL);
	search->iterations = 0;

	search->start = malloc(sizeof(unsigned char *)*chains);
	search->end   = malloc(sizeof(unsigned char *)*chains);
	search->len   = malloc(sizeof(long)*chains);
}

/*
	Destroys a search object
*/
void endSearch(collisionSearch *search){
	int i;
	for(i=0 ; i<search->chainsFound ; i++){
		free(search->start[i]);
		free(search->end[i]);
	}
	free(search->start);
	free(search->end);
	free(search->len);
}

/*
	Prints how many chains have been produced so far and how many collisions have been found.
*/
void reportProgress(collisionSearch *search){
	if((search->chainsFound&(search->chainsFound-1)) == 0) {
		printf("chains = %4d , collisions = %4d \n", search->chainsFound, search->collisionsFound);
	}
}

/*
	Produces two colliding inputs hash1 and hash2.

	returns the number of aplications of the function that was used, or 0 in case no collision fas found.
*/
long findCollision(collisionSearch *search, unsigned char *hash1, unsigned char *hash2){
	int j;
	while(search->chainsFound < search->chains){
		search->start[search->chainsFound] = malloc(sizeof(unsigned char[32]));
		search->end[search->chainsFound] = malloc(sizeof(unsigned char[32]));

		// produce a chain that ends in a distinguished point
		findChain(search,search->start[search->chainsFound],search->end[search->chainsFound],&(search->len[search->chainsFound]));
		search->iterations += search->len[search->chainsFound];
		search->chainsFound ++;
		
		//reportProgress(search);

		// check whether we have a collision in the table.
		for(j=0; j<search->chainsFound-1 ;j++){
			if(memcmp(search->end[search->chainsFound-1],search->end[j],32)==0){
				// Extract the collision from the two colliding chains
				extractCollision(search,search->start[j],search->len[j],search->start[search->chainsFound-1],search->len[search->chainsFound-1],hash1,hash2);
				search->collisionsFound++;
				return search->iterations;
			}
		}
	}
	return 0;
}


/*
	Worker thread used by findCollisionMT
*/
void *worker(void * srsh){
	int j;
	long len = 0;
	collisionSearch *search = srsh;
	
	// while no worker thread has found a collision
	while(search->busy){
		unsigned char *start = malloc(sizeof(unsigned char[32]));
		unsigned char *end   = malloc(sizeof(unsigned char[32]));

		// produce a chain
		findChain(search,start,end,&len);

		pthread_mutex_lock(&search->mutex);
			if(search->busy == 1){

				// add the chain to the common table and update counters
				search->iterations += len;
				search->len[search->chainsFound] = len;
				search->start[search->chainsFound] = start;
				search->end[search->chainsFound] = end;
				search->chainsFound ++;

				//reportProgress(search);

				// check if distinuished point was already in the table
				for(j=0; j<search->chainsFound-1 ;j++){
					if(memcmp(end,search->end[j],32)==0){
						// Extract the collision from the two colliding chains
						search->busy = 0;
						extractCollision(search,search->start[j],search->len[j],search->start[search->chainsFound-1],search->len[search->chainsFound-1],search->hash1,search->hash2);
						break;
					}
				}

				// if we have found many chains, but still no collision we give up.
				if(search->busy == 1 && search->chainsFound == search->chains){
					search->busy = 0;
					search->iterations = 0;
				}
			}
		pthread_mutex_unlock(&search->mutex);
	}
}

/*
	Does the same as findCollision, but multithreaded.
*/
long findCollisionMT(collisionSearch *search, unsigned char *hash1, unsigned char *hash2, int numberOfThreads){
	int i;
	search->busy = 1;
	
	// create worker threads
	pthread_t *threads = malloc(sizeof(pthread_t)*numberOfThreads);
	for(i = 0; i < numberOfThreads; i++)
	{
		pthread_create(&threads[i], NULL, worker, search);
	}

	// wait untill worker threads are done
	for(i=0 ; i< numberOfThreads ; i++){
		pthread_join(threads[i],NULL);
	}

	// return the collision
	search->collisionsFound++;
	memcpy(hash1,search->hash1,32);
	memcpy(hash2,search->hash2,32);
	return search->iterations;
}
