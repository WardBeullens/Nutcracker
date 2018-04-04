/*
* Copyright (c) 2017 SecureRF Corporation, All rights reserved.
* -------------------------------------------------------------------------
* This computer program is proprietary information of SecureRF Corporation.
* The receipt or possession of this program does not convey any rights to
* reproduce or disclose its contents, or to manufacture, use, or sell
* anything that it may describe, in whole or in part, except for the purposes of 
* the post-quantum algorithm public review and evaluation in connection with 
* the National Institute of Standards and Technology’s development of standards 
* for post-quantum cryptography.  Any reproduction of this program for any other 
* purpose without the express written consent of SecureRF is a violation of the 
* copyright laws and may subject you to criminal prosecution.
* -------------------------------------------------------------------------
*/

//**************************************************************************
// START USER-CONTROLLED DEFINITIONS
//**************************************************************************

/* If defined, the signature will be rewritten as per BKL Normal Form with Dehornoy Reduction */
//#define BKL

/* If defined, the signature will be rewritten as per Stochastic Rewriting with Dehornoy Reduction */
//#define STOCHASTIC

/* If defined, the signature will be rewritten as per Stochastic Rewriting without Dehornoy Reduction */
#define STOCHASTIC_WO_DEHORNOY

#ifndef WALNUT_SECURITY_LEVEL
/* Define the security level. Valid options: 128, 256 */
#define WALNUT_SECURITY_LEVEL       256
#endif

//**************************************************************************
// END USER-CONTROLLED DEFINITIONS
//**************************************************************************

#if (defined(BKL) && (defined(STOCHASTIC) || defined(STOCHASTIC_WO_DEHORNOY))) || (defined(STOCHASTIC) && defined(STOCHASTIC_WO_DEHORNOY))
#error Please choose only one re-writing function
#endif

#if WALNUT_SECURITY_LEVEL != 128 && WALNUT_SECURITY_LEVEL != 256
#error Please choose either security level 128 or 256
#endif

#if WALNUT_SECURITY_LEVEL == 128
#define CRYPTO_SECRETKEYBYTES 136
#define CRYPTO_PUBLICKEYBYTES 83
#	ifdef BKL
#define CRYPTO_BYTES 1100
#	elif defined(STOCHASTIC)
#define CRYPTO_BYTES 1200
#	else
#define CRYPTO_BYTES 2000
#	endif
#else
#define CRYPTO_SECRETKEYBYTES 291
#define CRYPTO_PUBLICKEYBYTES 128
#	ifdef BKL
#define CRYPTO_BYTES 1800
#	elif defined(STOCHASTIC)
#define CRYPTO_BYTES 2100
#	else
#define CRYPTO_BYTES 3400
#	endif
#endif
#define CRYPTO_ALGNAME "walnut128"
