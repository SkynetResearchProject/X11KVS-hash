/*
    MIT License
	
    Copyright (c) 2021 The DECENOMY Core Developers
    Copyright (c) 2022 SkynetResearch Project https://github.com/github.com/DiplexSoftfork/X11KVS-hash

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/
#include "x11kvshash.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sha256.h"

/* ----------- Kyan Hash X11KV ------------------------------------------- */

const unsigned int HASHX11KV_MIN_NUMBER_ITERATIONS = 2;
const unsigned int HASHX11KV_MAX_NUMBER_ITERATIONS = 6;
const unsigned int HASHX11KV_NUMBER_ALGOS = 11;

inline void HashX11KV(const char* input, char* output)
{
    sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein512_context      ctx_skein;
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    //static unsigned char      pblank[1];


	//these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16];


    // Iteration 0
    sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, hashA);

    int n = HASHX11KV_MIN_NUMBER_ITERATIONS + ( (unsigned int)((unsigned char*)hashA)[63] % (HASHX11KV_MAX_NUMBER_ITERATIONS - HASHX11KV_MIN_NUMBER_ITERATIONS + 1));	

    for (int i = 1; i < n; i++) {
        switch (((unsigned int)((unsigned char*)hashA)[i % 64]) % HASHX11KV_NUMBER_ALGOS) {
        case 0:
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, hashA, 64);
            sph_blake512_close(&ctx_blake, hashA);
            break;
        case 1:
            sph_bmw512_init(&ctx_bmw);
            sph_bmw512(&ctx_bmw, hashA, 64);
            sph_bmw512_close(&ctx_bmw, hashA);
            break;
        case 2:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, hashA, 64);
            sph_groestl512_close(&ctx_groestl, hashA);
            break;
        case 3:
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, hashA, 64);
            sph_skein512_close(&ctx_skein, hashA);
            break;
        case 4:
            sph_jh512_init(&ctx_jh);
            sph_jh512(&ctx_jh, hashA, 64);
            sph_jh512_close(&ctx_jh, hashA);
            break;
        case 5:
            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, hashA, 64);
            sph_keccak512_close(&ctx_keccak, hashA);
            break;
        case 6:
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, hashA, 64);
            sph_luffa512_close(&ctx_luffa, hashA);
            break;
        case 7:
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, hashA, 64);
            sph_cubehash512_close(&ctx_cubehash, hashA);
            break;
        case 8:
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, hashA, 64);
            sph_shavite512_close(&ctx_shavite, hashA);
            break;
        case 9:
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, hashA, 64);
            sph_simd512_close(&ctx_simd, hashA);
            break;
        case 10:
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, hashA, 64);
            sph_echo512_close(&ctx_echo, hashA);
            break;
        }
    }
	memcpy(output, hashA, 32);	
}

/* ----------- Sapphire 2.0 Hash X11KVS ------------------------------------ */
/* - X11, from the original 11 algos used on DASH -------------------------- */
/* - K, from Kyanite ------------------------------------------------------- */
/* - V, from Variable, variation of the number iterations on the X11K algo - */
/* - S, from Sapphire ------------------------------------------------------ */

static inline uint32_t le32dec(const void* pp)
{
    const uint8_t* p = (uint8_t const*)pp;
    return ((uint32_t)(p[0]) |
            ((uint32_t)(p[1]) << 8) |
            ((uint32_t)(p[2]) << 16) |
            ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void* pp, uint32_t x)
{
    uint8_t* p = (uint8_t*)pp;
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}


static inline void Hash(const char* hash, const char* hash1, const char* hash2, char* output){	
    struct sha256_buff buff;
	
    sha256_init(&buff);  
    sha256_update(&buff, hash, 32);
	sha256_update(&buff, hash1, 32);
	sha256_update(&buff, hash2, 32);
    sha256_finalize(&buff);
	sha256_read(&buff, (uint8_t*)output);
	
	sha256_init(&buff);
	sha256_update(&buff, (uint8_t*)output, 32);
	sha256_finalize(&buff);
	sha256_read(&buff, (uint8_t*)output);

}	
	
const unsigned int HASHX11KVS_MAX_LEVEL = 7;
const unsigned int HASHX11KVS_MIN_LEVEL = 1;
const unsigned int HASHX11KVS_MAX_DRIFT = 0xFFFF;

void x11kvs_hash(const char* input, char* output)
{
    const unsigned int level = HASHX11KVS_MAX_LEVEL;
    x11kvs_hash1(input, (char*)output,  level);
}

inline void x11kvs_hash1(const char* input, char* output, const unsigned int level)
{
	uint32_t hash[16], hash1[16], hash2[16];	
	
    HashX11KV(input, (char*)hash);	

	if (level == HASHX11KVS_MIN_LEVEL){
		memcpy(output, hash, 32);
		return;
	}
	
	uint32_t nonce = le32dec(input + 76);

    uint8_t nextheader1[80];
    uint8_t nextheader2[80];

    uint32_t nextnonce1 = nonce + (le32dec(((unsigned char*)hash) + 24) % HASHX11KVS_MAX_DRIFT);
    uint32_t nextnonce2 = nonce + (le32dec(((unsigned char*)hash) + 28) % HASHX11KVS_MAX_DRIFT);

    memcpy(nextheader1, input, 76);
    le32enc(nextheader1 + 76, nextnonce1);

    memcpy(nextheader2, input, 76);
    le32enc(nextheader2 + 76, nextnonce2);
	
    x11kvs_hash1((const char*) nextheader1, (char*) hash1, level-1);
	
    x11kvs_hash1((const char*) nextheader2, (char*) hash2, level-1);

    Hash((const char*)hash, (const char*)hash1, (const char*)hash2, (char*)output);
}
