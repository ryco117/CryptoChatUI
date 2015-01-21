#ifndef ECDSA_H
#define ECDSA_H

#include "curve25519-donna.c"
#include "SFMT/SFMT.h"

static const uint8_t Curve25519Base[32] = {9};

static void ECC_Curve25519_Create(uint8_t pub[32], uint8_t k[32], sfmt_t& sfmt)
{
	sfmt_fill_small_array64(&sfmt, (uint64_t*)k, 4);
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	curve25519_donna(pub, k, Curve25519Base);
	return;
}
#endif