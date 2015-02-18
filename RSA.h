#ifndef MYRSA
#define MYRSA

#include <gmpxx.h>

using namespace std;

namespace
{
class RSA
{
public:
    void BigPrime(mpz_class& p, gmp_randclass& rng, unsigned long sz, unsigned long c);
    void KeyGenerator(mpz_class& Dec, mpz_class& Enc, mpz_class& Mod, gmp_randclass& rng);

    mpz_class Encrypt(mpz_class& Modulus, mpz_class& Key, unsigned int Msg);
    unsigned char Decrypt(mpz_class& Modulus, mpz_class& Key, mpz_class& Cypher);

    mpz_class BigEncrypt(mpz_class& Modulus, mpz_class& Key, mpz_class Msg);
    mpz_class BigDecrypt(mpz_class& Modulus, mpz_class& Key, mpz_class Cypher);
};
}
#endif