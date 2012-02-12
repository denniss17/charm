#include <iostream>
#include <ctime>
#include <map>
#include <sstream>
#define MR_PAIRING_MNT
#define AES_SECURITY 80
#include "pairing_3.h"

int N = 1;
#define HASH(x, str) group.hash_and_map(x, (char *) string(str).c_str())
#define Group PFC
#define SmallExp(x, a)	\
	x = mirvar(0); \
	bigbits(AES_SECURITY, x); \
	a = Big(x);

#define pair(a, b) group.pairing(b, a)
#define group_mul(a, b) a = a + b
#define group_exp(c, a, b) c.g = b * a.g

using namespace std;

int main()
{
	time_t seed;
	Group group(AES_SECURITY);
	miracl *mip=get_mip();
	mip->IOBASE = 10;
	time(&seed);
	irand((long)seed);

	Big delta[N];
	big t;

	for (int z = 0; z < N; z++)
	{
		SmallExp(t, delta[z]);
	}

	G1 dotA[N];
	G1 dotB[N];

	G1 h;
	string M;

	for z in range(0, N):
		M= verifyArgsDict[z]['message'][bodyKey]
		h= group.hash( M , G1 )

		dotA[z] =   h ** delta [ z ]  
		dotB[z] =   verifyArgsDict[z]['sig'][bodyKey] ** delta [ z ]  

	verifySigsRecursive(verifyArgsDict, group, incorrectIndices, 0, N, delta, dotA, dotB)

	return incorrectIndices