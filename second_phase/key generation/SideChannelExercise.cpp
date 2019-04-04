// Turn off compiler optimizations
// Try to turn on compiler optimizations and execute again
// Measure time of operation (available to an attacker)
// Measure counts of operation (usually not available to an atatcker, but gives us insight)
// Try profiler to obtain count of operations

// What is "secret" information stored at server? What is data that attacker can choose?

// Plot.ly - Traces->Range/bins 1

#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <memory.h>
#include <assert.h>
#include "bignum.h"

typedef unsigned long ULONG;
const int ULONG_LENGTH = sizeof(ULONG);

typedef enum {
	SQUAREANDMULTIPLY = 2,
	SQUAREANDMULTIPLYMASKED = 3
} ExpType;
 
// Note: we will use long int for easy manipulation with variables. However, length unsigned int (32 bits) is not enough to provide secure RSA!

/**
Toy random number generation function. Not suitable for rea crypto use due to weak RNG generator!!!
*/
int generateRNG(void *, unsigned char * buffer, size_t numBytes) {
	for (size_t i = 0; i < numBytes; i++) {
		buffer[i] = rand() % 256;
	}
	return 0;
}

//Helper function for generating new keypair
void generateSuitableNumbers(mpi* modulus, mpi* publicExponent, mpi* privateExponent, size_t SIZE, FILE * file) {
	mpi p; mpi_init(&p);
	mpi q; mpi_init(&q);	
	mpi phi; mpi_init(&phi);
	mpi pMinusOne; mpi_init(&pMinusOne);
	mpi qMinusOne; mpi_init(&qMinusOne);
	mpi divisor; mpi_init(&divisor);
	do {
		mpi_gen_prime(&p, SIZE, 1, generateRNG, NULL);
		mpi_sub_int(&pMinusOne, &p, 1);
		printf("first\n");
		mpi_gen_prime(&q, SIZE, 1, generateRNG, NULL);
		mpi_sub_int(&qMinusOne, &q, 1);
		mpi_mul_mpi(modulus, &p, &q);
		printf("second\n");
		mpi_mul_mpi(&phi, &pMinusOne, &qMinusOne);
		mpi_gcd(&divisor, privateExponent, &phi);
		printf("round\n");
	} while (mpi_cmp_int(&divisor, 1) != 0);
	mpi_write_file("First prime: \n", &p, 16, file);
	mpi_write_file("Second prime: \n", &q, 16, file);
	printf("generated\n");

	mpi_inv_mod(publicExponent, privateExponent, &phi);
	return;
}

void generateHighKeypairHW(mpi* modulus, mpi* publicExponent, mpi* privateExponent, size_t SIZE) {

	FILE* file = fopen("klice_high.txt", "w");
	size_t expSize = 2 * SIZE;
	for (int i = 0; i < expSize; i++) {
		mpi_set_bit(privateExponent, i, 1);
	}
	generateSuitableNumbers(modulus, publicExponent, privateExponent, SIZE, file);
	mpi_write_file("exponent: \n", privateExponent, 16, file);
	mpi_write_file("modulus: \n", modulus, 16, file);
	mpi_write_file("public : \n", publicExponent, 16, file);
	fclose(file);
	return;
}

void generateLowKeypairHW(mpi* modulus, mpi* publicExponent, mpi* privateExponent, size_t SIZE) {

	size_t expSize = 2 * SIZE;
	for (int i = 1; i < expSize - 1; i++) {
		mpi_set_bit(privateExponent, i, 0);
	}

	FILE* file = fopen("klice_low.txt", "w");
	generateSuitableNumbers(modulus, publicExponent, privateExponent, SIZE, file);
	mpi_write_file("exponent: \n", privateExponent, 16, file);
	mpi_write_file("modulus: \n", modulus, 16, file);
	mpi_write_file("public : \n", publicExponent, 16, file);
	fclose(file);
	return;
}

int main()
{
	printf("sizeof(ULONG) = %d\n", sizeof(ULONG));
	printf("CLOCKS_PER_SEC = %d\n", CLOCKS_PER_SEC);
	printf("######################################\n");

	int measurement = 1000;
        size_t size = 1024;

		size_t SIZE = 1024;
		mpi modulus; mpi_init(&modulus);
		mpi publicExponent; mpi_init(&publicExponent);
		mpi privateExponent; mpi_init(&privateExponent);

		generateHighKeypairHW(&modulus, &publicExponent, &privateExponent, SIZE);
		generateLowKeypairHW(&modulus, &publicExponent, &privateExponent, SIZE);

}


