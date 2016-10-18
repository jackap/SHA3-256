
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>
#include "sha3.h"
#include "keccak.h"

unsigned long RC[] =
{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};


unsigned long RhoOffset[5][5] = {
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14}
};

/// This function is hidden because it is used only within this file
void r_ound(uint64_t * A, unsigned int rnd);

/*****************************************************************************
 * @brief: This set of functions prints the content of a generic state array
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10 
 * @return: void 
 * @arg: inpunt state array
 * @note: Use them just to debug the code
 *
 *****************************************************************************/
void printStateArray(uint64_t * A)
{

	int i;
	for (i = 0; i < 25; i++) {
		if (i % 2 == 0)
			printf("\n");
		printf("%.16llx", A[i]);


	}
	printf("\n");
}
void printStateArrayInverted(uint64_t * A)
{
	unsigned char *ptr = (unsigned char *)A;
	int i;
	for (i = 0; i < 200; i++) {

		if (i % 16 == 0)
			printf("\n");
		printf("%.2X ", ptr[i]);


	}
	printf("\n");
}

/*****************************************************************************
 * @brief: The sequence of step mappings that is iterated in the calculation of
 * a KECCAK-p permutation (See par. 3.2).
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10
 * @return: updated state array
 * @arg: state array and number of round
 * @note: This function contains all steps to perform the permutation.
 *
 *****************************************************************************/
void Round(uint64_t * A, unsigned int rnd)
{

	for (unsigned int i = 0; i < rnd; i++) {
		trace(printf("\n+++Round %d+++\n", i));
		r_ound(A, i);
	}
}
void r_ound(uint64_t * A, unsigned int rnd)
{
	uint64_t C[MOD], B[MOD * MOD], D[MOD];
	uint8_t x, y;

	/* Initialization */
	bzero(C, sizeof(C));
	bzero(D, sizeof(D));
	bzero(B, sizeof(B));

///theta step
	trace(printf("After theta:\n"));

	for (x = 0; x < MOD; x++) {
		C[x] = A[indexOf(0, x)] ^ A[indexOf(1, x)] ^ A[indexOf(2, x)]
		    ^ A[indexOf(3, x)] ^ A[indexOf(4, x)];
	}
	for (x = 0; x < MOD; ++x) {

		D[x] = C[(x + 4) % MOD] ^ ROL64(C[(x + 1) % MOD], 1);
		for (y = 0; y < MOD; ++y)
			A[indexOf(y, x)] = A[indexOf(y, x)] ^ D[x];


	}

	trace(printStateArrayInverted(A));


///rho step
	trace(printf("After rho:\n"));

	for (x = 0; x < 5; x++) 
		for (y = 0; y < 5; y++) 
			B[indexOf(y, x)] =
			ROL64(A[indexOf(y, x)], RhoOffset[x][y]);

	trace(printStateArrayInverted(B));


///pi step
	trace(printf("After pi:\n"));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y) {
			B[indexOf(2 * x + 3 * y, y)] =
			ROL64(A[indexOf(y, x)], RhoOffset[x][y]);

		}

	trace(printStateArrayInverted(B));

///chi step
	trace(printf("After chi:%c\n", 0));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y)
			A[indexOf(y, x)] = B[indexOf(y, x)] ^
			((~B[indexOf(y, x + 1)]) &
			 B[indexOf(y, x + 2)]);

	trace(printStateArrayInverted(A));

///iota step
	trace(printf("After iota:%c\n", 0));
	A[indexOf(0, 0)] = A[indexOf(0, 0)] ^ RC[rnd];

	trace(printStateArrayInverted(A));

}

/*****************************************************************************
 * @brief: This function implements the sponge algorithm (see par 4.0)
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10
 * @return: sha3 encrypted array
 * @arg: output message and size,input message (already with 01 as padding),
 * input len
 * @note: In this function is not necessary to create the  arrays
 * nextState and cur_state (you can just create pointers) but I have
 * added them because in my opinion is a good compromise between optimization
 * and code readability.
 *****************************************************************************/
void
sponge(unsigned char *out_msg, unsigned int out_size, unsigned char *in_msg,
 unsigned int in_size)
{

	unsigned long pad_len, final_len;
	unsigned char *msg_final = NULL;
	unsigned int i, nchunks = in_size / RATIO +
	(in_size % RATIO == 0 ? 0 : 1);

///do I need additional padding? 
	if (in_size % RATIO) { ///yes
	unsigned char *msg_pad = NULL;
		if ((pad_len = ///create padding
		pad10x1(&msg_pad, RATIO, (unsigned long)in_size % 1088)) <= 0)
			exit(EXIT_FAILURE);
		if ((final_len = ///concatenate the old string with padding
		concatenate(&msg_final, in_msg,
		in_size, msg_pad, pad_len)) % RATIO)
			exit(EXIT_FAILURE);
		free(msg_pad);///free memory
	} else
		msg_final = in_msg;

	/* Now I have message plus padding, and it is a multiple of the rate */
	unsigned int cur_pos = 0;
	unsigned char input[200];
	uint64_t *nextState = (uint64_t *) calloc(200, sizeof(char));
	uint64_t *cur_state = (uint64_t *) calloc(200, sizeof(char));
	
	bzero(input, sizeof(input));
	memcpy(cur_state, &msg_final[cur_pos], 136 * sizeof(char));
	Round(cur_state, 24); /* call keccak the first time */
	
	while (--nchunks) { //enter here until there is data to absorb
		cur_pos += 136;
		//load the next chunk
		memcpy(nextState, &msg_final[cur_pos], 136 * sizeof(char)); 
		//bit-bit XOR between states
		for (i = 0; i < 25; i++)
			cur_state[i] = cur_state[i] ^ nextState[i];
		//repeat keccak algorithm
		Round(cur_state, 24);

	}

	/* fill output array with sha3 and free memory */
	memcpy(out_msg, cur_state, (unsigned int)out_size / 8);
	free(cur_state);
	free(nextState);
	if (msg_final != in_msg)
		free(msg_final);


}

