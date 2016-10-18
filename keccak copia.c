
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

	int i;;
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



	trace(printf("After rho:\n"));

	for (x = 0; x < 5; x++) {
		for (y = 0; y < 5; y++) {

			B[indexOf(y, x)] = ROL64(A[indexOf(y, x)], RhoOffset[x][y]);
			//printf("A[%d] = %llx\n", indexOf(y, x), B[indexOf(y, x)]);
		}
	}

	trace(printStateArrayInverted(B));



	trace(printf("After rho and pi:\n"));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y) {
			B[indexOf(2 * x + 3 * y, y)] =
			    ROL64(A[indexOf(y, x)], RhoOffset[x][y]);

		}
	trace(printStateArrayInverted(B));
	//chi step
	    trace(printf("After chi:%c\n", 0));

	for (x = 0; x < 5; ++x)
		for (y = 0; y < 5; ++y)
			A[indexOf(y, x)] =
			    B[indexOf(y, x)] ^
			    ((~B[indexOf(y, x + 1)]) &
			     B[indexOf(y, x + 2)]);

	trace(printStateArrayInverted(A));

	///iota step
	    trace(printf("After iota:%c\n", 0));
	A[indexOf(0, 0)] = A[indexOf(0, 0)] ^ RC[rnd];

	trace(printStateArrayInverted(A));
}
/*****************************************************************************
 * @brief: This function inverts the bytes of a 64bit variable
 * @author: Jacopo Bufalino - jacopobufalino@gmail.com
 * @date: 2016/13/10
 * @return: new 64bit variable
 * @arg: input variable
 * @note: This function is used only to print the value.
 *
 *****************************************************************************/
void sponge(unsigned char *out_msg, unsigned int out_size, unsigned char *in_msg,
	     unsigned int in_size)
{

	/* printf("***************STATS*************\n"); printf("in_size
	   %d\n",in_size); printf("in_size\\%RATIO %d\n",in_size%RATIO);
	   printf("padding len %d\n",pad_len); printf("final_len
	   %d\n",final_len); */

	unsigned long pad_len, final_len;
	unsigned char *msg_final = NULL;
	unsigned int i, nchunks = in_size / RATIO + (in_size % RATIO == 0 ? 0 : 1);
	if (in_size % RATIO) {
		unsigned char *msg_pad = NULL;
		if ((pad_len =
		pad10x1(&msg_pad, RATIO, (unsigned long)in_size % 1088)) <= 0)
			exit(EXIT_FAILURE);
		if ((final_len =
		     concatenate(&msg_final, in_msg, in_size, msg_pad, pad_len)) % RATIO)
			exit(EXIT_FAILURE);
		free(msg_pad);
	} else
		msg_final = in_msg;
	/* Now I have message plus padding, and it is a multiple of the rate */

	unsigned int cur_pos = 0;
	unsigned char input[200];
	uint64_t *nextState = (uint64_t *) calloc(200, sizeof(char));
	uint64_t *cur_state = (uint64_t *) calloc(200, sizeof(char));
	/* this probably can be a function */
	bzero(input, sizeof(input));
	memcpy(cur_state, &msg_final[cur_pos], 136 * sizeof(char));
	Round(cur_state, 24);
	while (--nchunks) {
		cur_pos += 136;
		memcpy(nextState, &msg_final[cur_pos], 136 * sizeof(char));
		for (i = 0; i < 25; i++)
			cur_state[i] = cur_state[i] ^ nextState[i];
		Round(cur_state, 24);

	}
	/* while(nchunks--){ printStateArray(cur_state);
	   printf("\n********************************\n"); //	printf("OK for
	   now\n"); Round(cur_state,24); //		exit(0);
	   //system("pause"); } */


	/* fill output array with sha3 */
	memcpy(out_msg, cur_state, (unsigned int)out_size / 8);
	free(cur_state);
	free(nextState);
	if (msg_final != in_msg)
		free(msg_final);


}
