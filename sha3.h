#ifndef SHA3_H
#define SHA3_H


/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)

/* Implement the following API. Do NOT modify the given prototypes. */

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer (allocated by the caller)
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */


unsigned long concatenate(unsigned char **Z, const unsigned char *X,
			  unsigned long X_len, const unsigned char *Y,
			  unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
			     unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);
unsigned char rc(unsigned int t);

void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */
#endif /* SHA3_H */
