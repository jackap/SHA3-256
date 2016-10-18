#ifndef KECCAK_H
#define KECCAK_H

#define VERBOSE 0
#define MOD 5
#define RATIO 1088
#define indexOf(x,y) (5*(x%5)+(y)%5)%25
#define trace(x) if (VERBOSE) x 
void sponge(unsigned char *out_msg,unsigned int out_size,unsigned char *in_msg,
unsigned int in_size);

void printStateArray(uint64_t *A);
void Round(uint64_t *A,unsigned int rnd);
void printStateArrayInverted(uint64_t *A);




#endif /* KECCAK_H */
