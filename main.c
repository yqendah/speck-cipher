#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#define ER32(x,y,k) (x=ROR(x,8), x+=y, x^=k, y=ROL(y,3), y^=x)
#define DR32(x,y,k) (y^=x, y=ROR(y,3), x^=k, x-=y, x=ROL(x,8))
#define ROR(x, r) ((x >> r) | (x << (32 - r)))
#define ROL(x, r) ((x << r) | (x >> (32 - r)))

#define alpha 8
#define peta 3
#define m 4

// function for converting Hex String to a 64-bit integer
uint64_t fromHexStringToLong(char *block) {
    uint64_t result;
    int i;
    // each character is 4 bits, there are 16 characters in a 64-bit block
    // the multiplication and addition are done the same way as before, with shifting and bitwise OR
    for (i = 0; i < 16; i++)
        result = (result << 4) | ((block[i] >= '0' && block[i] <= '9') ? (block[i] - '0') : (block[i] - 'a' + 10));
    return result;
}

// function for converting a 64-bit integer to a Hex String
char *fromLongToHexString(uint64_t block) {
    char *hexString = malloc(17 * sizeof(char));
    //we print the integer in a String in hexadecimal format
    sprintf(hexString, "%016llx", block);
    return hexString;
}

// function that returns the low 64 bits of the key, which is given as input in a Hex String format
uint64_t getKeyLow(char *key) {
    int i;
    uint64_t keyLow = 0;
    //the least significant 16 bits are the last 4 characters of the key
    for (i = 16; i < 32; i++)
        //again, multiplication and addition are done using bitwise left shift and bitwise OR
        keyLow = (keyLow << 4) | (((key[i] >= '0' && key[i] <= '9') ? (key[i] - '0') : (key[i] - 'a' + 10)) & 0xF);
    return keyLow;
}

//Convert words (input) into bytes.
uint32_t Words32ToBytes(uint32_t value) {
    return ((uint32_t) ((uint8_t) value) << 24 | (uint32_t) (uint8_t) (value >> 8) << 16 |
            (uint32_t) (uint8_t) (value >> 16) << 8 | (uint32_t) (uint8_t) (value >> 24));
}

//Covert bytes into words (output).
uint32_t BytesToWords32(uint32_t value)
{
    return ((uint32_t) (uint8_t) (value >> 24) | (uint32_t) (uint8_t) (value >> 16) << 8 |
            (uint32_t) (uint8_t) (value >> 8) << 16 | (uint32_t) ((uint8_t) value) << 24);
}

// function that generates subKeys from the key according to the SPECK key scheduling algorithm for a 128-bit key
uint32_t* generateSubkeys(char* key){
    //the 128 bit key is placed in two integers, both of them are 64 bit
    uint64_t KeyHigh = fromHexStringToLong(key);
    uint64_t KeyLow = getKeyLow(key);

    //we allocate space for 27 subkeys, since there are 27 rounds
    uint32_t *roundKeys = malloc(44 * (sizeof(uint32_t)));
    uint32_t *L = malloc(44 * (sizeof(uint32_t)));

    roundKeys[0] = Words32ToBytes(KeyHigh >> 32);
    L[0] = Words32ToBytes(KeyHigh);
    L[1] = Words32ToBytes(KeyLow >> 32);
    L[2] = Words32ToBytes(KeyLow);

    for(uint32_t i=0;i<27;i++) {
        L[i+m-1] = (roundKeys[i] + ROR(L[i],alpha)) ^ i;
        roundKeys[i+1] = ROL(roundKeys[i], peta) ^ L[i+m-1];
    }

//        for (int i = 0; i < 27; i++) {
//        printf("roundKeys[%d] = %" PRIx32 "\n", i, roundKeys[i]);
//        }
return roundKeys;

}
// function for encrypting a block using a key
char* encrypt(char* plaintext, char* key){
    //generate the subkeys using the function defined above
    uint32_t *roundKeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(plaintext);

    uint32_t rightPlainBlock = Words32ToBytes(state >> 32);
    uint32_t leftPlainBlock = Words32ToBytes(state);

    for(int i = 0 ; i < 27 ;i++)
    {
        leftPlainBlock = (ROR(leftPlainBlock, alpha) + rightPlainBlock) ^ roundKeys[i];
        rightPlainBlock = ROL(rightPlainBlock, peta) ^ leftPlainBlock;
//        printf("cipher round [%d] = %" PRIx32 ", %" PRIx32 "\n", i, leftPlainBlock, rightPlainBlock);
    }

    state = state & 0;
    state = ((state | leftPlainBlock) << 32) | rightPlainBlock;
    return fromLongToHexString(state);

}
// function for decrypting a block using a key
char* decrypt(char* ciphertext, char* key){
//generate the subkeys using the function defined above
    uint32_t *roundKeys = generateSubkeys(key);
    //convert the plaintext from a Hex String to a 64-bit integer
    uint64_t state = fromHexStringToLong(ciphertext);
    //split block of plain text into 2 blocks.
    uint32_t rightCipherBlock = state;
    uint32_t leftCipherBlock = state >> 32;
    for (int i = 26; i >= 0; i--) {
        rightCipherBlock = ROR((rightCipherBlock ^ leftCipherBlock),peta);
        leftCipherBlock = ROL(((leftCipherBlock ^ roundKeys[i]) - rightCipherBlock), alpha);
        printf("cipher round [%d] = %" PRIx32 ", %" PRIx32 "\n", i, leftCipherBlock, rightCipherBlock);
    }


    state = state & 0;
    state = ((state | BytesToWords32(rightCipherBlock)) << 32) | BytesToWords32(leftCipherBlock);

    return fromLongToHexString(state);

}

// Test main function
int main(){
    //declare a pointer and allocate memory for the plaintext (1 block) and the key
    char *plaintext = malloc(17 * sizeof(char));
    char *key = malloc(21 * sizeof(char));

    //declare a pointer for the ciphertext
    char *ciphertext;
    //code for entering the plaintext and the key
    printf("Enter the plaintext (64 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(plaintext);
    printf("Enter the key (80 bits) in hexadecimal format\nUse lower case characters and enter new line at the end\n");
    gets(key);
//    plaintext = "2d4375747465723b";
//    key = "0001020308090a0b1011121318191a1b";
    //calling the encrypt function
    ciphertext = encrypt(plaintext, key);
    //printing the result
    printf("The ciphertext is: ");
    puts(ciphertext);
    printf("The decrypted plaintext is: ");
    //calling the decrypt function and printing the result
    puts(decrypt(ciphertext, key));
    //freeing the allocated memory
    free(key);
    free(plaintext);
    free(ciphertext);
    return 0;
}