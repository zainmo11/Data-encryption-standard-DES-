// if you view from github, make index space 4 to view the code properly (https://github.com/zainmo11/Data-encryption-standard-DES-/blob/main/main.c?ts=4)
// ##################################################################################################################
/*                                            -------------------------------------
 *                                            |     DES Encryption/Decryption     |
 *  							              |              Team : 28            |
 *  							              |   Abdelrhman Zain Mohamed 2101646 |
 *  							              |   Abdelrhman Atef Saad    2101645 |
 *  							              |  Mahmoud Hamdy Mohamed    2001300 |
 *                                            |  Mohamed Adham Mohamed    2001184 |
 *  							              |  Yassa Sfen Ayed Helmy    2001307 |
 *  							              -------------------------------------
 *
 *
 *      								                                      +--------------+
 *  								                             	          |  64 bit Key  |
 *  								                             	          +--------------+
 *  								                             			         |
 *  								                             	     +---------------------+
 *  								                             	  ---|  Permuted Choice 1  |---  >>> 56 bit Key
 *  								                             	  |  +---------------------+  |
 *  								                             	  |                           |
 *  								                             	  |                           |
 *  								                             	  |                           |
 *      		<--32 bit->	    <--32 bit->			           <--28 bit->		          <--28 bit->
 *  			+----------+    +----------+                   +----------+               +----------+
 *  			|  L(i-1)  |    |  R(i-1)  |                   |  C(i-1)  |               |  D(i-1)  |
 *  			+----------+    +----------+                   +----------+               +----------+
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  	    -------------------------|                              |                          |
 *        	|	     |        +------+-------+            +--------------------+      +--------------------+
 *  		|	     |        | Expansion    |        ----|  Left Shift(s)     |      |    Left Shift(s)   |---
 *  		|	     |        | Permutation  |        |   +--------------------+      +--------------------+  |
 *  		|	     |        |    (E)       |        |                 |               |                     |
 *  		|	     |        +------+-------+        |                 |               |                     |
 *  		|	     |               |                |                 |               |                     |
 *  		|	     |            48 bits             |                 |               |                     |
 *  		|	     |               |                |                 |               |                     |
 *  		|	     |          +-----+----+          |               +--------------------+                  |
 *  		|	     |          |    XOR   |--------------------------|  Permuted Choice 2 |                  |
 *  		|	     |          +-----+----+          |               +--------------------+                  |
 *  		|	     |                |               |                                                       |
 *  		|	     |             48 bits            |                                                       |
 *  		|	     |                |               |                                                       |
 *  		|	     |   +------------+------------+  |                                                       |
 *  		|	     |   |  Substitution (S-box)   |  |                                                       |
 *  		|	     |   +------------+------------+  |                                                       |
 *  		|	     |                |               |                                                       |
 *  		|	     |             32 bits            |                                                       |
 *  		|	     |                |               |                                                       |
 *  		|	     |         +------+-------+       |                                                       |
 *  		|	     |         |  Permutation |       |                                                       |
 *  		|	     |         |    (P)       |       |                                                       |
 *  		|	     |         +------+-------+       |                                                       |
 *  		|	     |                |               |                                                       |
 *  		|	     |          +-----+----+          |                                                       |
 *          |        |----------|    XOR   |          |                                                       |
 *  		|	                +-----+----+          |                                                       |
 *  		|	                     |                |                                                       |
 *          |                        +                |                                                       |
 *  		|	                     |                |                                                       |
 *  	+----------+            +----------+     +-------------+                                      +-------------+
 *  	|  L(i)    |            |   R(i)   |     |    C(i)     |                                      |    D(i)     |
 *  	+----------+            +----------+     +-------------+                                      +-------------+
 *
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define LOOP(i, n) for (unsigned char i = 0; i < (n); ++i)
#define SET_BIT(output, input, i, table, x, y) (*output) |= (((input) >> (x - table[i])) & 1) << (y - i)
#define FIXED_SIZE 1024

// ##################################################################################################################
// Constants and Tables
// ##################################################################################################################

// Initial Permutation Table
const unsigned char initial_permutation_table[64] = {58, 50, 42, 34, 26, 18, 10, 2,
                                                     60, 52, 44, 36, 28, 20, 12, 4,
                                                     62, 54, 46, 38, 30, 22, 14, 6,
                                                     64, 56, 48, 40, 32, 24, 16, 8,
                                                     57, 49, 41, 33, 25, 17, 9, 1,
                                                     59, 51, 43, 35, 27, 19, 11, 3,
                                                     61, 53, 45, 37, 29, 21, 13, 5,
                                                     63, 55, 47, 39, 31, 23, 15, 7};

// Final Permutation Table
const unsigned char Final_permutation[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                                                             39, 7, 47, 15, 55, 23, 63, 31,
                                                             38, 6, 46, 14, 54, 22, 62, 30,
                                                             37, 5, 45, 13, 53, 21, 61, 29,
                                                             36, 4, 44, 12, 52, 20, 60, 28,
                                                             35, 3, 43, 11, 51, 19, 59, 27,
                                                             34, 2, 42, 10, 50, 18, 58, 26,
                                                             33, 1, 41, 9, 49, 17, 57, 25};

// Expansion D-box Table
const unsigned char expansion_d_box_table[48] = {32, 1, 2, 3, 4, 5, 4, 5,
                                                 6, 7, 8, 9, 8, 9, 10, 11,
                                                 12, 13, 12, 13, 14, 15, 16, 17,
                                                 16, 17, 18, 19, 20, 21, 20, 21,
                                                 22, 23, 24, 25, 24, 25, 26, 27,
                                                 28, 29, 28, 29, 30, 31, 32, 1};

// S-box Table
const unsigned char s_box_table[8][4][16] = {
        // S1
        {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        // S2
        {
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        // S3
        {
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9 , 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15,1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        // S4
        {
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        // S5
        {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        // S6
        {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        // S7
        {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        // S8
        {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
};

// Straight Permutation Table
const unsigned char straight_permutation_table[32] = {16, 7, 20, 21,
                                                      29, 12, 28, 17,
                                                      1, 15, 23, 26,
                                                      5, 18, 31, 10,
                                                      2, 8, 24, 14,
                                                      32, 27, 3, 9,
                                                      19, 13, 30, 6,
                                                      22, 11, 4, 25};

// Permuted Choice 1 Table
const unsigned char permuted_choice_1_table[56] = {57, 49, 41, 33, 25, 17, 9,
                                                   1, 58, 50, 42, 34, 26, 18,
                                                   10, 2, 59, 51, 43, 35, 27,
                                                   19, 11, 3, 60, 52, 44, 36,
                                                   63, 55, 47, 39, 31, 23, 15,
                                                   7, 62, 54, 46, 38, 30, 22,
                                                   14, 6, 61, 53, 45, 37, 29,
                                                   21, 13, 5, 28, 20, 12, 4};

// Permuted Choice 2 Table
const unsigned char permuted_choice_2_table[48] = {14, 17, 11, 24, 1, 5,
                                                   3, 28, 15, 6, 21, 10,
                                                   23, 19, 12, 4, 26, 8,
                                                   16, 7, 27, 20, 13, 2,
                                                   41, 52, 31, 37, 47, 55,
                                                   30, 40, 51, 45, 33, 48,
                                                   44, 49, 39, 56, 34, 53,
                                                   46, 42, 50, 36, 29, 32};

// Left Shift Table
const unsigned char left_shift_table[16] = {1, 1, 2, 2,
                                            2, 2, 2, 2,
                                            1, 2, 2, 2,
                                            2, 2, 2, 1};



// ##################################################################################################################
// ##################################################################################################################


// ##################################################################################################################
// Function Prototypes
// ##################################################################################################################

// read and write functions
uint64_t* readFile(const char* filename, char hex, uint64_t* size);

void writeFile(char *filename, const uint64_t *data, char hex, uint64_t size_in_blocks);


// permutation functions
void initial_permutation(uint64_t input, uint64_t *output);

void inverse_initial_permutation(uint64_t input, uint64_t *output);

void expansion_d_box(uint64_t input, uint64_t *output);

void straight_permutation(uint64_t input, uint64_t *output);

void permuted_choice_1(uint64_t key, uint64_t *c, uint64_t *d);

void permuted_choice_2(uint64_t c, uint64_t d, uint64_t *key);

// key generation functions
void left_shift(uint64_t *key, unsigned char round);

void generate_keys(uint64_t key, uint64_t keys[16]);

// encryption functions
void xor(uint64_t a, uint64_t b, uint64_t *result);

void swap(uint64_t *a, uint64_t *b);

void s_box(uint64_t input, uint64_t *output);

void f_function(uint64_t right, uint64_t key, uint64_t *output);

void encrypt(uint64_t plain_text, uint64_t keys[16], uint64_t *cipher_text);

void decrypt(uint64_t cipher_text, uint64_t keys[16], uint64_t *plain_text);

// ##################################################################################################################

// ##################################################################################################################
// Main Function
// ##################################################################################################################

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s <mode> <keyfile> <inputfile> <outputfile>\n", argv[0]);
        printf("Modes: 'e' for encryption, 'd' for decryption\n");
        return 1;
    }

    char mode = argv[1][0];
    char *keyFile = argv[2];
    char *inputFile = argv[3];
    char *outputFile = argv[4];

    uint64_t key_size;
    uint64_t size_in_blocks;

    //NOTE: no need to free after reading, file data is stored in static buffers
    //that are automayically destroyed before program termination

    // Read the encryption key from the specified key file (assuming key is 64-bit)
    // I used 'x' to represent anything other than 'e'
    uint64_t* key_ptr = readFile(keyFile, 'x', &key_size);
    uint64_t key = key_ptr[0];

    // Read input file (plaintext for encryption or ciphertext for decryption)
    uint64_t* input_ptr = readFile(inputFile, mode, &size_in_blocks);
    uint64_t result[size_in_blocks];

    // Generate 16 keys for encryption/decryption
    uint64_t keys[16];
    generate_keys(key, keys);

    if (mode == 'e') {
        // Encrypt the plaintext
        for (uint64_t i = 0; i < size_in_blocks; i++)
            encrypt(input_ptr[i], keys, &result[i]);
        printf("Encrypted successfully.\n");
    } else if (mode == 'd') {
        // Decrypt the ciphertext
        for (uint64_t i = 0; i < size_in_blocks; i++)
            decrypt(input_ptr[i], keys, &result[i]); 
        printf("Decrypted successfully.\n");
    } else {
        printf("Invalid mode. Use 'e' for encryption or 'd' for decryption.\n");
        return 1;
    }

    // Write result to output file (ciphertext for encryption or plaintext for decryption)
    writeFile(outputFile, result, mode, size_in_blocks);

    return 0;
}

// ##################################################################################################################


// ##################################################################################################################
// Function Definitions
// ##################################################################################################################


// NOTE: this doesn't work if file size is not a multiple of 64bits
void writeFile(char *filename, const uint64_t *data, char hex, uint64_t size_in_blocks) {
    // Open file for binary writing
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Error: Unable to open file %s\n", filename);
        return;
    }

    if (hex == 'd') {
        // Write the data in binary mode (byte-by-byte)
        for (size_t i = 0; i < size_in_blocks; i++) {
            // Write 8 bytes (uint64_t) in big-endian order
            for (int j = 7; j >= 0; j--) {
                uint8_t ch = (uint8_t)(data[i] >> (j * 8));
                size_t written = fwrite(&ch, sizeof(uint8_t), 1, file);
                if (written != 1) {
                    perror("Error writing to file");
                    fclose(file);
                    return;
                }
            }
        }
    } else {
        // Write the data in hexadecimal format
        for (size_t i = 0; i < size_in_blocks; i++) {
            // Print each 64-bit value as a 16-character hexadecimal number
            if (fprintf(file, "%016" PRIx64, data[i]) < 0) {
                perror("Error writing hex data to file");
                fclose(file);
                return;
            }
        }
    }

    // Close the file
    fclose(file);
}



uint64_t* readFile(const char* filename, char hex, uint64_t* size) {
    // Open the file
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Error opening file");
        return NULL;
    }

    // Allocate a fixed size for the array
    static uint64_t array[FIXED_SIZE];
    for (size_t i = 0; i < FIXED_SIZE; i++) {
        array[i] = 0;
    }

    if (hex == 'e') {
        // Read the file byte by byte in binary mode
        size_t bit_index = 0;
        uint8_t byte;
        while (fread(&byte, sizeof(uint8_t), 1, fp) == 1 && bit_index < FIXED_SIZE * 64) {
            LOOP(bit, 8) {
                if (bit_index >= FIXED_SIZE * 64) break; // Prevent overflow
                size_t array_index = bit_index / 64;
                size_t bit_pos = bit_index % 64;
                array[array_index] |= ((uint64_t)((byte >> (7 - bit)) & 1)) << (63 - bit_pos);
                bit_index++;
            }
        }
        *size = bit_index / 64;

    } else {
        // Read the file as hexadecimal characters
        size_t byte_index = 0;
        uint8_t byte = 0;
        int byte_count = 0;
        int ch;

        while ((ch = fgetc(fp)) != EOF && byte_index < FIXED_SIZE * 8) {
            if (isxdigit(ch)) {
                byte = (byte << 4) | (isdigit(ch) ? ch - '0' : toupper(ch) - 'A' + 10);
                byte_count++;

                // Store byte once we have two hex digits
                if (byte_count == 2) {
                    size_t array_index = byte_index / 8;
                    if (array_index >= FIXED_SIZE) break; // Prevent overflow
                    size_t byte_pos = 7 - (byte_index % 8);
                    array[array_index] |= ((uint64_t)byte) << (byte_pos * 8);

                    byte_index++;
                    byte_count = 0;
                    byte = 0;
                }
            }
        }
        *size = byte_index / 8;
    }
    fclose(fp);
    return array; // Return the static array
}



void initial_permutation(uint64_t input, uint64_t *output) {
    *output = 0;
    LOOP(i, 64) {
        // Set the i-th bit of the output to the (64 - table[i])th bit of the input
        SET_BIT(output, input, i, initial_permutation_table, 64, 64 - 1);
    }
}

void inverse_initial_permutation(uint64_t input, uint64_t *output) {
    *output = 0;
    LOOP(i, 64) {
        // Set the i-th bit of the output to the (64 - table[i])th bit of the input
        SET_BIT(output, input, i, Final_permutation, 64, 64 - 1);
    }
}

void expansion_d_box(uint64_t input, uint64_t *output) {
    *output = 0;
    LOOP(i, 48) {
        // Set the i-th bit of the output to the (64 - table[i])th bit of the input
        SET_BIT(output, input, i, expansion_d_box_table, 32, 48 - 1);
    }
}

void straight_permutation(uint64_t input, uint64_t *output) {
    *output = 0;
    LOOP(i, 32) {
        // Set the i-th bit of the output to the (64 - table[i])th bit of the input
        SET_BIT(output, input, i, straight_permutation_table, 32, 32 - 1);
    }
}

void permuted_choice_1(uint64_t key, uint64_t *c, uint64_t *d) {
    *c = 0;
    *d = 0;

    LOOP(i, 28) {
        SET_BIT(c, key, i, permuted_choice_1_table, 64, 28 - 1);
    }

    LOOP(i, 28) {
        (*d) |= (((key) >> (64 - permuted_choice_1_table[i + 28])) & 1) << (27 - i);
    }
}

void permuted_choice_2(uint64_t c, uint64_t d, uint64_t *key) {
    *key = 0;
    uint64_t temp = (c << 28) | d;
    LOOP(i, 48) {
        // Set the i-th bit of the output to the (56 - table[i])th bit of the input
        SET_BIT(key, temp, i, permuted_choice_2_table, 56, 48 - 1);
    }
}

void left_shift(uint64_t *key, unsigned char round) {
    unsigned char shift = left_shift_table[round];

    // Perform a left shift by 'shift' bits
    *key = ((*key << shift) & 0xFFFFFFF) | (*key >> (28 - shift));
}

void generate_keys(uint64_t key, uint64_t keys[16]) {
    uint64_t c, d;
    permuted_choice_1(key, &c, &d);

    LOOP(i, 16) {
        left_shift(&c, i);
        left_shift(&d, i);
        permuted_choice_2(c, d, &keys[i]);
    }
}

void xor(uint64_t a, uint64_t b, uint64_t *result) {
    *result = a ^ b;
}

void swap(uint64_t *a, uint64_t *b) {
    uint64_t temp = *a;
    *a = *b;
    *b = temp;
}

void s_box(uint64_t input, uint64_t *output) {
    *output = 0;
    LOOP(i, 8) {
        // Get the 6-bit block from the input
        uint64_t block = (input >> (48 - (i + 1) * 6)) & 0x3F;

        // Get the row and column from the block
        unsigned char row = ((block & 0x20) >> 4) | (block & 1);
        unsigned char col = (block >> 1) & 0xF;

        // Get the value from the S-box
        uint64_t value = s_box_table[i][row][col];

        // Set the 4-bit value to the output
        *output |= value << (32 - (i + 1) * 4);
    }
}

void f_function(uint64_t right, uint64_t key, uint64_t *output) {
    uint64_t expanded_right;
    expansion_d_box(right, &expanded_right);

    uint64_t xored;
    xor(expanded_right, key, &xored);

    uint64_t s_box_output;
    s_box(xored, &s_box_output);

    straight_permutation(s_box_output, output);
}

void encrypt(uint64_t plain_text, uint64_t keys[16], uint64_t *cipher_text) {
    
    uint64_t ip;
    initial_permutation(plain_text, &ip);

    uint64_t l = (ip >> 32) & 0xFFFFFFFF;
    uint64_t r = ip & 0xFFFFFFFF;

    LOOP(i, 16) {
        uint64_t temp = r;
        uint64_t f_output;
        f_function(r, keys[i], &f_output);

        xor(l, f_output, &r);
        l = temp;
    }

    swap(&l, &r);

    *cipher_text = (l << 32) | r;
    inverse_initial_permutation(*cipher_text, cipher_text);
}

void decrypt(uint64_t cipher_text, uint64_t keys[16], uint64_t *plain_text) {
    uint64_t ip;
    initial_permutation(cipher_text, &ip);

    uint64_t l = (ip >> 32) & 0xFFFFFFFF;
    uint64_t r = ip & 0xFFFFFFFF;

    LOOP(i, 16) {
        uint64_t temp = r;
        uint64_t f_output;
        f_function(r, keys[15 - i], &f_output);

        xor(l, f_output, &r);
        l = temp;
    }

    swap(&l, &r);

    *plain_text = (l << 32) | r;
    inverse_initial_permutation(*plain_text, plain_text);
}






