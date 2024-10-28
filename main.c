/*
 *                                                DES Encryption/Decryption
 *  							  Team : 5
 *      								          +--------------+
 *  								       	          |  64 bit Key  |
 *  								       	          +--------------+
 *  								       			|
 *  								       	     +---------------------+
 *  								       	  ---|  Permuted Choice 1  |---  >>> 56 bit Key
 *  								       	  |  +---------------------+  |
 *  								       	  |                           |
 *  								       	  |                           |
 *  								       	  |                           |
 *      		<--32 bit->	<--32 bit->			<--28 bit->		  <--28 bit->
 *  			+----------+    +----------+                   +----------+               +----------+
 *  			|  L(i-1)  |    |  R(i-1)  |                   |  C(i-1)  |               |  D(i-1)  |
 *  			+----------+    +----------+                   +----------+               +----------+
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  			     |               |                              |                          |
 *  	        -----------------------------|                              |                          |
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
 *  		|            |----------|    XOR   |          |                                                       |
 *  		|	                +-----+----+          |                                                       |
 *  		|	                     |                |                                                       |
 *  		|		             +                |                                                       |
 *  		|	                     |                |                                                       |
 *  	+----------+                   +----------+     +-------------+                                      +-------------+
 *  	|  L(i)    |                   |   R(i)   |     |    C(i)     |                                      |    D(i)     |
 *  	+----------+                   +----------+     +-------------+                                      +-------------+
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LOOP(i, n) for (unsigned char i = 0; i < (n); ++i)
#define SET_BIT(output, input, i) (*output |= (((*input) >> (64 - initial_permutation_table[i])) & 1) << (63 - i))
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
const unsigned char final_permutation_table[64] = {40, 8, 48, 16, 56, 24, 64, 32,
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

// Initial Permutation Inverse Table
const unsigned char initial_permutation_inverse_table[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                                                   39, 7, 47, 15, 55, 23, 63, 31,
                                                   38, 6, 46, 14, 54, 22, 62, 30,
                                                   37, 5, 45, 13, 53, 21, 61, 29,
                                                   36, 4, 44, 12, 52, 20, 60, 28,
                                                   35, 3, 43, 11, 51, 19, 59, 27,
                                                   34, 2, 42, 10, 50, 18, 58, 26,
                                                   33, 1, 41, 9, 49, 17, 57, 25};

// ##################################################################################################################
// ##################################################################################################################


// ##################################################################################################################
// Function Prototypes
// ##################################################################################################################

void hex_to_bin(char *hex, char *bin);

void bin_to_hex(char *bin, char *hex);

void readFile(char *filename, char *buffer, unsigned char size);

void writeFile(char *filename, char *buffer, unsigned char size);

void initial_permutation(char *input, char *output);

void final_permutation(char *input, char *output);

void expansion_d_box(char *input, char *output);

void straight_permutation(char *input, char *output);

void permuted_choice_1(char *key, char *c, char *d);

void permuted_choice_2(char *c, char *d, char *key);

void left_shift(char *key, unsigned char key_size, unsigned char shift);

void generate_keys(char *key, char keys[16][48]);

void xor(char *a, char *b, unsigned char size);

void swap(char *a, char *b, unsigned char size);

void s_box(char *input, char *output);

void f_function(char *right, char *key, char *output);

void encrypt(char *plain_text, char keys[16][48], char *cipher_text);

void decrypt(char *cipher_text, char keys[16][48], char *plain_text);

// ##################################################################################################################

// ##################################################################################################################
// Main Function
// ##################################################################################################################

void main()
{

}

// ##################################################################################################################

// ##################################################################################################################
// Function Definitions
// ##################################################################################################################

void hex_to_bin(char *hex, char *bin) {

    const char *hex_to_bin_table[16] = {
        "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", // 0-7
        "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"  // 8-F
    };

    bin[0] = '\0';

    for (int i = 0; hex[i] != '\0'; i++) {
        char hex_digit = hex[i];
        int index;

        if (hex_digit >= '0' && hex_digit <= '9') {
            index = hex_digit - '0';
        } else if (hex_digit >= 'A' && hex_digit <= 'F') {
            index = hex_digit - 'A' + 10;
        } else if (hex_digit >= 'a' && hex_digit <= 'f') {
            index = hex_digit - 'a' + 10;
        } else {
            printf("Error: Invalid hex character %c\n", hex_digit);
            return;
        }
        strcat(bin, hex_to_bin_table[index]);
    }
}

void bin_to_hex(char *bin, char *hex) {
    int len = strlen(bin);
    if (len % 4 != 0) {
        printf("Error: Binary string length must be a multiple of 4.\n");
        return;
    }

    const char bin_to_hex_table[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    int hex_index = 0;

    for (int i = 0; i < len; i += 4) {
        int value = 0;

        for (int j = 0; j < 4; j++) {
            value = (value << 1) | (bin[i + j] - '0');
        }

        hex[hex_index++] = bin_to_hex_table[value];
    }

    hex[hex_index] = '\0';
}

void readFile(char *filename, char *buffer, unsigned char size) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Unable to open file %s\n", filename);
        return;
    }

    fread(buffer, 1, size, file);
    fclose(file);
}

void writeFile(char *filename, char *buffer, unsigned char size) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("Error: Unable to open file %s\n", filename);
        return;
    }

    fwrite(buffer, 1, size, file);
    fclose(file);
}

void initial_permutation(char *input, char *output) {
    LOOP(i, 64) {
        // Extract the bit from input using the permutation table
        *output |= ((*input >> (64 - initial_permutation_table[i])) & 1)<< (63 - i);
        // Set the corresponding bit in output
        *output |= (bit << (63 - i));
    }
    output[64] = '\0';
}


