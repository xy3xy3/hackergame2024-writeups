#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_size) {
    size_t len = strlen(hex);
    if (len != bin_size * 2) {
        return -1;
    }
    for (size_t i = 0; i < bin_size; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        bin[i] = (unsigned char)byte;
    }
    return 0;
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char input[3][17];
    unsigned char data[3][8];
    unsigned char hash[3][SHA256_DIGEST_LENGTH];
    uint32_t last4bytes[3];

    for (int i = 0; i < 3; i++) {
        printf("Data %d:", i + 1);
        if (scanf("%16s", input[i]) != 1) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        if (hex_to_bin(input[i], data[i], 8) != 0) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
    }

    if ((strcmp(input[0], input[1]) == 0) || (strcmp(input[0], input[2]) == 0) || (strcmp(input[1], input[2]) == 0)) {
        printf("Input should be different\n");
        return 1;
    }

    for (int i = 0; i < 3; i++) {
        SHA256(data[i], 8, hash[i]);
        last4bytes[i] = 0;
        for (int j = 0; j < 4; j++) {
            last4bytes[i] = (last4bytes[i] << 8) | hash[i][SHA256_DIGEST_LENGTH - 4 + j];
        }
    }

    if (last4bytes[0] == last4bytes[1] && last4bytes[1] == last4bytes[2]) {
        FILE *fp = fopen("flag1", "r");
        if (fp == NULL) {
            fprintf(stderr, "Can't open file\n");
            return 1;
        }
        int ch;
        while ((ch = fgetc(fp)) != EOF) {
            putchar(ch);
        }
        fclose(fp);
    } else {
        printf("Wrong answer\n");
    }

    return 0;
}
