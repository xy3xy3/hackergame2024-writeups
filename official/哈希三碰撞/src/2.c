#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#define MAX_INPUT_BYTES 1000
#define MAX_HEX_INPUT (MAX_INPUT_BYTES * 2)
#define ROUNDS 100
#define PATHS 100
#define MAX_PATH_LENGTH 100

int hex_to_bin(const char *hex, unsigned char *bin, size_t *bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len > MAX_HEX_INPUT) {
        return -1;
    }
    size_t bytes_len = hex_len / 2;
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) {
            return -1;
        }
        bin[i] = (unsigned char)byte;
    }
    *bin_len = bytes_len;
    return 0;
}

void trim_newline(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n') {
        str[len - 1] = '\0';
    }
}

typedef struct {
    unsigned char salt1[MAX_INPUT_BYTES];
    size_t salt1_len;
    unsigned char salt2[MAX_INPUT_BYTES];
    size_t salt2_len;
} SaltPair;

typedef struct {
    SaltPair salts[MAX_PATH_LENGTH];
    int length;
} Path;

Path paths[PATHS];
Path path;

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    unsigned char base[SHA256_DIGEST_LENGTH];
    unsigned char s1[SHA256_DIGEST_LENGTH], s2[SHA256_DIGEST_LENGTH];
    unsigned char buf1[2 * MAX_INPUT_BYTES + SHA256_DIGEST_LENGTH];
    unsigned char buf2[2 * MAX_INPUT_BYTES + SHA256_DIGEST_LENGTH];
    size_t len1, len2;
    char input_hex[MAX_HEX_INPUT + 2];

    printf("Initial data: ");
    if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }
    trim_newline(input_hex);
    unsigned char initial_input[MAX_INPUT_BYTES];
    size_t initial_input_len;
    if (hex_to_bin(input_hex, initial_input, &initial_input_len) != 0) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }
    SHA256(initial_input, initial_input_len, base);
    memcpy(s1, base, SHA256_DIGEST_LENGTH);
    memcpy(s2, base, SHA256_DIGEST_LENGTH);

    for (int i = 0; i < ROUNDS; i++) {
        unsigned char salt1[MAX_INPUT_BYTES], salt2[MAX_INPUT_BYTES];
        unsigned char salt3[MAX_INPUT_BYTES], salt4[MAX_INPUT_BYTES];
        size_t salt1_len, salt2_len, salt3_len, salt4_len;

        printf("Round %d\n", i + 1);

        printf("Salt 1: ");
        if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        trim_newline(input_hex);
        if (hex_to_bin(input_hex, salt1, &salt1_len) != 0) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }

        printf("Salt 2: ");
        if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        trim_newline(input_hex);
        if (hex_to_bin(input_hex, salt2, &salt2_len) != 0) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }

        printf("Salt 3: ");
        if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        trim_newline(input_hex);
        if (hex_to_bin(input_hex, salt3, &salt3_len) != 0) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }

        printf("Salt 4: ");
        if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        trim_newline(input_hex);
        if (hex_to_bin(input_hex, salt4, &salt4_len) != 0) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }

        if (salt1_len != salt3_len || salt2_len != salt4_len) {
            fprintf(stderr, "Length should be equal\n");
            return 1;
        }

        len1 = salt1_len + SHA256_DIGEST_LENGTH + salt2_len;
        memcpy(buf1, salt1, salt1_len);
        memcpy(buf1 + salt1_len, s1, SHA256_DIGEST_LENGTH);
        memcpy(buf1 + salt1_len + SHA256_DIGEST_LENGTH, salt2, salt2_len);
        SHA256(buf1, len1, s1);

        len2 = salt3_len + SHA256_DIGEST_LENGTH + salt4_len;
        memcpy(buf2, salt3, salt3_len);
        memcpy(buf2 + salt3_len, s2, SHA256_DIGEST_LENGTH);
        memcpy(buf2 + salt3_len + SHA256_DIGEST_LENGTH, salt4, salt4_len);
        SHA256(buf2, len2, s2);

        if (memcmp(s1, s2, SHA256_DIGEST_LENGTH) == 0) {
            fprintf(stderr, "Hash should be different\n");
            return 1;
        }
    }

    if (memcmp(s1 + SHA256_DIGEST_LENGTH - 8, s2 + SHA256_DIGEST_LENGTH - 8, 8) == 0 &&
        memcmp(s1 + SHA256_DIGEST_LENGTH - 8, base + SHA256_DIGEST_LENGTH - 8, 8) == 0) {
        FILE *fp = fopen("flag2", "r");
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
        return 1;
    }

    unsigned char magic_input[MAX_INPUT_BYTES];
    size_t magic_input_len;
    unsigned char magic[SHA256_DIGEST_LENGTH];

    printf("Magic data: ");
    if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }
    trim_newline(input_hex);
    if (hex_to_bin(input_hex, magic_input, &magic_input_len) != 0) {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }
    SHA256(magic_input, magic_input_len, magic);

    int num_paths = 0;

    for (int i = 0; i < PATHS; i++) {
        printf("How many rounds for path %d: ", i + 1);
        if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
            fprintf(stderr, "Invalid input\n");
            return 1;
        }
        trim_newline(input_hex);

        char *endptr;
        long n = strtol(input_hex, &endptr, 10);
        if (*endptr != '\0' || n <= 0 || n > MAX_PATH_LENGTH) {
            fprintf(stderr, "Invalid number of rounds\n");
            return 1;
        }

        unsigned char s[SHA256_DIGEST_LENGTH];
        memcpy(s, magic, SHA256_DIGEST_LENGTH);

        path.length = (int)n;

        for (int j = 0; j < n; j++) {
            unsigned char salt1[MAX_INPUT_BYTES], salt2[MAX_INPUT_BYTES];
            size_t salt1_len, salt2_len;

            printf("Round %d\n", j + 1);

            printf("Salt 1: ");
            if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
                fprintf(stderr, "Invalid input\n");
                return 1;
            }
            trim_newline(input_hex);
            if (hex_to_bin(input_hex, salt1, &salt1_len) != 0) {
                fprintf(stderr, "Invalid input\n");
                return 1;
            }

            printf("Salt 2: ");
            if (fgets(input_hex, sizeof(input_hex), stdin) == NULL) {
                fprintf(stderr, "Invalid input\n");
                return 1;
            }
            trim_newline(input_hex);
            if (hex_to_bin(input_hex, salt2, &salt2_len) != 0) {
                fprintf(stderr, "Invalid input\n");
                return 1;
            }

            memcpy(path.salts[j].salt1, salt1, salt1_len);
            path.salts[j].salt1_len = salt1_len;
            memcpy(path.salts[j].salt2, salt2, salt2_len);
            path.salts[j].salt2_len = salt2_len;

            unsigned char buffer[2 * MAX_INPUT_BYTES + SHA256_DIGEST_LENGTH];
            size_t buf_len = salt1_len + SHA256_DIGEST_LENGTH + salt2_len;
            memcpy(buffer, salt1, salt1_len);
            memcpy(buffer + salt1_len, s, SHA256_DIGEST_LENGTH);
            memcpy(buffer + salt1_len + SHA256_DIGEST_LENGTH, salt2, salt2_len);

            SHA256(buffer, buf_len, s);
        }

        if (memcmp(s, base, SHA256_DIGEST_LENGTH) != 0) {
            fprintf(stderr, "Hash does not match\n");
            return 1;
        }

        int is_duplicate = 0;
        for (int k = 0; k < num_paths; k++) {
            if (paths[k].length != path.length) {
                continue;
            }
            int same = 1;
            for (int l = 0; l < path.length; l++) {
                if (paths[k].salts[l].salt1_len != path.salts[l].salt1_len ||
                    memcmp(paths[k].salts[l].salt1, path.salts[l].salt1, path.salts[l].salt1_len) != 0 ||
                    paths[k].salts[l].salt2_len != path.salts[l].salt2_len ||
                    memcmp(paths[k].salts[l].salt2, path.salts[l].salt2, path.salts[l].salt2_len) != 0) {
                    same = 0;
                    break;
                }
            }
            if (same) {
                is_duplicate = 1;
                break;
            }
        }

        if (is_duplicate) {
            fprintf(stderr, "Duplicate path\n");
            return 1;
        }

        paths[num_paths++] = path;
    }

    FILE *fp = fopen("flag3", "r");
    if (fp == NULL) {
        fprintf(stderr, "Can't open file\n");
        return 1;
    }
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        putchar(ch);
    }
    fclose(fp);

    return 0;
}
