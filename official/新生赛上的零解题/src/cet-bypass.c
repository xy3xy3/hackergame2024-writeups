// Compiled with:
//      g++ -no-pie -Wl,-z,relro,-z,now ./chall2.c -o ./chall2
// Compiled in ubuntu:24.04

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define PATH_MAX 0x100

const char *blacklist[] = {"/flag", "/flag1", "/flag2"};
size_t blacklist_size = sizeof(blacklist) / sizeof(blacklist[0]);

void setup() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

int is_forbidden(const char *path) {
    for (size_t i = 0; i < blacklist_size; ++i) {
        if (strcmp(path, blacklist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void gift1() {
    char filename[PATH_MAX];
    printf("\tEnter a filename: ");
    scanf("%32s", filename);

    char resolved_path[PATH_MAX];
    if (realpath(filename, resolved_path) == NULL) {
        exit(-1);
    }

    if (is_forbidden(resolved_path)) {
        fprintf(stderr, "Nice try. But don't try again.\n");
        exit(-1);
    }

    int fd = open(resolved_path, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) {
        exit(-1);
    }

    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    if (bytes_read == -1) {
        exit(-1);
    }

    close(fd);
}

void gift2() {
    size_t addr, data;

    printf("\tEnter the address: ");
    scanf("%lu", &addr);
    printf("\tEnter the data: ");
    scanf("%lu", &data);
    *(char *)addr = data;
}

void vuln(char *win_buf) {
    size_t buf[2];
    strcpy(win_buf, "Good game.");

    for (int i = 0; i < 0x100 / sizeof(size_t); i++) {

        scanf("%lu", &(buf[i]));
        /* while (getchar() != '\n' && getchar() != EOF) */
        /*     ; */
        /* i--; */

        if (buf[i] == 0x31337) {
            puts("Gift 1 - Load a file.");
            gift1();
            puts("Gift 2 - Change 1 byte wherever you want.");
            gift2();

            throw win_buf;
        }
    }
}

void banner() {
    try {

        // clang-format off
        puts("   ,--,                                                ");
        puts(",---.'|                                  ,--.          ");
        puts("|   | :                  ,----..     ,--/  /|          ");
        puts(":   : |            ,--, /   /   \\ ,---,': / '    ,---, ");
        puts("|   ' :          ,'_ /||   :     ::   : '/ /    /_ ./| ");
        puts(";   ; '     .--. |  | :.   |  ;. /|   '   ,---, |  ' : ");
        puts("'   | |__ ,'_ /| :  . |.   ; /--` '   |  /___/ \\.  : | ");
        puts("|   | :.'||  ' | |  . .;   | ;    |   ;  ;.  \\  \\ ,' ' ");
        puts("'   :    ;|  | ' |  | ||   : |    :   '   \\\\  ;  `  ,' ");
        puts("|   |  ./ :  | | :  ' ;.   | '___ |   |    '\\  \\    '  ");
        puts(";   : ;   |  ; ' |  | ''   ; : .'|'   : |.  \\'  \\   |  ");
        puts("|   ,/    :  | : ;  ; |'   | '/  :|   | '_\\.' \\  ;  ;  ");
        puts("'---'     '  :  `--'   \\   :    / '   : |      :  \\  \\ ");
        puts("          :  ,      .-./\\   \\ .'  ;   |,'       \\  ' ; ");
        puts("           `--`----'     `---`    '---'          `--`  ");
        puts("                                                       ");

        puts("\t                                                                            ");
        puts("\t         ,--.                        ____                                   ");
        puts("\t       ,--.'|                      ,'  , `.    ,---,.     ,---,.,-.----.    ");
        puts("\t   ,--,:  : |         ,--,      ,-+-,.' _ |  ,'  .'  \\  ,'  .' |\\    /  \\   ");
        puts("\t,`--.'`|  ' :       ,'_ /|   ,-+-. ;   , ||,---.' .' |,---.'   |;   :    \\  ");
        puts("\t|   :  :  | |  .--. |  | :  ,--.'|'   |  ;||   |  |: ||   |   .'|   | .\\ :  ");
        puts("\t:   |   \\ | :,'_ /| :  . | |   |  ,', |  '::   :  :  /:   :  |-,.   : |: |  ");
        puts("\t|   : '  '; ||  ' | |  . . |   | /  | |  ||:   |    ; :   |  ;/||   |  \\ :  ");
        puts("\t'   ' ;.    ;|  | ' |  | | '   | :  | :  |,|   :     \\|   :   .'|   : .  /  ");
        puts("\t|   | | \\   |:  | | :  ' ; ;   . |  ; |--' |   |   . ||   |  |-,;   | |  \\  ");
        puts("\t'   : |  ; .'|  ; ' |  | ' |   : |  | ,    '   :  '; |'   :  ;/||   | ;\\  \\ ");
        puts("\t|   | '`--'  :  | : ;  ; | |   : '  |/     |   |  | ; |   |    \\:   ' | \\.' ");
        puts("\t'   : |      '  :  `--'   \\;   | |`-'      |   :   /  |   :   .':   : :-'   ");
        puts("\t;   |.'      :  ,      .-./|   ;/          |   | ,'   |   | ,'  |   |.'     ");
        puts("\t'---'         `--`----'    '---'           `----'     `----'    `---'       ");
        puts("\t                                                                            ");
        // clang-format on

        puts("================ Make ROP Great Again! ================");

        puts("Please share your lucky number.");
        puts("I won’t stop reading until I receive the correct one.");

    } catch (const char *data) {
        system(data);
    }
}

int main() {
    char win_buf[0x10];

    setup();
    banner();
    try {
        vuln(win_buf);
    } catch (const char *data) {
        puts(data);
    }

    return 0;
}
