// Compiled with:
//      g++ -static -Wl,-z,relro,-z,now -masm=intel ./chall1.c -o ./chall1
// Compiled in ubuntu:22.04

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

int ssp;
size_t *stack_buf;
size_t temp_num;

void setup() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);

    stack_buf =
        (size_t *)mmap((void *)(0x31336 << 12), 0x8000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_buf == MAP_FAILED)
        exit(-1);
    ssp = 0x1000 / sizeof(size_t);
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
        puts("========== Try to bypass canary without leak! =========");

        puts("Please share your lucky number.");
        puts("I won’t stop reading until I receive the correct one.");

    } catch (int x) {
        puts("What?");
    }
}

void vuln() {
    __asm__("mov r14, qword ptr [rbp + 8];"
            "mov temp_num, r14;");
    stack_buf[ssp++] = temp_num;
    size_t buf[2];

    for (int i = 0; i < 0x100 / sizeof(size_t); i++) {

        if (scanf("%lu", &temp_num) != 1) {
            while (getchar() != '\n' && getchar() != EOF)
                ;
            i--;
            continue;
        }

        if (temp_num == 0x31337) {
            break;
        }

        buf[i] = temp_num;
    }

    __asm__("mov r14, qword ptr [rbp + 8];"
            "mov temp_num, r14;");
    if (temp_num != stack_buf[ssp - 1])
        throw 1;
}

int main() {

    setup();
    banner();
    try {
        while (1) {
            vuln();
            puts("Alright, even if you guessed it right, I won't stop—the next "
                 "round has begun.");
        }
    } catch (int x) {
        puts("Hacker!");
    }

    return 0;
}
