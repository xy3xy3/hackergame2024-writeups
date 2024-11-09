/* Compiled with: */
/*      gcc -no-pie -z now -masm=intel ./chal.c -o ./chal */
/* Compiled in docker ubuntu:20.04 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#define MAX_STU_NUM 0x100

struct {
        int (*sort_func)(const void *const, const void *const);
        double temp_sort_array[MAX_STU_NUM];
} gms;

void *unused() { return NULL; }
void doredolaso() {
    __asm__("add rsp, 8;"
            "jmp [rsi];");
}
void why_theres_a_b4ckd00r_in_my_GMS() {
    puts("獎一個 🌸⌚️");
    system("echo 🌸⌚️");
}

void inits() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}

void banner() {
    puts("===================================================");
    puts("        Our QuickSort Indeed Has Problems          ");
    puts("     gpasortings Ystemth At Utilizes quicksort     ");
    puts("===================================================");
}

void disable_malloc() {
    /* 我認為 malloc 應該被取消調用資格 */
    size_t puts_addr = (size_t)&puts;
    size_t malloc_hook_addr = puts_addr + 0x168750;
    *(size_t *)malloc_hook_addr = (size_t)&unused;
}

int whos_jipiei_is_better(const void *const pa, const void *const pb) {
    const double a = *(const double *)pa;
    const double b = *(const double *)pb;

    if (!a || !b) {
        return 0;
    }
    if (a < 2.5 || b < 2.5) {
        puts("With such grades, how can we sort them?");
        return -1;
    }
    if (a < b)
        return -1;
    if (a > b)
        return 1;
    return 0;
}

int main() {
    inits();
    banner();
    disable_malloc();

    int student_num;
    char student_num2[0x28];

    puts("Enter student number:");
    scanf("%d", &student_num);
    if (student_num <= 0 || student_num > MAX_STU_NUM) {
        puts("That's too many students! We'll let someone else handle this.");
        return -1;
    }

    puts("Enter the GPA data:");
    for (int i = 0; i < student_num; i++) {
        scanf("%lf", &(gms.temp_sort_array[i]));
    }

    puts("Processing...");
    gms.sort_func = whos_jipiei_is_better;
    qsort(gms.temp_sort_array, student_num, sizeof(double), gms.sort_func);

    puts("Oops, sorting a wrong direction. Processing again...");
    for (int i = 0; i < student_num; i++) {
        scanf("%lf", &(gms.temp_sort_array[i]));
    }
    qsort(gms.temp_sort_array, student_num, sizeof(double), gms.sort_func);

    return 0;
}
