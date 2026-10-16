#include <stdio.h>

extern int asm4(const char *str);

int main() {
    printf("0x%x\n", asm4("academy_7749b"));
    return 0;
}
