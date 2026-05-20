/* Example vulnerable C code — CWE-787 OOB write via strcpy. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void greet(const char *name) {
    char buf[16];
    /* CWE-787: no bounds check */
    strcpy(buf, name);
    printf("Hello, %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        greet(argv[1]);
    }
    return 0;
}
