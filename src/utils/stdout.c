#include <stdio.h>

void reset_color() {
    printf("\033[0m");
}

void set_stdout_color(const char* color) {
    printf("\033%s", color);
}

void print_char(const char* c, int n) {
    for (int i = 0; i < n; ++i) {
        printf(c);
    }
}
