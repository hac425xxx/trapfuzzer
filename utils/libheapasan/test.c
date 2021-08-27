#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>

int test_func()
{
    puts("test_func");
    void *tbl[20] = {0};
    for (size_t i = 0; i < 20; i++)
    {
        tbl[i] = malloc(21);
    }

    // char* p = tbl[2];

    // p[0x20] = 0;

    for (size_t i = 0; i < 20; i++)
    {
        tbl[i] = realloc(tbl[i], 0x42);
    }

    for (size_t i = 0; i < 20; i++)
    {
        free(tbl[i]);
    }

    for (size_t i = 0; i < 20; i++)
    {
        tbl[i] = realloc(NULL, 0x42);
    }

    for (size_t i = 0; i < 20; i++)
    {
        free(tbl[i]);
    }

    for (size_t i = 0; i < 20; i++)
    {
       tbl[i] = calloc(23, 0x42);
    }

    for (size_t i = 0; i < 20; i++)
    {
        free(tbl[i]);
    }

    return 0;
}

int main()
{
    puts("in main");
    test_func();
}