#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

int
main(void)
{
    int size = 1024;
    void *mem = mmap(NULL, size, PROT_READ|PROT_EXEC|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }

    getchar();

    char s[] = "vitooooo";
    for (int i=0; i+5<size; i+=strlen(s)+1)
        strncpy(mem+i, s, size-i);

    getchar();

    munmap(mem, size);

    getchar();

    return 0;
}