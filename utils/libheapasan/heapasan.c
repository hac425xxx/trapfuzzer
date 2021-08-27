#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#include <pthread.h>

#include "salmalloc.h"

pthread_mutex_t g_heapasan_lock = PTHREAD_MUTEX_INITIALIZER;

#define kcalloc(N, Z) salcalloc(N, Z)
#define kmalloc(Z) salmalloc(Z)
#define krealloc(P, Z) salrealloc(P, Z)
#define kfree(P) salfree(P)

#include "khash.h"
#include "plthook.h"

/*
gcc heapasan.c plthook_elf.c salmalloc.c  -o heapasan -ltest -L. -ldl -w -g
LD_LIBRARY_PATH=. ./heapasan

gcc heapasan.c plthook_elf.c salmalloc.c  -shared -fPIC -g -o libheapasan.so -ldl
*/

typedef struct _HEAP
{
    void *pChunkStart;
    unsigned int chunk_size;
    void *pPageStart;
    unsigned int page_size;
} HEAP;

KHASH_MAP_INIT_INT64(HEAP_MAP_DEF, unsigned long);
khash_t(HEAP_MAP_DEF) *HEAP_MAP = NULL;

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

void *inline_hook_unprotect(void *address)
{
    long pagesize;
    pagesize = sysconf(_SC_PAGESIZE);
    address = (void *)((long)address & ~(pagesize - 1));
    if (mprotect(address, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
    {
        return address;
    }
    else
    {
        return NULL;
    }
}

#ifdef __x86_64__

void inline_hook(void *func, void *newAddr)
{
    unsigned char *f = (unsigned char *)func;
    *(unsigned short *)&f[0] = 0x25ff;
    *(unsigned int *)&f[2] = 0x00000000;
    *(unsigned long *)&f[6] = (unsigned long)newAddr;
}
#endif

#ifdef __i386__

void inline_hook(void *func, void *newAddr)
{
    unsigned char *f = (unsigned char *)func;
    f[0] = 0x68;
    *(unsigned long *)&f[1] = (unsigned long)newAddr;
    f[5] = 0xc3;
}
#endif

int my_target()
{
    puts("my_target");
}

int my_hook_func()
{
    puts("my_hook_func");
}

void *heap_asan_alloc(unsigned int size, unsigned int align_size)
{
    unsigned int rlen;
    void *ret;

    if (align_size != 1)
        rlen = (size & ~(align_size - 1)) + align_size;
    else
        rlen = size;

    unsigned int pad_size = PAGE_SIZE - (rlen % PAGE_SIZE);
    unsigned int page_len = rlen + pad_size;

    unsigned int alloc_size = page_len + PAGE_SIZE;

    void *mmap_addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned int rnd = rand() % 2;

    if (rnd)
    {
        mprotect(mmap_addr + page_len, PAGE_SIZE, PROT_NONE);
        ret = mmap_addr + pad_size;
    }
    else
    {
        mprotect(mmap_addr, PAGE_SIZE, PROT_NONE);
        ret = mmap_addr + PAGE_SIZE;
    }

    pthread_mutex_lock(&g_heapasan_lock);

    HEAP *p = (HEAP *)kmalloc(sizeof(HEAP));
    p->pChunkStart = ret;
    p->chunk_size = rlen;
    p->pPageStart = mmap_addr;
    p->page_size = alloc_size;

    int r;
    khiter_t k = kh_put(HEAP_MAP_DEF, HEAP_MAP, (unsigned long)p->pChunkStart, &r);
    kh_value(HEAP_MAP, k) = (unsigned long)p;

    pthread_mutex_unlock(&g_heapasan_lock);

    return p->pChunkStart;
}

void heap_asan_free(char *addr)
{
    if (addr == NULL)
    {
        return;
    }

    pthread_mutex_lock(&g_heapasan_lock);
    khiter_t k = kh_get(HEAP_MAP_DEF, HEAP_MAP, (unsigned long)addr);
    if (k != kh_end(HEAP_MAP))
    {
        HEAP *heap = (HEAP *)kh_value(HEAP_MAP, k);
        munmap(heap->pPageStart, heap->page_size);
        kh_del(HEAP_MAP_DEF, HEAP_MAP, k);
        kfree(heap);
    }
    pthread_mutex_unlock(&g_heapasan_lock);
}

void *my_malloc(unsigned int sz)
{
    // printf("my_malloc:%d\n", sz);
    void * p = heap_asan_alloc(sz, 1);

    if(p)
    {
        memset(p, 0xaf, sz);
    }

    return p;
}

void my_free(void *addr)
{
    // printf("my_free:%p\n", addr);
    heap_asan_free(addr);
}

void *my_calloc(size_t nmemb, size_t size)
{
    size_t sz = nmemb * size;
    // printf("my_calloc:%d\n", sz);
    void *p = heap_asan_alloc(sz, 1);
    if (!p)
        return NULL;

    memset(p, 0, sz);
    return p;
}
void *my_realloc(void *ptr, size_t sz)
{
    // printf("my_realloc(%p, %d)\n", ptr, sz);
    void *p = NULL;

    unsigned int rsz = 0;

    if (ptr != NULL)
    {
        pthread_mutex_lock(&g_heapasan_lock);
        khiter_t k = kh_get(HEAP_MAP_DEF, HEAP_MAP, (unsigned long)ptr);
        if (k != kh_end(HEAP_MAP))
        {
            HEAP *heap = (HEAP *)kh_value(HEAP_MAP, k);
            rsz = heap->chunk_size;
        }
        pthread_mutex_unlock(&g_heapasan_lock);
    }

    p = heap_asan_alloc(sz, 1);
    if (p != NULL)
    {   
        memset(p, 0xa2, sz);
        
        if (sz > rsz)
            memcpy(p, ptr, rsz);
        else
            memcpy(p, ptr, sz);
    }

    heap_asan_free(ptr);
    return p;
}

int heap_op_plt_hook(char *module_name)
{
    plthook_t *plthook;
    if (plthook_open(&plthook, module_name) != 0)
    {
        printf("plthook_open error: %s\n", plthook_error());
        return -1;
    }

    plthook_replace(plthook, "malloc", (void *)my_malloc, NULL);
    plthook_replace(plthook, "free", (void *)my_free, NULL);
    plthook_replace(plthook, "realloc", (void *)my_realloc, NULL);
    plthook_replace(plthook, "calloc", (void *)my_calloc, NULL);

    plthook_close(plthook);
    return 0;
}

void init_heap_asan()
{
    srand(time(0));
    HEAP_MAP = kh_init(HEAP_MAP_DEF);
}

void deinit_heap_asan()
{
    kh_destroy(HEAP_MAP_DEF, HEAP_MAP);
}

void inline_hook_function(char *func_name, void *func)
{
    void *addr = dlsym(NULL, func_name);
    if (addr != NULL)
    {
        inline_hook_unprotect(addr);
        inline_hook(addr, func);
    }
}

void heap_op_inline_hook()
{
    inline_hook_function("malloc", my_malloc);
    inline_hook_function("free", my_free);
    inline_hook_function("calloc", my_calloc);
    inline_hook_function("realloc", my_realloc);
}

int main()
{
    void *tbl[20] = {0};

    init_heap_asan();

    // heap_op_plt_hook("libtest.so");

    heap_op_inline_hook();

    for (size_t i = 0; i < 20; i++)
    {
        tbl[i] = malloc(21);
    }

    char *p = tbl[2];
    p[-2] = 0;
    p[0x20] = 0;

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

    deinit_heap_asan();
    return 0;
}