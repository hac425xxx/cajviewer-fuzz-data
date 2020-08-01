#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>

// gcc CAJFILE_OpenEx1.c -o test_CAJFILE_OpenEx1_dbg -ldl -lheapasan -L libheapasan/  -g

void my_init(void) __attribute__((constructor)); //告诉gcc把这个函数扔到init section

int heap_op_plt_hook(char* module_name);

void heap_op_inline_hook();
void init_heap_asan();

typedef char *(*CAJFILE_OpenEx1)(char *x, char *b);
typedef char *(*CAJFILE_CreateErrorObject)();

CAJFILE_OpenEx1 p_CAJFILE_OpenEx1 = NULL;
CAJFILE_CreateErrorObject p_CAJFILE_CreateErrorObject = NULL;

void *subhook_unprotect(void *address, size_t size)
{
    unsigned long pagesize;

    pagesize = sysconf(_SC_PAGESIZE);
    address = (void *)((unsigned long)address & ~(pagesize - 1));

    if (mprotect(address, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
    {
        return address;
    }
    else
    {
        return NULL;
    }
}

void inline_hook_x64(void *func, void *newAddr)
{

    subhook_unprotect(func, 0x1000);

    char *f = (char *)func;
    *(unsigned short *)&f[0] = 0x25ff;
    *(int *)&f[2] = 0x00000000;
    *(long *)&f[6] = (long)newAddr;
}

int my_LoadSymbolMap()
{
    return 0;
}

void my_init(void)
{
    void *handle;
    handle = dlopen("/home/hac425/cajviewer/cajviewer-bin/usr/lib/libreaderex_x64.so", RTLD_LAZY);
    if (!handle)
    {
        fprintf(stderr, "Error: %s\n", dlerror());
        return;
    }


    init_heap_asan();
    // heap_op_plt_hook("libreaderex_x64.so");
    heap_op_inline_hook();

    struct link_map *lm = (struct link_map *)handle;
    printf("%lx\n", lm->l_addr);

    unsigned long image_base = lm->l_addr;

    p_CAJFILE_OpenEx1 = dlsym(handle, "CAJFILE_OpenEx1");
    p_CAJFILE_CreateErrorObject = dlsym(handle, "CAJFILE_CreateErrorObject");

    // unsigned long p_target = image_base + 0x42CC6F;
    unsigned long p_target = (unsigned long)dlsym(handle, "_Z13LoadSymbolMapv");
    inline_hook_x64((void *)p_target, my_LoadSymbolMap);

    if (!p_CAJFILE_OpenEx1 || !p_CAJFILE_CreateErrorObject)
    {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return;
    }

    printf("p_CAJFILE_OpenEx1:%p\n", p_CAJFILE_OpenEx1);
}

int main(int argc, char **argv)
{
    char buf[0x2D8];
    printf("main:%p\n", main);

    memset(buf, 0, 0x2D8);
    *(unsigned int *)buf = 0x2D8;
    // *(unsigned int *)(buf + 4) = 256;

    // *(char* *)(buf + 8) = p_CAJFILE_CreateErrorObject();

    char *ret = p_CAJFILE_OpenEx1(argv[1], buf);
    return 0;
}
