#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>

// gcc UnCompressImage.c -o test_UnCompressImage_dbg -ldl -lheapasan -L libheapasan/  -g

void my_init(void) __attribute__((constructor)); //告诉gcc把这个函数扔到init section

int heap_op_plt_hook(char* module_name);
void plt_hook_function(char* module_name, char* func_name, void* new_func);
void heap_op_inline_hook();
void init_heap_asan();

typedef char *(*UnCompressImage)(char *buffer, unsigned int a2, unsigned int buffer_length, unsigned int a4, unsigned int a5);
typedef char *(*CAJFILE_CreateErrorObject)();

UnCompressImage p_UnCompressImage = NULL;
CAJFILE_CreateErrorObject p_CAJFILE_CreateErrorObject = NULL;



char *read_to_buf(char *path, unsigned int *len)
{
    FILE *f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    unsigned int fsize = ftell(f);
    fseek(f, 0, SEEK_SET); /* same as rewind(f); */
    char *buffer = malloc(fsize + 1);
    fread(buffer, 1, fsize, f);
    fclose(f);
    buffer[fsize] = 0;

    *len = fsize;
    return buffer;
}

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

int my_assert_fail()
{
    printf("my_assert_fail\n");
    exit(1);
    return 0;
}

int my_cxa_throw()
{
    printf("my_cxa_throw\n");
    exit(1);
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


    // init_heap_asan();
    // heap_op_plt_hook("libreaderex_x64.so");
    // heap_op_inline_hook();

    struct link_map *lm = (struct link_map *)handle;
    printf("image:%lx\n", lm->l_addr);

    char* image_base = (char*)lm->l_addr;

    printf("export AFL_CODE_START=%p\n", image_base + 0x3D4880);
    printf("export AFL_CODE_END=%p\n", image_base + 0x90984F);

    p_UnCompressImage = dlsym(handle, "_Z15UnCompressImagePcjjii");
    p_CAJFILE_CreateErrorObject = dlsym(handle, "CAJFILE_CreateErrorObject");

    // unsigned long p_target = image_base + 0x42CC6F;
    unsigned long p_target = (unsigned long)dlsym(handle, "_Z13LoadSymbolMapv");
    inline_hook_x64((void *)p_target, my_LoadSymbolMap);

    if (!p_UnCompressImage || !p_CAJFILE_CreateErrorObject)
    {
        fprintf(stderr, "Error: %s\n", dlerror());
        dlclose(handle);
        return;
    }
    
    plt_hook_function("libreaderex_x64.so", "__assert_fail", my_assert_fail);
    plt_hook_function("libreaderex_x64.so", "__cxa_throw", my_cxa_throw);
    
    
}

int main(int argc, char **argv)
{
    printf("export AFL_ENTRYPOINT=%p\n", main);
    int f_sz = 0;
    char* buffer = read_to_buf(argv[1], &f_sz);

    if(f_sz < 2)
    {
        return 0;
    }

    unsigned int type = buffer[0] % 5;

    char *ret = p_UnCompressImage(buffer + 1, type, f_sz - 1, 100, 100);
    return 0;
}
