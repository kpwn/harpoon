#include "harpoon.h"
#include <pthread.h>

#ifdef __x86_64__
#define ABSJUMP_SUB(x) 0
#define ZONE_SIZE 0x30
#define native_word_t uint64_t
#define ZONE_ALLOCATOR_BEEF 0xbbadbeefbbadbeef
#define __x86_64__COMPACT_HOOK
#ifdef __x86_64__COMPACT_HOOK
#define ABSJUMP_SUB_COMPACT(x) (5+(uint32_t)(x))
#define IS_NEAR(orig,repl) IS_NEAR_((uint64_t)orig,(uint64_t)repl)
#define IS_NEAR_(orig,repl) ((repl < (5+orig)) && repl > (5+orig) - ((1ULL<<31)-1ULL) ) || ((repl > (5+orig)) && repl < (5+orig) + ((1ULL<<31)-1ULL) )
typedef struct __attribute__((__packed__)) opst_compact {
    uint8_t a; uint32_t b;
} opst_compact;
#endif
typedef struct __attribute__((__packed__)) opst {
    uint16_t a; uint64_t b; uint16_t c;
} opst;
#elif __i386__
#define ABSJUMP_SUB(x) (5+(uint32_t)(x))
#define ZONE_SIZE 0x20
#define native_word_t uint32_t
#define ZONE_ALLOCATOR_BEEF 0xbbadbeef
typedef struct __attribute__((__packed__)) opst {
    uint8_t a; uint32_t b;
} opst;
#endif

static native_word_t* zone_free_list = NULL;
static pthread_mutex_t zone_lck = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t hook_lck = PTHREAD_MUTEX_INITIALIZER;
static void zfree(void* alloc, native_word_t** zone);
static void* zalloc(native_word_t** zone) {
    void* ret = NULL;
    pthread_mutex_lock(&zone_lck);
    if (!(*zone)) {
        
        if (ZONE_SIZE % 2 || ZONE_SIZE < sizeof(native_word_t)) {
            puts("zalloc error: zone size must be a multiple of 2 and bigger than sizeof(native_word_t)");
            exit(-1);
        }

        native_word_t* szfl = 0;
        
        vm_allocate(mach_task_self_, (vm_address_t*)&szfl, PAGE_SIZE, 1);
        if (!szfl) {
            goto out;
        }
        vm_protect(mach_task_self_, (vm_address_t)szfl, PAGE_SIZE, 0, VM_PROT_ALL);
        for (int i = 0; i < (PAGE_SIZE/ZONE_SIZE); i++) {
            zfree((void*)(1ULL | (native_word_t)&szfl[i*(ZONE_SIZE/sizeof(native_word_t))]), zone);
        }
    }
    if (!(*zone)) {
        goto out;
    }
    ret = (*zone);
    (*zone) = (native_word_t*) (*zone)[0];
    ((native_word_t*) ret)[0] = ZONE_ALLOCATOR_BEEF;
out:
    pthread_mutex_unlock(&zone_lck);
    return ret;
}
static void zfree(void* alloc, native_word_t** zone) {
    char lock = !(((native_word_t)alloc) & 1);
    
    alloc = (void*) (((native_word_t) alloc) & (~1));
    
    if (lock) {
        pthread_mutex_lock(&zone_lck);
    }
    bzero(alloc, ZONE_SIZE);
    ((native_word_t*) alloc)[0] = (native_word_t)(*zone);
    (*zone) = (native_word_t*)alloc;
    if (lock) {
        pthread_mutex_unlock(&zone_lck);
    }
}

size_t eat_instructions(void *func, size_t target)
{
  csh handle;
  cs_insn *insn;
  size_t cnt;
  size_t len_cnt = 0;
#ifdef __x86_64__
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return 0;
#elif __i386__
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return 0;
#endif
  cnt = cs_disasm(handle, func, 0xF, 0x0, 0, &insn);
  for (int k = 0; k < 0xF || !(len_cnt >= target); k++) {
    if (len_cnt < target) {
      len_cnt+=insn[k].size;
    }
  }
    
    if (len_cnt < target) {
        return 0;
    }

  return len_cnt;
}
#ifdef __x86_64__
#ifdef __x86_64__COMPACT_HOOK
static struct current_zone {
    struct current_zone* list_next;
    native_word_t* zone_free_list;
} zbg;
vm_address_t find_near(vm_address_t addr) {
    struct current_zone* cur = &zbg;
    struct current_zone* prev = NULL;
    while (cur) {
        if (cur->zone_free_list && IS_NEAR(addr,cur->zone_free_list)) {
            vm_address_t rtn = (vm_address_t)zalloc(&cur->zone_free_list);
            if (prev && !cur->zone_free_list) {
                prev->list_next = cur->list_next;
                free(cur);
            }
            return rtn;
        }
        prev = cur;
        cur = cur->list_next;
    }
    cur = &zbg;
    //printf("allocating new near zone\n");
    kern_return_t kr      = KERN_SUCCESS;
    vm_size_t     size    = 0;
    vm_size_t     old_size    = 0;
    vm_address_t     old_address    = 0;
    vm_address_t     address    = addr - ((1ULL << 31ULL) - 1ULL);
    
    while (1) {
        mach_msg_type_number_t count;
        struct vm_region_submap_info_64 info;
        uint32_t nesting_depth;
        
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(mach_task_self_, &address, &size, &nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }
        
        if (info.is_submap) {
            nesting_depth++;
        } else {
           // printf("near_region[%p]: %p -> %p (%lx bytes)\n", addr, (void*)address, (void*)(address+size), size);
            if (old_address && old_address + old_size < address) {
                //printf("GOT SPACE_region[%p]: %p -> %p (%lx bytes)\n", addr, (void*)address, (void*)(address+size), size);
                if ((IS_NEAR(addr, old_address+old_size))) {
                    if (ZONE_SIZE % 2 || ZONE_SIZE < sizeof(native_word_t)) {
                        //puts("zalloc error: zone size must be a multiple of 2 and bigger than sizeof(native_word_t)");
                        exit(-1);
                    }
                    
                    native_word_t* szfl = (native_word_t*)old_address + old_size;
                    
                    vm_allocate(mach_task_self_, (vm_address_t*)&szfl, PAGE_SIZE, 0);
                    if (!szfl) {
                        if (kr == KERN_INVALID_ADDRESS) {
                            return 0;
                        }
                        continue;
                    }
                    vm_protect(mach_task_self_, (vm_address_t)szfl, PAGE_SIZE, 0, VM_PROT_ALL);
                    if (cur->zone_free_list) {
                        while (cur->list_next) {
                            cur = cur->list_next;
                            if (!cur->zone_free_list) {
                                break;
                            }
                        }
                        if (cur->zone_free_list) {
                            cur->list_next = malloc(sizeof(struct current_zone));
                            cur->list_next->zone_free_list = 0;
                            cur->list_next->list_next = 0;
                            cur = cur->list_next;
                            assert(cur->zone_free_list == 0);
                        }
                    }
                    for (int i = 0; i < (PAGE_SIZE/ZONE_SIZE); i++) {
                        zfree((void*)((native_word_t)&szfl[i*(ZONE_SIZE/sizeof(native_word_t))]), &cur->zone_free_list);
                    }
                    return (vm_address_t)zalloc(&cur->zone_free_list);
                }
            }
            
            old_address = address;
            old_size = size;
            address += size;
        }
    }
    return 0;
}
#endif
#endif
void throw_hook(void *orig, void *repl, void **orig_ptr)
{
  //__DBG("throw_hook: (%p)\n", orig);
    opst x;
#ifdef __x86_64__
    x.a = 0xb848; // mov rax, target
    x.c = 0xc350; // pop rax; ret
#elif __i386__
    x.a = 0xE9;   // abs jump
#endif
    
    pthread_mutex_lock(&hook_lck);

    void *tramp = zalloc(&zone_free_list);

    int hook_size = sizeof(opst);
    
#ifdef __x86_64__
#ifdef __x86_64__COMPACT_HOOK
    opst_compact xc;
    vm_address_t nalloc=0;
    xc.a = 0xE9;
    if (IS_NEAR(orig,repl)) {
        //printf("no trampoline needed for short jump to %p from %p\n", repl, orig);
        hook_size = sizeof(opst_compact);
    } else
    if (( nalloc = find_near((vm_address_t)orig)) != 0) {
        //printf("allocated trampoline at %p\n", nalloc);
        hook_size = sizeof(opst_compact);
        x.b = (native_word_t) repl - ABSJUMP_SUB(orig);
        memcpy((void*)nalloc, &x, sizeof(x));
        repl = (void*) nalloc;
        assert(IS_NEAR(orig,repl));
    }
#endif
#endif
    
    // orig_ptr
    size_t eaten = eat_instructions(orig, hook_size);
    if (!eaten) {
        printf("throw_hook: eaten = 0, couldn't analyse function to hook\n");
        goto out;
    }
    
    x.b = (native_word_t) repl - ABSJUMP_SUB(orig);

    vm_protect(mach_task_self_, (vm_address_t)orig, PAGE_SIZE, 0, VM_PROT_ALL);
    vm_protect(mach_task_self_, (vm_address_t)orig+sizeof(opst), PAGE_SIZE, 0, VM_PROT_ALL);
    
#ifdef __x86_64__
#ifdef __x86_64__COMPACT_HOOK
    if ( hook_size == sizeof(opst_compact) ) {
        xc.b =  (uint32_t) (repl - ABSJUMP_SUB_COMPACT(orig));
        memcpy(tramp, orig, eaten);
        memset(orig, 0x90, eaten);
        memcpy(orig, &xc, sizeof(opst_compact));
    } else
#endif
#endif
    {
        memcpy(tramp, orig, eaten);
        memset(orig, 0x90, eaten);
        memcpy(orig, &x, sizeof(opst));
    }
    x.b = (native_word_t) (orig + eaten) - ABSJUMP_SUB(tramp+eaten);
    
    memcpy(tramp+eaten, &x, sizeof(opst));
    
    vm_protect(mach_task_self_, (vm_address_t)orig, PAGE_SIZE, 0, VM_PROT_READ|VM_PROT_EXECUTE);
    vm_protect(mach_task_self_, (vm_address_t)orig+sizeof(opst), PAGE_SIZE, 0, VM_PROT_READ|VM_PROT_EXECUTE);

    if (orig_ptr) {
        *orig_ptr = tramp;
    }
out:
    pthread_mutex_unlock(&hook_lck);
}
