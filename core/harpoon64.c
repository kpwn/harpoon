#include "harpoon64.h"

static void copy_bytes(char *old, char *new, size_t size)
{
  for (size_t i = 0; i < size; i++) {
    *(new+i) = *(old+i);
  }
}

static int make_zone_executable(void *z_ptr, size_t sz)
{
  int ret = 0;
  if ((ret = vm_protect(mach_task_self(), (vm_address_t)z_ptr, sz, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)) == 0)
    return ret;

    return -1;
}

static int allocate_jump_zone(void **z_ptr, void *orig)
{
  int ret = 0;
  vm_address_t page = 0;

  vm_address_t f = ((uint64_t)orig & ~((0xFUL << 28) | (PAGE_SIZE - 1))) | (0x1UL << 31); /* first address in 32-bit address space */
  vm_address_t l = (uint64_t)orig & ~((0x1UL << 32) - 1);                                 /* last address in 32-bit address space */

  page = f;
  int allocated = 0;
  vm_map_t task_self = mach_task_self();

  /* allocating loop */
  while(!ret && !allocated && page != l) {
    ret = vm_allocate(task_self, &page, PAGE_SIZE, 0);
    if(ret == 0)
      allocated = 1;
    else if(ret == KERN_NO_SPACE) {
      page -= PAGE_SIZE;
      ret = 0;
    }
  }

  if(allocated)
    *z_ptr = (void*) page;
  else if(!allocated && !ret)
    ret = KERN_NO_SPACE;

  return ret;
}

static int deallocate_jump_zone(void *z_ptr)
{
  assert(z_ptr);

  int ret = 0;
  if((ret = vm_deallocate(mach_task_self(), (vm_address_t)z_ptr, PAGE_SIZE)) == 0)
    return 0;

  return -1;
}

static int populate_jump_zone(void *z_ptr, char *jmp_shellcode, char *cooked, size_t ck_sz)
{
  assert(z_ptr);
  assert(jmp_shellcode);

  copy_bytes(JUMP_ZONE, z_ptr, JUMP_ZONE_SIZE); // copy memory -> memory

  if (cooked && (ck_sz != 0)) {
    memcpy(z_ptr, (const void *)cooked, ck_sz);
  } else if(cooked && (ck_sz == 0)) {
    return -1;
  }

  memcpy(z_ptr+(JUMP_ZONE_SIZE-JMP64_LONG_SIZE), (const void*)jmp_shellcode, JMP64_LONG_SIZE);
  make_zone_executable(z_ptr, PAGE_SIZE);

  return 0;
}

void mov(uint64_t *target, uint64_t value) //we need casting
{
    *target = value;
}

static void set_jump_to_jump_zone(void *z_ptr, void *target)
{
  uint64_t s_jump = 0x0;
  uint32_t off = ((char*)z_ptr - (char*)target - JMP32_SHORT_SIZE);
  off = OSSwapInt32(off); // reverse byte order

  s_jump |= 0xE900000000000000LL;
  s_jump |= ((uint64_t)off & 0xFFFFFFFF) << 24;
  s_jump = OSSwapInt64(s_jump);

  make_zone_executable(target, JMP32_SHORT_SIZE);
  mov((uint64_t *)target, s_jump);
}

static void load_shellcode64(char *shellcode, void *to)
{
  copy_bytes(SH_JMP64_LONG, shellcode, JMP64_LONG_SIZE);
  memcpy(shellcode+2, (const void*)&to, sizeof(to));
}

/* this will be used for i386. */
static void load_shellcode32(char *shellcode, void *to)
{
  copy_bytes(SH_JMP32_SHORT, shellcode, JMP32_SHORT_SIZE);
  memcpy(shellcode+1, (const void*)&to, sizeof(to));
}

size_t eat_instructions(void *func)
{
  csh handle;
  cs_insn *insn;
  size_t cnt;
  size_t len_cnt = 0;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return 0;

  cnt = cs_disasm(handle, func, 0xF, 0x0, 0, &insn);
  for (size_t k = 0;; k++) {
    if (len_cnt < JMP32_SHORT_SIZE + 0x3) {
      len_cnt+=insn[k].size;
    } else if (len_cnt >= JMP32_SHORT_SIZE + 0x3) {
      break;
    }
  }

  return len_cnt;
}

void throw_hook(void *orig, void *repl, void **origFunc)
{
  //__DBG("throw_hook: (%p)\n", orig);

  char zone_jump[JMP64_LONG_SIZE];
  char return_jmp[JMP64_LONG_SIZE];
  void *jzone_ptr = NULL, *trampoline_ptr = NULL;

  //allocate and fill jump zone (near original function) with long jump to replacement
  allocate_jump_zone(&jzone_ptr, orig);
  load_shellcode64(zone_jump, repl);
  populate_jump_zone(jzone_ptr, zone_jump, NULL, 0);

  size_t stolen_bytes = eat_instructions(orig);
  char prologue[stolen_bytes];

  memcpy(prologue, (const void *)orig, stolen_bytes);

  allocate_jump_zone(&trampoline_ptr, jzone_ptr);
  load_shellcode64(return_jmp, orig+stolen_bytes);
  populate_jump_zone(trampoline_ptr, return_jmp, prologue, stolen_bytes);

  make_zone_executable(orig, stolen_bytes);
  make_zone_executable(trampoline_ptr, PAGE_SIZE);
  //memset(orig, NOP_INSN, stolen_bytes);
  set_jump_to_jump_zone(jzone_ptr, orig);

  *origFunc = trampoline_ptr;
}