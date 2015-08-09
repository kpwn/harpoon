#ifndef __HARPOON_LIBHOOK__
#define __HARPOON_LIBHOOK__
void throw_hook(void *orig, void *repl, void **orig_ptr);
#define HOOK_ORIG(name, ...) __orig##name(__VA_ARGS__)
#define HOOK_DEFINE(type, name, ...) static type (*__orig##name)(__VA_ARGS__); static type __hook##name(__VA_ARGS__)
#define HOOK_THROW(name) throw_hook((void*)name, (void*)__hook##name, (void**)&__orig##name)
#define CTOR() __attribute__((constructor)) static void __load ()
#endif
