#import <stdio.h>
#import "libhook.h"

HOOK_DEFINE(void, puts, char* x) {
    HOOK_ORIG(puts, "puts hooked");
    HOOK_ORIG(puts, x);
}

int main() {
	HOOK_THROW(puts);
	puts("hello");
}
