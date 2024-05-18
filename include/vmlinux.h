
#if defined(__TARGET_ARCH_x86)
	#include <x86/vmlinux.h>
#elif defined(__TARGET_ARCH_arm64)
	#include <arm64/vmlinux.h>
#endif