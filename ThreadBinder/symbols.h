#ifndef ThreadBinder_symbols_h
#define ThreadBinder_symbols_h

#include <mach/kern_return.h>
#include <kern/kern_types.h>

#ifdef __cplusplus
extern "C" {
#endif
	kern_return_t resolve_symbols(void);
#undef ORG
#ifdef __cplusplus
}
#endif

#define ORG(sym) extern sym##_t org_##sym
typedef void* (*thread_bind_t)(void*);
typedef void* (*cpu_to_processor_t)(int);
typedef void (*machine_set_current_thread_t)(thread_t);
typedef thread_t (*port_name_to_thread_t)(unsigned int);

ORG(thread_bind);
ORG(cpu_to_processor);
ORG(machine_set_current_thread);
ORG(port_name_to_thread);

#undef ORG

#endif
