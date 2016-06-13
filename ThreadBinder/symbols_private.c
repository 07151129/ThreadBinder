#include "symbol_resolver.h"
#include "symbols_private.h"
#include "util.h"

kern_return_t resolve_symbols() {
#define RESOLVE_SYMBOL(sym) { if (!(org_##sym = (void*)resolve_symbol(&gkinfo, "_"#sym))){\
	SYSLOG("Failed to resolve %s", #sym);\
	return KERN_FAILURE;\
	}\
}
	RESOLVE_SYMBOL(thread_bind);
	RESOLVE_SYMBOL(cpu_to_processor);
	RESOLVE_SYMBOL(machine_set_current_thread);
	RESOLVE_SYMBOL(port_name_to_thread);
				   
	return KERN_SUCCESS;
}