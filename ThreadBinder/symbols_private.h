#ifndef __ThreadBinder__symbols_private__
#define __ThreadBinder__symbols_private__

#include "symbols.h"

#define ORG(sym) sym##_t org_##sym

ORG(thread_bind);
ORG(cpu_to_processor);
ORG(machine_set_current_thread);
ORG(port_name_to_thread);

#endif /* defined(__ThreadBinder__symbols_private__) */
