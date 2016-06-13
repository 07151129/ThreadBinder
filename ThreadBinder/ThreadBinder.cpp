#include <IOKit/IOLib.h>
#include <mach/kern_return.h>
#include <i386/machine_routines.h>
#include <kern/kern_types.h>
#include <i386/machine_routines.h>

#include "ThreadBinder.h"
#include "symbol_resolver.h"
#include "util.h"
#include "symbols.h"

#define super IOService
OSDefineMetaClassAndStructors(ThreadBinder, IOService)

bool ThreadBinder::start(IOService* provider) {
	if (!super::start(provider))
		return false;
	if (init_kernel_info(&gkinfo) != KERN_SUCCESS) {
		SYSLOG("failed to init kernel info");
		return false;
	}
	if (resolve_symbols() != KERN_SUCCESS) {
		SYSLOG("failed to resolve symbols");
		return false;
	}
	registerService();
	return true;
}

void ThreadBinder::stop(IOService* provider) {
	SYSLOG("stopping");
	super::stop(provider);
}

struct proc {
	void* unu0;
	void* unu1;
	int state;
};

extern "C" {
	extern unsigned int real_ncpus;
	extern int cpu_number(void);
}

#define PROCESSOR_OFF_LINE       0   /* Not available */
#define PROCESSOR_SHUTDOWN      1   /* Going off-line */

/* Derived from chud/chud_thread.c */
kern_return_t ThreadBinder::doBind(unsigned int thread, int cpu) {
	struct proc* proc = nullptr;
	
	if (cpu < 0 || (unsigned int)cpu >= real_ncpus) // sanity check
		return KERN_FAILURE;
	if (cpu == -1)
		proc = (struct proc*)PROCESSOR_NULL;
	else if (cpu >= 0)
		proc = (struct proc*)org_cpu_to_processor(cpu);
	else
		return KERN_FAILURE;
	
	if (thread == MACH_PORT_NULL) {
		SYSLOG("thread being bound is null");
		return KERN_FAILURE;
	}
	
	kern_return_t ret = KERN_FAILURE;
	
	ml_set_interrupts_enabled(false);
	
	thread_t curr = current_thread();
	thread_t target = org_port_name_to_thread(thread);
	
	if (curr != target) {
		org_machine_set_current_thread(target); /* Interrupts disabled, no need to lock? */
		
		org_thread_bind(proc);
		
		org_machine_set_current_thread(curr);
	} else
		org_thread_bind(proc);
	
	ret = KERN_SUCCESS;
	
exit:
	ml_set_interrupts_enabled(true);

	return ret;
}

kern_return_t ThreadBinder::doUnbind(unsigned int thread) {
	return doBind(thread, -1);
}

#undef super
#define super IOUserClient
OSDefineMetaClassAndStructors(ThreadBinderUserClient, IOUserClient)

bool ThreadBinderUserClient::initWithTask(task_t task, void *secID, uint32_t type, OSDictionary *props) {
	this->task = task;
	return super::initWithTask(task, secID, type, props);
}

bool ThreadBinderUserClient::start(IOService* provider) {
	if (!super::start(provider))
		return false;
	binder = (ThreadBinder*)provider;
	SYSLOG("ThreadBinder::start");
	return true;
}

IOReturn ThreadBinderUserClient::clientClose() {
	if (!isInactive())
		terminate();
	return kIOReturnSuccess;
}

void ThreadBinderUserClient::stop(IOService* provider) {
	task = nullptr;
	binder = nullptr;
	
	super::stop(provider);
}

IOExternalMethod* ThreadBinderUserClient::getTargetAndMethodForIndex(IOService **tgt, uint32_t idx) {
	SYSLOG("%s: %d", __PRETTY_FUNCTION__, idx);
	return super::getTargetAndMethodForIndex(tgt, idx);
}

kern_return_t ThreadBinderUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments* args,
												IOExternalMethodDispatch* disp, OSObject* tgt, void* ref) {
	IOReturn err = kIOReturnError;
//	SYSLOG("ThreadBinderUserClient::externalMethod(%d, ...)", selector);
	switch (selector) {
		SYSLOG("args: 0x%p, args->scalarInputCount: 0x%x, args->scalarOutputCount: 0x%x", args, args ? args->scalarInputCount : 0,  args ? args->scalarOutputCount : 0);
		case 0: {
			if (args && args->scalarInputCount == 2) {
				err = ThreadBinderUserClient::bind((unsigned int)args->scalarInput[0], (uint32_t)args->scalarInput[1]);
			}
			break;
		}
		case 1: {
			if (args && args->scalarInputCount == 1)
				err = ThreadBinderUserClient::unbind((unsigned int)args->scalarInput[0]);
			break;
		}
		  default:
				break;
	}

	return err;
}

kern_return_t ThreadBinderUserClient::bind(unsigned int thread, int cpu) {
	if (!binder) {
		SYSLOG("wtf, no binder?");
		return KERN_FAILURE;
	}
	return binder->doBind(thread, cpu);
}

kern_return_t ThreadBinderUserClient::unbind(unsigned int thread) {
	if (!binder)
		return KERN_FAILURE;
	return binder->doUnbind(thread);
}