#include <IOKit/IOLib.h>
#include <IOKit/IOUserClient.h>
#include <mach/mach_types.h>

class ThreadBinder : public IOService {
	OSDeclareDefaultStructors(ThreadBinder);
		
public:
	virtual bool start(IOService* provider) override;
	virtual void stop(IOService* provider) override;
	
	kern_return_t doBind(unsigned int thread, int cpu);
	kern_return_t doUnbind(unsigned int thread);
};

class ThreadBinderUserClient : public IOUserClient {
	OSDeclareDefaultStructors(ThreadBinderUserClient);
	
private:
	ThreadBinder* binder;
	task_t task;
	
	kern_return_t bind(unsigned int thread, int cpu);
	kern_return_t unbind(unsigned int thread);

public:
	virtual bool start(IOService* provider) override;
	virtual void stop(IOService* provider) override;
	
	virtual bool initWithTask(task_t task, void* secID, uint32_t type, OSDictionary* props) override;
	virtual IOReturn clientClose(void) override;
	virtual IOExternalMethod* getTargetAndMethodForIndex(IOService** tgt, uint32_t idx) override;
	virtual IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments* args,
									IOExternalMethodDispatch* disp=nullptr, OSObject* tgt=nullptr, void* ref=nullptr) override;
};
