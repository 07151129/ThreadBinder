#include <stdio.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach_types.h>
#include <assert.h>
#include <pthread.h>
#include <mach/mach.h>

const size_t nthreads = 30;

static pthread_mutex_t bindLck;

static io_service_t service;
static io_connect_t conn;

volatile
int threadEntry(long tid) {
	pthread_mutex_lock(&bindLck);
	
	fprintf(stderr, "Entering tid %ld\n", tid);
	
	mach_port_t thread_self = pthread_mach_thread_np(pthread_self());
	uint64_t input[] = {(uint64_t)thread_self, 0};
	
	uint64_t res = 0;
	uint32_t outCnt = 0;
	
	fprintf(stderr, "binding thread 0x%llx, cpu %llu\n", input[0], input[1]);
	kern_return_t kret = IOConnectCallScalarMethod(conn, 0, input, 2, &res, &outCnt);
	fprintf(stderr, "kret: 0x%x\n", kret);
//	assert(kret == KERN_SUCCESS);
	
	fprintf(stderr, "ThreadBinder::doBind results in %d\n", (kern_return_t)res);
	
	pthread_mutex_unlock(&bindLck);
	
	while (1) ;
	
	return 0;
}

int main(int argc, const char * argv[]) {
	service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("ThreadBinder"));
	assert(service);
	assert(IOServiceOpen(service, mach_task_self(), 0, &conn) == KERN_SUCCESS);

	assert(!pthread_mutex_init(&bindLck, NULL));
	
	static pthread_t threads[nthreads];
	
	for (size_t i = 0; i < nthreads; i++) {
		assert(!pthread_create(&threads[i], NULL, (void*)threadEntry, (void*)i));
	}
	
	for (size_t i = 0; i < nthreads; i++)
		pthread_join(threads[i], NULL);
	
	pthread_exit(NULL);

    return 0;
}
