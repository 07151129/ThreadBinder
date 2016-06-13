#ifndef ThreadBinder_util_h
#define ThreadBinder_util_h

#include <sys/systm.h>

#ifndef SYSLOG
#define SYSLOG(str, ...) printf("ThreadBinder: " str "\n", ## __VA_ARGS__)
#endif

#endif
