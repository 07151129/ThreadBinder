#ifndef __ThreadBinder__symbol_resolver__
#define __ThreadBinder__symbol_resolver__

#include <sys/types.h>
#include <sys/vnode.h>
#include <mach/vm_map.h>

// amount of mach-o header to read
#ifndef HEADER_SIZE
#define HEADER_SIZE         PAGE_SIZE_64*2
#endif

typedef struct kernel_info {
	mach_vm_address_t running_text_addr; // the address of running __TEXT segment
	mach_vm_address_t disk_text_addr;    // the same address at /mach_kernel in filesystem
	mach_vm_address_t kaslr_slide;       // the kernel aslr slide, computed as the difference between above's addresses
	void *linkedit_buf;                  // pointer to __LINKEDIT buffer containing symbols to solve
	uint64_t linkedit_fileoff;           // __LINKEDIT file offset so we can read
	uint64_t linkedit_size;
	uint32_t symboltable_fileoff;        // file offset to symbol table - used to position inside the __LINKEDIT buffer
	uint32_t symboltable_nr_symbols;
	uint32_t stringtable_fileoff;        // file offset to string table
	uint32_t stringtable_size;
	// other info from the header we might need
	uint64_t text_size;                  // size of __text section to disassemble
	struct mach_header_64 *mh;           // ptr to mach-o header of running kernel
} kernel_info;

#ifdef __cplusplus
extern "C" {
#endif

	extern kernel_info gkinfo;

	kern_return_t init_kernel_info(kernel_info *kinfo);
	kern_return_t cleanup_kernel_info(kernel_info *kinfo);
	mach_vm_address_t resolve_symbol(kernel_info *kinfo, const char *symbol_to_solve);
	mach_vm_address_t solve_next_kernel_symbol(const kernel_info *kinfo, const char *symbol);
	kern_return_t get_mach_header(void *buffer, vnode_t vnode, vfs_context_t ctxt);

	kern_return_t enable_kernel_write(boolean_t enable);
		
#ifdef __cplusplus
}
#endif

#endif /* defined(__ThreadBinder__symbol_resolver__) */
