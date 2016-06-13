#include "symbol_resolver.h"

/*
 * ________
 * \_____  \   ____ ___.__.___  ___
 *  /   |   \ /    <   |  |\  \/  /
 * /    |    \   |  \___  | >    <
 * \_______  /___|  / ____|/__/\_ \
 *         \/     \/\/           \/
 *                    The Black Cat
 *
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <sys/attr.h>
#include <i386/proc_reg.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach/vm_param.h>
#include <mach/mach_types.h>

#include "symbol_resolver.h"

// kernel locations in the filesystem
static char *kernel_paths[] = {
	"/mach_kernel",
	"/System/Library/Kernels/kernel",	//since 10.10
	"/System/Library/Kernels/kernel.debug",
	"/System/Library/Kernels/kernel.development"
};

kernel_info gkinfo;

// local prototypes
static kern_return_t process_kernel_mach_header(void *kernel_header, kernel_info *kinfo);
static kern_return_t get_kernel_linkedit(vnode_t kernel_vnode, vfs_context_t ctxt, kernel_info *kinfo);
static void get_running_text_address(kernel_info *kinfo);
static boolean_t is_current_kernel(void *kernel_header);

// 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!)
struct descriptor_idt {
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

void get_addr_idt (mach_vm_address_t* idt);
mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);

kern_return_t enable_wp(boolean_t enable);

/*
 * entrypoint function to read necessary information from running kernel and kernel at disk
 * such as kaslr slide, linkedit location
 * the reads from disk are implemented using the available KPI VFS functions
 */
kern_return_t init_kernel_info(kernel_info *kinfo) {
	kern_return_t error = 0;
	// lookup vnode for /mach_kernel
	
	void *kernel_header = _MALLOC(HEADER_SIZE, M_TEMP, M_ZERO);
	if (kernel_header == NULL) {
		return KERN_FAILURE;
	}
	
	vnode_t kernel_vnode = NULLVP;
	vfs_context_t ctxt = NULL;
	
	int found_kernel = 0;
	for(int i = 0; i < sizeof(kernel_paths) / sizeof(*kernel_paths); i++) {
		kernel_vnode = NULLVP;
		ctxt = vfs_context_create(NULL);
		
		error = vnode_lookup(kernel_paths[i], 0, &kernel_vnode, ctxt);
		if(!error) {
			error = get_mach_header(kernel_header, kernel_vnode, ctxt);
			if(!error) {
				if(!is_current_kernel(kernel_header)) {
					vnode_put(kernel_vnode);
				} else {
					found_kernel = 1;
					break;
				}
			}
		}
		
		vfs_context_rele(ctxt);
	}
	
	if(!found_kernel) {
		_FREE(kernel_header, M_TEMP);
		return KERN_FAILURE;
	}
	
	error = process_kernel_mach_header(kernel_header, kinfo);
	if (error) goto failure;
	
	// compute kaslr slide
	get_running_text_address(kinfo);
	kinfo->kaslr_slide = kinfo->running_text_addr - kinfo->disk_text_addr;
	// we know the location of linkedit and offsets into symbols and their strings
	// now we need to read linkedit into a buffer so we can process it later
	// __LINKEDIT total size is around 1MB
	// we should free this buffer later when we don't need anymore to solve symbols
	kinfo->linkedit_buf = _MALLOC(kinfo->linkedit_size, M_TEMP, M_ZERO);
	if (kinfo->linkedit_buf == NULL) {
		_FREE(kernel_header, M_TEMP);
		return KERN_FAILURE;
	}
	// read linkedit from filesystem
	error = get_kernel_linkedit(kernel_vnode, ctxt, kinfo);
	if (error) goto failure;
	
success:
	_FREE(kernel_header, M_TEMP);
	vfs_context_rele(ctxt);
	// drop the iocount due to vnode_lookup()
	// we must do this else machine will block on shutdown/reboot
	vnode_put(kernel_vnode);
	return KERN_SUCCESS;
failure:
	if (kinfo->linkedit_buf != NULL) _FREE(kinfo->linkedit_buf, M_TEMP);
	_FREE(kernel_header, M_TEMP);
	vfs_context_rele(ctxt);
	vnode_put(kernel_vnode);
	return KERN_FAILURE;
}

/*
 * cleanup the kernel info buffer to avoid memory leak.
 * there's nothing else to cleanup here, for now
 */
kern_return_t cleanup_kernel_info(kernel_info *kinfo) {
	if (kinfo->linkedit_buf != NULL) {
		_FREE(kinfo->linkedit_buf, M_TEMP);
	}
	return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
mach_vm_address_t resolve_symbol(kernel_info *kinfo, const char *symbol_to_solve) {
	if (kinfo == NULL || kinfo->linkedit_buf == NULL) {
		return 0;
	}
	
	// symbols and strings offsets into LINKEDIT
	// we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
	// subtract the base of LINKEDIT to fix the value into our buffer
	uint64_t symbol_off = kinfo->symboltable_fileoff - (kinfo->linkedit_fileoff);
	if (symbol_off > kinfo->symboltable_fileoff) return 0;
	uint64_t string_off = kinfo->stringtable_fileoff - (kinfo->linkedit_fileoff);
	if (string_off > kinfo->stringtable_fileoff) return 0;
	
	struct nlist_64 *nlist64 = NULL;
	// search for the symbol and get its location if found
	for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++) {
		// get the pointer to the symbol entry and extract its symbol string
		nlist64 = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
		char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist64->n_un.n_strx);
		// find if symbol matches
		if (strcmp(symbol_to_solve, symbol_string) == 0)
		{
			// the symbols values are without kernel ASLR so we need to add it
			return (nlist64->n_value + kinfo->kaslr_slide);
		}
	}
	// failure
	return 0;
}

/*
 * return the address of the symbol after the one in the parameter
 * this is a cheap/not very reliable trick to find out the size of a given symbol
 * cheap because we might have static functions between the two symbols, for example
 */
mach_vm_address_t solve_next_kernel_symbol(const kernel_info *kinfo, const char *symbol) {
	struct nlist_64 *nlist = NULL;
	
	if (kinfo == NULL || kinfo->linkedit_buf == NULL) {
		return 0;
	}
	
	mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
	mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;
	
	for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++) {
		nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
		char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
		if (strncmp(symbol, symbol_string, strlen(symbol)) == 0) {
			// lookup the next symbol
			nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + (i+1) * sizeof(struct nlist_64));
			symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
			return (nlist->n_value + kinfo->kaslr_slide);
		}
	}
	// failure
	return 0;
}

/*
 * retrieve the first page of kernel binary at disk into a buffer
 * version that uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
 */
kern_return_t get_mach_header(void *buffer, vnode_t vnode, vfs_context_t ctxt) {
	int error = 0;
	uio_t uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
	if (uio == NULL) {
		return KERN_FAILURE;
	}
	// imitate the kernel and read a single page from the header
	error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), HEADER_SIZE);
	if (error) {
		return error;
	}
	// read kernel vnode into the buffer
	error = VNOP_READ(vnode, uio, 0, ctxt);
	
	if (error) {
		return error;
	}
	else if (uio_resid(uio)) return EINVAL;
	
	// process the header
	uint32_t magic = *(uint32_t*)buffer;
	if (magic != MH_MAGIC_64) {
		return KERN_FAILURE;
	}
	
	return KERN_SUCCESS;
}

/*
 * retrieve the whole linkedit segment into target buffer from kernel binary at disk
 * we keep this buffer until we don't need to solve symbols anymore
 */
static kern_return_t get_kernel_linkedit(vnode_t kernel_vnode, vfs_context_t ctxt, kernel_info *kinfo) {
	int error = 0;
	uio_t uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
	if (uio == NULL) {
		return KERN_FAILURE;
	}
	error = uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size);
	if (error) return error;
	
	error = VNOP_READ(kernel_vnode, uio, 0, ctxt);
	
	if (error) {
		return error;
	} else if (uio_resid(uio)) {
		return EINVAL;
	}
	
	return KERN_SUCCESS;
}

/*
 * retrieve LC_UUID command value from a mach header
 */
static uint64_t *get_uuid(void *mach_header) {
	struct mach_header *mh = (struct mach_header*)mach_header;
	int header_size = sizeof(struct mach_header_64);
	
	struct load_command *load_cmd = NULL;
	char *load_cmd_addr = (char*)mach_header + header_size;
	for (uint32_t i = 0; i < mh->ncmds; i++) {
		load_cmd = (struct load_command*)load_cmd_addr;
		if (load_cmd->cmd == LC_UUID) {
			return (uint64_t *)((struct uuid_command *)load_cmd)->uuid;
		}
		
		load_cmd_addr += load_cmd->cmdsize;
	}
	
	return NULL;
}

/*
 * check if a found kernel is the one we are running atm
 */
static boolean_t is_current_kernel(void *kernel_header) {
	// retrieves the address of the IDT
	mach_vm_address_t idt_address = 0;
	get_addr_idt(&idt_address);
	// calculate the address of the int80 handler
	mach_vm_address_t int80_address = calculate_int80address(idt_address);
	// search backwards for the kernel base address (mach-o header)
	mach_vm_address_t kernel_base = find_kernel_base(int80_address);
	
	uint64_t *uuid1 = get_uuid(kernel_header);
	uint64_t *uuid2 = get_uuid((void*)kernel_base);
	
	if(!uuid1 || !uuid2) {
		return FALSE;
	}
	
	return uuid1[0] == uuid2[0] && uuid1[1] == uuid2[1];
}

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * stored at our kernel_info structure
 */
static kern_return_t process_kernel_mach_header(void *kernel_header, kernel_info *kinfo) {
	struct mach_header *mh = (struct mach_header*)kernel_header;
	int header_size = sizeof(struct mach_header_64);
	
	struct load_command *load_cmd = NULL;
	// point to the first load command
	char *load_cmd_addr = (char*)kernel_header + header_size;
	// iterate over all load cmds and retrieve required info to solve symbols
	// __LINKEDIT location and symbol/string table location
	for (uint32_t i = 0; i < mh->ncmds; i++) {
		load_cmd = (struct load_command*)load_cmd_addr;
		if (load_cmd->cmd == LC_SEGMENT_64) {
			struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
			// use this one to retrieve the original vm address of __TEXT so we can compute kernel aslr slide
			if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
				kinfo->disk_text_addr = seg_cmd->vmaddr;
				// lookup the __text section - we want the size which can be retrieve here or from the running version
				char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
				struct section_64 *section_cmd = NULL;
				// iterate thru all sections
				for (uint32_t x = 0; x < seg_cmd->nsects; x++) {
					section_cmd = (struct section_64*)section_addr;
					if (strncmp(section_cmd->sectname, "__text", 16) == 0) {
						kinfo->text_size = section_cmd->size;
						break;
					}
					section_addr += sizeof(struct section_64);
				}
			} else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0) {
				kinfo->linkedit_fileoff = seg_cmd->fileoff;
				kinfo->linkedit_size    = seg_cmd->filesize;
			}
		}
		// table information available at LC_SYMTAB command
		else if (load_cmd->cmd == LC_SYMTAB) {
			struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
			kinfo->symboltable_fileoff    = symtab_cmd->symoff;
			kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
			kinfo->stringtable_fileoff    = symtab_cmd->stroff;
			kinfo->stringtable_size       = symtab_cmd->strsize;
		}
		load_cmd_addr += load_cmd->cmdsize;
	}
	return KERN_SUCCESS;
}

/*
 * retrieve the __TEXT address of current loaded kernel so we can compute the KASLR slide
 * also the size of __text
 */
static void get_running_text_address(kernel_info *kinfo) {
	// retrieves the address of the IDT
	mach_vm_address_t idt_address = 0;
	get_addr_idt(&idt_address);
	// calculate the address of the int80 handler
	mach_vm_address_t int80_address = calculate_int80address(idt_address);
	// search backwards for the kernel base address (mach-o header)
	mach_vm_address_t kernel_base = find_kernel_base(int80_address);
	if (kernel_base != 0) {
		// get the vm address of __TEXT segment
		struct mach_header *mh = (struct mach_header*)kernel_base;
		int header_size = sizeof(struct mach_header_64);
		
		struct load_command *load_cmd = NULL;
		char *load_cmd_addr = (char*)kernel_base + header_size;
		for (uint32_t i = 0; i < mh->ncmds; i++) {
			load_cmd = (struct load_command*)load_cmd_addr;
			if (load_cmd->cmd == LC_SEGMENT_64) {
				struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
				if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0) {
					kinfo->running_text_addr = seg_cmd->vmaddr;
					kinfo->mh = (struct mach_header_64*)kernel_base;
					break;
				}
			}
			load_cmd_addr += load_cmd->cmdsize;
		}
	}
}

/* retrieve the address of the IDT
 * should never be a bogus value?
 */
void get_addr_idt(mach_vm_address_t *idt) {
	uint8_t idtr[10];
	__asm__ volatile ("sidt %0": "=m" (idtr));
	*idt = *(mach_vm_address_t *)(idtr+2);
}

/*
 * calculate the address of the kernel int80 handler
 * using the IDT array
 */
mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address) {
	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor = NULL;
	mach_vm_address_t int80_address = 0;
	// we need to compute the address, it's not direct
	// extract the stub address
	
	// retrieve the descriptor for interrupt 0x80
	// the IDT is an array of descriptors
	int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
	uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
	uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
	int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low);
	
	return int80_address;
}

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address) {
	mach_vm_address_t temp_address = int80_address;
	struct segment_command_64 *segment_command = NULL;
	while (temp_address > 0) {
		if (*(uint32_t*)(temp_address) == MH_MAGIC_64) {
			// make sure it's the header and not some reference to the MAGIC number
			segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
			if (strncmp(segment_command->segname, "__TEXT", 16) == 0) {
				return temp_address;
			}
		}
		if (temp_address - 1 > temp_address) break;
		temp_address--;
	}
	return 0;
}

/*
 * enable/disable the Write Protection bit in CR0 register
 */
kern_return_t enable_wp(boolean_t enable) {
	uintptr_t cr0;
	// retrieve current value
	cr0 = get_cr0();
	if (enable) {
		// add the WP bit
		cr0 = cr0 | CR0_WP;
	} else {
		// remove the WP bit
		cr0 = cr0 & ~CR0_WP;
	}
	// and write it back
	set_cr0(cr0);
	// verify if we were successful
	if (((get_cr0() & CR0_WP) != 0 && enable) ||
		((get_cr0() & CR0_WP) == 0 && !enable)) {
		return KERN_SUCCESS;
	} else {
		return KERN_FAILURE;
	}
}

/*
 * enable/disable kernel memory write protection
 */
kern_return_t enable_kernel_write(boolean_t enable) {
	kern_return_t res = KERN_SUCCESS;
	if (enable) __asm__ volatile("cli"); // disable interrupts
	if (enable_wp(!enable) != KERN_SUCCESS) {
		enable = FALSE;
		res = KERN_FAILURE;
	}
	if (!enable) __asm__ volatile("sti"); // enable interrupts
	return res;
}