// SPDX-License-Identifier: GPL-2.0
/*
 * Architecture-specific kernel symbols
 */

#ifdef CONFIG_VIRTUAL_MEM_MAP
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/memblock.h>
EXPORT_SYMBOL(min_low_pfn);	/* defined by bootmem.c, but not exported by generic code */
EXPORT_SYMBOL(max_low_pfn);	/* defined by bootmem.c, but not exported by generic code */
#endif

#include <linux/efi.h>
EXPORT_SYMBOL_GPL(efi_mem_type);
