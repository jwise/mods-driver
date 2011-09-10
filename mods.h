/*
 * mods.h - This file is part of NVIDIA MODS kernel driver.
 *
 * Copyright 2008-2011 NVIDIA Corporation.
 *
 * NVIDIA MODS kernel driver is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 2 of the
 * License, or (at your option) any later version.
 *
 * NVIDIA MODS kernel driver is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with NVIDIA MODS kernel driver.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _MODS_H_
#define _MODS_H_

#include <linux/module.h>
#include <linux/init.h>         /*  module_init, module_exit        */
#include <asm/uaccess.h>        /*  copy_from_user, copy_to_user    */
#include <linux/pci.h>          /*  pci_find_class, etc             */
#include <linux/poll.h>         /*  poll and select                 */
#include <asm/io.h>             /*  port READ/WRITE operation       */
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/netfilter.h>
#include <linux/version.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>

#define     NvU8    u8
#define     NvU16   u16
#define     NvU32   u32
#define     NvU64   u64

#include "driverAPI.h"

#ifndef true
#define true    1
#define false   0
#endif

/* function return code */
#define OK       0
#define ERROR   -1

#define IRQ_FOUND       1
#define IRQ_NOT_FOUND   0

#define DEV_FOUND       1
#define DEV_NOT_FOUND   0

#define MSI_DEV_FOUND        1
#define MSI_DEV_NOT_FOUND    0


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define IRQF_SHARED SA_SHIRQ
#endif

typedef struct _def_sys_page_table
{
    NvU64   phys_addr;
    NvU64   k_virtual_addr;
} SYS_PAGE_TABLE, *PSYS_PAGE_TABLE;

struct en_dev_entry
{
    struct pci_dev      *dev;
    struct en_dev_entry *next;
};

struct mem_type
{
    NvU64 phys_addr;
    NvU64 size;
    NvU32 type;
};

/* file private data */
typedef struct
{
    struct list_head    *mods_alloc_list;
    struct list_head    *mods_mapping_list;
    wait_queue_head_t   interrupt_event;
    struct en_dev_entry *enabled_devices;
    int                 mods_id;
    struct mem_type     mem_type;
} mods_file_private_data;

/* VM private data */
typedef struct
{
    struct file    *fp;
    atomic_t        usageCount;

} mods_vm_private_data;

/* system memory allocation tracking */
typedef struct _def_sys_mem_mods_info
{
    NvU32 contiguous;

    /* tells how the memory is cached:
     * (MODS_MEMORY_CACHED, MODS_MEMORY_UNCACHED, MODS_MEMORY_WRITECOMBINE)
     */
    NvU32 cache_type;

    NvU32 length;    /* actual number of bytes allocated */
    NvU32 order;     /* 2^Order pages allocated for contiguous allocation */
    NvU32 num_pages; /* number of allocated pages */
    NvU32 k_mapping_ref_cnt;

    NvU32 addr_bits;
    struct page *p_page;
    NvU64 logical_addr; /* kernel logical address */
    NvU64 phys_addr;    /* physical address, for contiguous allocation */

    /* keeps information about allocated pages for noncontiguous allocation */
    SYS_PAGE_TABLE **p_page_tbl;

    struct list_head    list;
} SYS_MEM_MODS_INFO, *PSYS_MEM_MODS_INFO;

/* map memory tracking */
typedef struct _def_sys_map_mods_info
{
    NvU32 contiguous;
    NvU64 phys_addr;      /* first physical address of given mapping */
    NvU64 virtual_addr;   /* virtual address of given mapping */
    NvU32 mapping_length; /* tells how many bytes were mapped */

    /* helps to unmap noncontiguous memory, NULL for contiguous */
    PSYS_MEM_MODS_INFO p_mem_info;

    struct list_head list;
} SYS_MAP_MEMORY, *PSYS_MAP_MEMORY;


/* functions used to avoid global debug variables */
int mods_check_debug_level(int);
int mods_get_mem4g(void);
int mods_get_highmem4g(void);
void mods_set_highmem4g(int);
int mods_get_multi_instance(void);
int mods_get_mem4goffset(void);

#define IRQ_MAX             256+PCI_IRQ_MAX
#define PCI_IRQ_MAX         15
#define MODS_CHANNEL_MAX    32

/* msi */
#define PCI_MSI_FLAGS       2
#define PCI_MSI_FLAGS_64BIT 0x80
#define PCI_MSI_DATA_64     12
#define PCI_MSI_MASK_BIT    16
#define MSI_CONTROL_REG(base)       (base + PCI_MSI_FLAGS)
#define IS_64BIT_ADDRESS(control)   (!!(control & PCI_MSI_FLAGS_64BIT))
#define MSI_DATA_REG(base, is64bit) \
    ((is64bit == 1) ? base + PCI_MSI_DATA_64 : base + PCI_MSI_DATA_32)

#define IRQ_VAL_POISON      0xfafbfcfdU

/* debug print masks */
#define DEBUG_IOCTL         0x2
#define DEBUG_PCICFG        0x4
#define DEBUG_ACPI          0x8
#define DEBUG_ISR           0x10
#define DEBUG_MEM           0x20
#define DEBUG_FUNC          0x40
#define DEBUG_CLOCK         0x80
#define DEBUG_DETAILED      0x100
#define DEBUG_ISR_DETAILED  (DEBUG_ISR | DEBUG_DETAILED)
#define DEBUG_MEM_DETAILED  (DEBUG_MEM | DEBUG_DETAILED)

#define LOG_ENT() mods_debug_printk(DEBUG_FUNC, "> %s\n", __FUNCTION__)
#define LOG_EXT() mods_debug_printk(DEBUG_FUNC, "< %s\n", __FUNCTION__)
#define LOG_ENT_C(format, args...) \
    mods_debug_printk(DEBUG_FUNC, "> %s: " format, __FUNCTION__, ##args)
#define LOG_EXT_C(format, args...) \
    mods_debug_printk(DEBUG_FUNC, "< %s: " format, __FUNCTION__, ##args)

#define mods_debug_printk(level, fmt, args...)\
    (void)(mods_check_debug_level(level) && \
           printk(KERN_DEBUG "mods debug: " fmt, ##args))

#define mods_info_printk(fmt, args...)\
    printk(KERN_INFO "mods: " fmt, ##args)

#define mods_error_printk(fmt, args...)\
    printk(KERN_ERR "mods error: " fmt, ##args)

#define mods_warning_printk(fmt, args...)\
    printk(KERN_WARNING "mods warning: " fmt, ##args)

#define assert(expr) do {                               \
    if (!(expr)) {                                      \
        printk(KERN_CRIT "mods: BUG in %s:%d: %s\n",           \
                __FILE__, __LINE__, __FUNCTION__);      \
        BUG();                                          \
    }                                                   \
} while (0)

struct irq_q_data
{
    NvU32               time;
    struct pci_dev     *dev;
    NvU32               irq;
};

struct irq_q_info
{
    struct irq_q_data   data[MODS_MAX_IRQS];
    NvU32               head;
    NvU32               tail;
};

struct dev_irq_map
{
    NvU32              *dev_irq_enabled;
    NvU32              *dev_irq_state;
    NvU32               apic_irq;
    NvU8                type;
    NvU8                channel;
    struct pci_dev     *dev;
    struct list_head    list;
};

struct mods_priv
{
    /* map info from pci irq to apic irq */
    struct list_head    irq_head[MODS_CHANNEL_MAX];

    /* bits map for each allocated id. Each mods has an id. */
    /* the design is to take  into  account multi mods. */
    unsigned long       channel_flags;

    /* fifo loop queue */
    struct irq_q_info   rec_info[MODS_CHANNEL_MAX];
    spinlock_t          lock;
};



/* *************************************************************************** */
/* *************************************************************************** */
/* **                                                                          */
/* ** SYSTEM CALLS                                                             */
/* **                                                                          */
/* *************************************************************************** */
/* *************************************************************************** */


/* MEMORY */
#define MODS_KMALLOC(ptr, size)                               \
    {                                                        \
        (ptr) = kmalloc(size, GFP_KERNEL);                   \
        MODS_ALLOC_RECORD(ptr, size, "km_alloc");             \
    }

#define MODS_KMALLOC_ATOMIC(ptr, size)                        \
    {                                                        \
        (ptr) = kmalloc(size, GFP_ATOMIC);                   \
        MODS_ALLOC_RECORD(ptr, size, "km_alloc_atomic");      \
    }

#define MODS_KFREE(ptr, size)                                 \
    {                                                        \
        MODS_FREE_RECORD(ptr, size, "km_free");               \
        kfree((void *) (ptr));                               \
    }

#define MODS_ALLOC_RECORD(ptr, size, name)                    \
    if (ptr != NULL)                                         \
    {                                                        \
        mods_add_mem(ptr, size, __FILE__, __LINE__);          \
    }

#define MODS_FREE_RECORD(ptr, size, name)                     \
    if (ptr != NULL)                                         \
    {                                                        \
        mods_del_mem(ptr, size, __FILE__, __LINE__);          \
    }

#define MEMDBG_ALLOC(a,b)       (a = kmalloc(b, GFP_ATOMIC))
#define MEMDBG_FREE(a)          (kfree(a))
#define MODS_FORCE_KFREE(ptr)    (kfree(ptr))

#define MODS_GET_FREE_PAGES(ptr, order, gfp_mask)             \
    {                                                        \
        (ptr) = __get_free_pages(gfp_mask, order);           \
    }

#define MODS_FREE_PAGES(ptr, order)                           \
    {                                                        \
        free_pages(ptr, order);                              \
    }

#define __MODS_ALLOC_PAGES(page, order, gfp_mask)              \
    {                                                       \
        (page) = alloc_pages(gfp_mask, order);              \
    }

#define __MODS_FREE_PAGES(page, order)                        \
    {                                                        \
        __free_pages(page, order);                           \
    }

#ifdef CONFIG_ARM
#   define MODS_SET_MEMORY_UC(addr, pages) 0
#   define MODS_SET_MEMORY_WC(addr, pages) 0
#   define MODS_SET_MEMORY_WB(addr, pages) 0
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#   define MODS_SET_MEMORY_UC(addr, pages) change_page_attr(virt_to_page(addr), pages, PAGE_KERNEL_NOCACHE)
#   define MODS_SET_MEMORY_WC MODS_SET_MEMORY_UC
#   define MODS_SET_MEMORY_WB(addr, pages) change_page_attr(virt_to_page(addr), pages, PAGE_KERNEL)
#else
#   define MODS_SET_MEMORY_UC(addr, pages) set_memory_uc(addr, pages)
#   if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#       define MODS_SET_MEMORY_WC(addr, pages) MODS_SET_MEMORY_UC(addr, pages)
#   else
#       define MODS_SET_MEMORY_WC(addr, pages) set_memory_wc(addr, pages)
#   endif
#   define MODS_SET_MEMORY_WB(addr, pages) set_memory_wb(addr, pages)
#endif

#define MODS_PGPROT_UC pgprot_noncached
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#   define MODS_PGPROT_WC pgprot_noncached
#else
#   define MODS_PGPROT_WC pgprot_writecombine
#endif

/* VMA */
#define MODS_VMA_PGOFF(vma)             ((vma)->vm_pgoff)
#define MODS_VMA_SIZE(vma)              ((vma)->vm_end - (vma)->vm_start)
#define MODS_VMA_OFFSET(vma)            (((NvU64)(vma)->vm_pgoff) << PAGE_SHIFT)
#define MODS_VMA_PRIVATE(vma)           ((vma)->vm_private_data)
#define MODS_VMA_FILE(vma)              ((vma)->vm_file)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    #define MODS_REMAP_PAGE_RANGE(vma, virt, phys, size, flags) \
        remap_pfn_range(vma, virt, phys, size, flags)
#else
    #define MODS_REMAP_PAGE_RANGE(vma, virt, phys, size, flags) \
        remap_page_range(vma, virt, phys<<PAGE_SHIFT, size, flags)
#endif

/* PCI */
#define MODS_PCI_BUS_NUMBER(dev)                     (dev)->bus->number
#define MODS_PCI_SLOT_NUMBER(dev)                    PCI_SLOT(MODS_PCI_DEVFN(dev))
#define MODS_PCI_FUNCTION_NUMBER(dev)                PCI_FUNC(MODS_PCI_DEVFN(dev))
#define MODS_PCI_DEVFN(dev)                          (dev)->devfn
#define MODS_PCI_VENDOR(dev)                         (dev)->vendor

#define MODS_PCI_DEV_PUT(dev)                        pci_dev_put(dev)
#define MODS_PCI_FIND_CAPABILITY(dev,id)             pci_find_capability(dev,id)
#define MODS_PCI_GET_DEVICE(vendor,device,from)      pci_get_device(vendor,device,from)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#define MODS_PCI_GET_CLASS(class,from)               pci_get_class(class,from)
#else
#define MODS_PCI_GET_CLASS(class,from)               pci_find_class(class,from)
#endif
#define MODS_PCI_FIND_BUS(domain, bus)               pci_find_bus(domain, bus)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
#define MODS_PCI_BUS_ADD_DEVICES(bus)                pci_bus_add_devices(bus)
#define MODS_PCI_SCAN_CHILD_BUS(bus)                 pci_scan_child_bus(bus)
#endif

#define MODS_PCI_GET_SLOT(bus,devfn)                                      \
   ({                                                                    \
        struct pci_dev *__dev = NULL;                                    \
        while ((__dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, __dev)))  \
        {                                                                \
            if (MODS_PCI_BUS_NUMBER(__dev) == bus                         \
                    && MODS_PCI_DEVFN(__dev) == devfn) break;             \
        }                                                                \
        __dev;                                                           \
    })

#define MODS_PCI_READ_CONFIG_BYTE(dev,where,val)     pci_read_config_byte(dev,where,val)
#define MODS_PCI_READ_CONFIG_WORD(dev,where,val)     pci_read_config_word(dev,where,val)
#define MODS_PCI_READ_CONFIG_DWORD(dev,where,val)    pci_read_config_dword(dev,where,val)
#define MODS_PCI_WRITE_CONFIG_BYTE(dev,where,val)    pci_write_config_byte(dev,where,val)
#define MODS_PCI_WRITE_CONFIG_WORD(dev,where,val)    pci_write_config_word(dev,where,val)
#define MODS_PCI_WRITE_CONFIG_DWORD(dev,where,val)   pci_write_config_dword(dev,where,val)

#define MODS_PCI_ENABLE_DEVICE(dev)                  pci_enable_device(dev)
#define MODS_PCI_DISABLE_DEVICE(dev)                 pci_disable_device(dev)
#define MODS_PCI_ENABLE_MSI(dev)                     pci_enable_msi(dev)
#define MODS_PCI_DISABLE_MSI(dev)                    pci_disable_msi(dev)

/* ACPI */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#define MODS_ACPI_WALK_NAMESPACE(type,start_object,max_depth,user_function,context,return_value)\
    acpi_walk_namespace(type,start_object,max_depth,user_function,NULL,context,return_value)
#else
#define MODS_ACPI_WALK_NAMESPACE acpi_walk_namespace
#endif

/* PIO */
#define MODS_PIO_READ_BYTE(port)             inb(port)
#define MODS_PIO_READ_WORD(port)             inw(port)
#define MODS_PIO_READ_DWORD(port)            inl(port)
#define MODS_PIO_WRITE_BYTE(data,port)       outb(data,port)
#define MODS_PIO_WRITE_WORD(data,port)       outw(data,port)
#define MODS_PIO_WRITE_DWORD(data,port)      outl(data,port)

/* FILE */
#define MODS_GET_FILE_PRIVATE(fp)         (fp)->private_data
#define MODS_GET_FILE_PRIVATE_ID(fp)      ((mods_file_private_data *)(fp)->private_data)->mods_id

/* SPIN_LOCK */
#define MODS_INIT_LOCK(lock)             spin_lock_init(&lock)
#define MODS_LOCK_IRQ(lock,flags)        spin_lock_irqsave(&lock,flags)
#define MODS_UNLOCK_IRQ(lock,flags)      spin_unlock_irqrestore(&lock,flags)
#define MODS_LOCK(lock)                  spin_lock(&lock)
#define MODS_UNLOCK(lock)                spin_unlock(&lock)

/* ATOMIC    */
#define MODS_ATOMIC_SET(data,val)        atomic_set(&(data),(val))
#define MODS_ATOMIC_INC(data)            atomic_inc(&(data))
#define MODS_ATOMIC_DEC_AND_TEST(data)   atomic_dec_and_test(&(data))

/* *************************************************************************** */
/* ** MODULE WIDE FUNCTIONS                                                    */
/* *************************************************************************** */

/* irq */
void mods_init_irq(void);
void mods_cleanup_irq(void);
unsigned char mods_alloc_channel(void);
void mods_free_channel(unsigned char);
void mods_irq_dev_clr_pri(unsigned char);
void mods_irq_dev_set_pri(unsigned char id, void *pri);
int mods_irq_event_check(unsigned char);

/* mem */
void mods_init_mem(void);
void mods_add_mem(void *, NvU32, const char *, NvU32);
void mods_del_mem(void *, NvU32, const char *, NvU32);
int mods_map_pages(void);
void mods_check_mem(void);
void mods_unmap_pages(void);
void mods_unregister_all_alloc(struct file *fp);
PSYS_MEM_MODS_INFO mods_find_alloc(struct file *, NvU64);

/* clock */
#ifdef CONFIG_ARM
void mods_init_clock_api(void);
void mods_shutdown_clock_api(void);
#endif

#endif  /* _MODS_H_  */
