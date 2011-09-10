/*
 * mods_mem.c - This file is part of NVIDIA MODS kernel driver.
 *
 * Copyright 2008-2010 NVIDIA Corporation.
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

#include "mods.h"
#include "driverAPI.h"

/* we remap phys for the beginning of 4G + 1M and leave a guard region. */
#define REMAP_DEFAULT_START     (0x100000000ULL)
#define REMAP_MEM_START     (REMAP_DEFAULT_START \
                             + (NvU64)(mods_get_mem4goffset() & PAGE_MASK))

#ifdef CONFIG_X86_64
#define REMAP_DEFAULT_SIZE  (255 << 20)
#else
#define REMAP_DEFAULT_SIZE  (100 << 20)
#endif
#define REMAP_MEM_SIZE    ((mods_get_mem4g() << 20) ? \
                           (mods_get_mem4g() << 20) : REMAP_DEFAULT_SIZE)

#define REMAP_VM_START      ((NvU64)(unsigned long)(vm_start))
#define REMAP_VM_END        (REMAP_VM_START + REMAP_MEM_SIZE)

#define P2M(x) ((x) >> (20 - PAGE_SHIFT))

static spinlock_t km_lock;
static NvU32 km_usage;

static struct list_head km_list;
static struct page * mods_alloc_highpages(int order);
static NvU64 mods_get_mpage(int order);
static NvU64 mods_virt_tophys(NvU64 addr);
static void mods_free_hpage(NvU64 addr);


/* Add mem=3G in cmdline of grub to reserve the page above 4G.
 * Then directly map pages above 4G phys for mods use
 * mods_vmlist will record the used addr range.
 */
struct mods_vm_struct {
     struct mods_vm_struct   *next;
     NvU64               addr;
     unsigned long       size;
     unsigned long       flags;
     struct page         **pages;
     unsigned int        nr_pages;
     NvU64               phys_addr;
};

struct mem_tracker
{
    void    *addr;
    NvU32    size;
    const char *file;
    NvU32    line;
    struct list_head list;
};

static struct mods_vm_struct *mods_vmlist;
static rwlock_t mods_vmlist_lock;
static void *vm_start;

/************************************************************************ */
/************************************************************************ */
/**  Kernel memory allocation tracker                                     */
/**  Register all the allocation from the beginning and inform            */
/**  about the memory leakage at unload time                              */
/************************************************************************ */
/************************************************************************ */

/*********************
 * PRIVATE FUNCTIONS *
 *********************/
static void mods_list_mem(void)
{
    struct list_head    *head = &km_list;
    struct list_head    *iter;
    struct mem_tracker  *pmem_t;

    list_for_each(iter, head)
    {
        pmem_t = list_entry(iter, struct mem_tracker, list);

        mods_debug_printk(DEBUG_MEM, "leak: virt %p, size 0x%x, allocated by %s:%d\n",
                          pmem_t->addr,
                          (unsigned int) pmem_t->size,
                          pmem_t->file,
                          (unsigned int) pmem_t->line);
    }
}

static void mods_del_list_mem(void)
{
    struct list_head    *head = &km_list;
    struct list_head    *iter;
    struct list_head    *tmp;
    struct mem_tracker  *pmem_t;

    list_for_each_safe(iter, tmp, head)
    {
        pmem_t = list_entry(iter, struct mem_tracker, list);

        /* free the memory */
        list_del(iter);
        MODS_FORCE_KFREE(pmem_t->addr);
        MEMDBG_FREE(pmem_t);
    }
}

/* allocate page using GFP_HIGHMEM */
static struct page * mods_alloc_highpages(int order)
{
    struct page *page = NULL;
    LOG_ENT();

    __MODS_ALLOC_PAGES(page, order, __GFP_HIGHMEM);
    if (!page)
    {
        mods_error_printk("unable to alloc high page\n");
        return NULL;
    }

    LOG_EXT();
    return page;
}

/* get mapped pages */
static NvU64 mods_get_mpage(int order)
{
    struct mods_vm_struct **p, *tmp, *area;
    NvU64 align = 1;
    NvU64 addr;
    unsigned long size = (1 << order) * PAGE_SIZE;
    NvU64 start = REMAP_VM_START;
    NvU64 end = REMAP_VM_END;
    int bit = fls(size);

    LOG_ENT();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
    if (bit > IOREMAP_MAX_ORDER)
        bit = IOREMAP_MAX_ORDER;
    else
#endif
        if (bit < PAGE_SHIFT)
            bit = PAGE_SHIFT;

    align = 1ull << bit;

    if (start < VMALLOC_START)
    {
        mods_error_printk("invalid vm_start %p\n", vm_start);
        return 0;
    }

    addr = ALIGN(start, align);
    size = PAGE_ALIGN(size);
    mods_debug_printk(DEBUG_MEM_DETAILED, "addr: 0x%llx size: 0x%lx\n", addr, size);
    if (unlikely(!size))
        return 0;

    MODS_KMALLOC(area, sizeof(*area));
    if (unlikely(!area))
        return 0;

    /* we always allocate a guard page. */
    size += PAGE_SIZE;

    write_lock(&mods_vmlist_lock);
    for (p = &mods_vmlist; (tmp = *p) != NULL ;p = &tmp->next)
    {
        if (tmp->addr < addr)
        {
            if(tmp->addr + tmp->size >= addr)
                addr = ALIGN(tmp->size + tmp->addr, align);
            continue;
        }
        if ((size + addr) < addr)
            goto out;
        if (size + addr <= tmp->addr)
            goto found;
        addr = ALIGN(tmp->size + tmp->addr, align);
        if (addr > end - size)
            goto out;
    }
    if ((size + addr) < addr)
        goto out;
    if (addr > end - size)
        goto out;

found:
    area->next = *p;
    *p = area;

    area->addr = addr;
    area->size = size;
    area->pages = NULL;
    area->nr_pages = 0;
    area->phys_addr = REMAP_MEM_START + (addr - start) ;
    write_unlock(&mods_vmlist_lock);
    LOG_EXT_C("virt address 0x%llx, phys_addr 0x%llx, size 0x%lx\n",
              area->addr, area->phys_addr, size);
    return area->addr;

out:
    write_unlock(&mods_vmlist_lock);
    MODS_KFREE(area, sizeof(*area));

    if (printk_ratelimit())
        mods_warning_printk("allocation failed: out of vmalloc space - use "
                            "vmalloc=<size> to increase size\n");
    return 0;
}

static struct mods_vm_struct *__mods_find_vm_area(NvU64 addr)
{
    struct mods_vm_struct *tmp;

    for (tmp = mods_vmlist; tmp != NULL; tmp = tmp->next)
    {
         if (tmp->addr == addr)
            break;
    }

    return tmp;
}

static NvU64 mods_virt_tophys(NvU64 addr)
{
    struct mods_vm_struct *tmp = NULL;

    NvU64 phys = 0;

    read_lock(&mods_vmlist_lock);

    tmp = __mods_find_vm_area(addr);
    if (tmp)
        phys = tmp->phys_addr;

    read_unlock(&mods_vmlist_lock);

    if (!tmp)
        mods_error_printk("no mapping for virt 0x%llx\n", addr);

    return phys;
}

static struct mods_vm_struct *__mods_remove_vm_area(NvU64 addr)
{
    struct mods_vm_struct **p, *tmp;

    for (p = &mods_vmlist ; (tmp = *p) != NULL ;p = &tmp->next)
    {
         if (tmp->addr == addr)
             goto found;
    }
    return NULL;

found:
    *p = tmp->next;

    /* remove the guard page. */
    tmp->size -= PAGE_SIZE;
    return tmp;
}

static void mods_free_hpage(NvU64 addr)
{
    struct mods_vm_struct *v;

    LOG_ENT_C("addr 0x%llx\n", addr);

    write_lock(&mods_vmlist_lock);
    v = __mods_remove_vm_area(addr);
    write_unlock(&mods_vmlist_lock);
    if (!v)
    {
        mods_error_printk("bad virt 0x%llx\n", addr);
        return;
    }

    mods_debug_printk(DEBUG_MEM_DETAILED, "found va; addr 0x%llx, phys 0x%llx, size 0x%lx\n", 
            v->addr, v->phys_addr, v->size);

    MODS_KFREE(v, sizeof(*v));
    LOG_EXT();
}

static int mods_set_mem_type(NvU64 virtAddr, NvU64 pages, NvU32 type)
{
    if (type == MODS_MEMORY_UNCACHED)
    {
        return MODS_SET_MEMORY_UC(virtAddr, pages);
    }
    else if (type == MODS_MEMORY_WRITECOMBINE)
    {
        return MODS_SET_MEMORY_WC(virtAddr, pages);
    }
    return 0;
}

static int mods_restore_mem_type(NvU64 virtAddr, NvU64 pages, NvU32 typeOverride)
{
    if ((typeOverride == MODS_MEMORY_UNCACHED) ||
            (typeOverride == MODS_MEMORY_WRITECOMBINE))
    {
        return MODS_SET_MEMORY_WB(virtAddr, pages);
    }
    return 0;
}

static void mods_alloc_contig_sys_pages(PSYS_MEM_MODS_INFO p_mem_info)
{
    NvU32 order = 0;
    LOG_ENT();

    while ((1 << order) < p_mem_info->num_pages)
    {
        order++;
    }
    p_mem_info->order = order;

    MODS_GET_FREE_PAGES(p_mem_info->logical_addr, order,
        GFP_KERNEL | __GFP_COMP
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
        | (((p_mem_info->addr_bits & 0xff) == 32) ? __GFP_DMA32 : 0)
#endif
        );
    if (p_mem_info->logical_addr == 0)
    {
        mods_error_printk("get_free_pages with param order=%d\n", (int) order);
        LOG_EXT();
        return;
    }

    mods_debug_printk(DEBUG_MEM_DETAILED, "get_free_pages allocated 2^%d pages\n",
                      (int) order);

    p_mem_info->phys_addr = __pa(p_mem_info->logical_addr);
    if (p_mem_info->phys_addr == 0)
    {
        mods_error_printk("alloc_contig_sys_pages: failed to lookup"
                          " physical address\n");

        MODS_FREE_PAGES(p_mem_info->logical_addr, order);
        p_mem_info->logical_addr = 0;
    }
    if (mods_set_mem_type(p_mem_info->logical_addr, 1<<order, p_mem_info->cache_type))
    {
        mods_error_printk("alloc_contig_sys_pages: failed to set caching type\n");
        MODS_FREE_PAGES(p_mem_info->logical_addr, order);
        p_mem_info->logical_addr = 0;
        LOG_EXT();
        return;
    }
    LOG_EXT();
}

static void mods_free_contig_sys_mem(PSYS_MEM_MODS_INFO p_mem_info)
{
    if (p_mem_info->p_page)
    {
        mods_restore_mem_type(p_mem_info->logical_addr, 1<<p_mem_info->order,
                p_mem_info->cache_type);
        __MODS_FREE_PAGES(p_mem_info->p_page, p_mem_info->order);
    }
    else
    {
        if (p_mem_info->logical_addr >= VMALLOC_START)
        {
            mods_free_hpage(p_mem_info->logical_addr);
        }
        else
        {
            mods_restore_mem_type(p_mem_info->logical_addr, 1<<p_mem_info->order,
                    p_mem_info->cache_type);
            MODS_FREE_PAGES(p_mem_info->logical_addr, p_mem_info->order);
        }
    }
}

static void mods_free_noncontig_sys_mem(PSYS_MEM_MODS_INFO p_mem_info)
{
    int i;
    int ptaSize;
    PSYS_PAGE_TABLE pt;

    ptaSize = p_mem_info->num_pages * sizeof(PSYS_PAGE_TABLE);

    if (p_mem_info->p_page_tbl)
    {
        for (i = 0; i < p_mem_info->num_pages; i++)
        {
            pt = p_mem_info->p_page_tbl[i];
            if (pt)
            {
                if (pt->k_virtual_addr)
                {
                    mods_restore_mem_type(pt->k_virtual_addr, 1,
                            p_mem_info->cache_type);
                    MODS_FREE_PAGES(pt->k_virtual_addr, 0);
                }
                MODS_KFREE(pt, sizeof(SYS_PAGE_TABLE));
            }
        }
        MODS_KFREE(p_mem_info->p_page_tbl, ptaSize);
        p_mem_info->p_page_tbl = 0;
    }
}

static void mods_alloc_contig_sys_hi_pages(PSYS_MEM_MODS_INFO p_mem_info)
{
    NvU32 order = 0;
    struct page *page = NULL;

    LOG_ENT();

    while ((1 << order) < p_mem_info->num_pages)
    {
        order++;
    }
    p_mem_info->order = order;
    mods_debug_printk(DEBUG_MEM_DETAILED, "parame order=0x%x\n", order);
    if (mods_get_highmem4g() == 1) /* get mem from remap area */
    {
        p_mem_info->logical_addr = mods_get_mpage(order);
        if (!p_mem_info->logical_addr)
        {
            mods_error_printk("p_mem_info->logical_addr  is NULL\n");
            return;
        }

        p_mem_info->phys_addr = mods_virt_tophys(p_mem_info->logical_addr);
        LOG_EXT();
        return;
    }

    page = mods_alloc_highpages(order);
    if (!page)
    {
        mods_error_printk("page is NULL\n");
        return;
    }
    p_mem_info->p_page = page;

    p_mem_info->phys_addr = page_to_phys(p_mem_info->p_page);
    p_mem_info->logical_addr = (NvU64)(unsigned long)page_address(p_mem_info->p_page);

    mods_debug_printk(DEBUG_MEM_DETAILED, "Get_free_pages allocated 2^%d pages, phys 0x%llx\n", (int) order,
            p_mem_info->phys_addr);
    
    if (p_mem_info->phys_addr == 0)
    {
        mods_error_printk("failed to lookup physical address\n");
        __MODS_FREE_PAGES(p_mem_info->p_page, order);
        p_mem_info->logical_addr = 0;
        p_mem_info->p_page = 0;
    }
    else if (mods_set_mem_type(p_mem_info->logical_addr, 1<<order, p_mem_info->cache_type))
    {
        mods_error_printk("failed to set caching type\n");
        __MODS_FREE_PAGES(p_mem_info->p_page, order);
        p_mem_info->logical_addr = 0;
        p_mem_info->p_page = 0;
    }

    LOG_EXT();
    return;
}

static void mods_alloc_noncontig_sys_pages(PSYS_MEM_MODS_INFO p_mem_info)
{
    int ptaSize;
    int i;
    PSYS_PAGE_TABLE pt;

    LOG_ENT();

    ptaSize = p_mem_info->num_pages * sizeof(PSYS_PAGE_TABLE);

    MODS_KMALLOC(p_mem_info->p_page_tbl, ptaSize);
    if (unlikely(!p_mem_info->p_page_tbl))
    {
        goto failed;
    }
    memset(p_mem_info->p_page_tbl, 0, ptaSize);

    /* allocate resources */
    for (i = 0; i < p_mem_info->num_pages; i++)
    {
        MODS_KMALLOC(p_mem_info->p_page_tbl[i], sizeof(SYS_PAGE_TABLE));
        if (unlikely(!p_mem_info->p_page_tbl[i]))
        {
            goto failed;
        }
        memset(p_mem_info->p_page_tbl[i], 0, sizeof(SYS_PAGE_TABLE));
    }

    /* alloc pages */
    for (i = 0; i < p_mem_info->num_pages; i++)
    {
        pt = p_mem_info->p_page_tbl[i];

        MODS_GET_FREE_PAGES(pt->k_virtual_addr, 0, GFP_KERNEL
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
            | (((p_mem_info->addr_bits & 0xff) == 32) ? __GFP_DMA32 : 0)
    #endif
            );
        if (pt->k_virtual_addr == 0)
        {
            mods_error_printk("can't allocate single page with "
                              "MODS_GET_FREE_PAGES\n");
            goto failed;
        }
        pt->phys_addr = __pa(pt->k_virtual_addr);
        if (pt->phys_addr == 0)
        {
            mods_error_printk("alloc_noncontig_sys_pages: failed to lookup "
                              "physical address\n");
            goto failed;
        }
        mods_debug_printk(DEBUG_MEM_DETAILED, "%d-th page is allocated, virtAddress="
                          "0x%llx, physAddress=0x%llx\n", i, 
                          p_mem_info->p_page_tbl[i]->k_virtual_addr, 
                          p_mem_info->p_page_tbl[i]->phys_addr);

        if (mods_set_mem_type(pt->k_virtual_addr, 1, p_mem_info->cache_type))
        {
            mods_error_printk("alloc_noncontig_sys_pages: failed to set caching "
                              "type to uncached\n");
            goto failed;
        }
    }

    return;

failed:
    mods_free_noncontig_sys_mem(p_mem_info);
}

static void mods_register_alloc(struct file *fp, PSYS_MEM_MODS_INFO p_mem_info)
{
    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    list_add(&p_mem_info->list, private_data->mods_alloc_list);
}

static void mods_unregister_and_free(struct file *fp, PSYS_MEM_MODS_INFO p_mem_infoRemove)
{
    PSYS_MEM_MODS_INFO  p_mem_info;

    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    struct list_head  *head = private_data->mods_alloc_list;
    struct list_head  *iter;

    list_for_each(iter, head)
    {
        p_mem_info = list_entry(iter, SYS_MEM_MODS_INFO, list);

        if (p_mem_infoRemove == p_mem_info)
        {
            if (p_mem_info->contiguous)
            {
                // was a contiguous alloc
                mods_free_contig_sys_mem(p_mem_info);
            }
            else
            {
                // was a normal, noncontiguous alloc
                mods_free_noncontig_sys_mem(p_mem_info);
            }

            // remove from the list
            list_del(iter);

            // free our data struct that keeps track of this allocation
            MODS_KFREE(p_mem_info, sizeof(SYS_MEM_MODS_INFO));

            return;
        }
    }

    mods_error_printk("mods_unregister_and_free: can't unregister allocation, it"
                      " doesn't exist");
}

/********************
 * PUBLIC FUNCTIONS *
 ********************/
void mods_init_mem(void)
{
    INIT_LIST_HEAD(&km_list);
    MODS_INIT_LOCK(km_lock);
    km_usage = 0;
}

/* implements mods kmalloc */
void mods_add_mem(void *addr, NvU32 size, const char *file, NvU32 line)
{
    struct mem_tracker *mem_t;
    unsigned long __eflags;

    MODS_LOCK_IRQ(km_lock, __eflags);

    km_usage += size;

    MEMDBG_ALLOC(mem_t, sizeof(struct mem_tracker));
    if (mem_t == NULL) {
        MODS_UNLOCK_IRQ(km_lock, __eflags);
        return;
    }
    mem_t->addr = addr;
    mem_t->size = size;
    mem_t->file = file;
    mem_t->line = line;

    list_add(&mem_t->list, &km_list);

    MODS_UNLOCK_IRQ(km_lock, __eflags);
}

/* implements mods kfree */
void mods_del_mem(void *addr, NvU32 size, const char* file, NvU32 line)
{
    struct list_head  *head = &km_list;
    struct list_head  *iter;
    struct mem_tracker *pmem_t;
    unsigned long __eflags;

    MODS_LOCK_IRQ(km_lock, __eflags);
    
    km_usage -= size;

    list_for_each(iter, head){
        pmem_t = list_entry(iter, struct mem_tracker, list);

        if (pmem_t->addr == addr)
        {
            if (pmem_t->size != size)
                mods_error_printk("mods_del_mem size mismatch on free\n");

            list_del(iter);
            MEMDBG_FREE(pmem_t);
            MODS_UNLOCK_IRQ(km_lock, __eflags);
            return;
        }
    }

    /* no allocation with given address */
    mods_error_printk("mods_del_mem no allocation with given address\n");
    MODS_UNLOCK_IRQ(km_lock, __eflags);
}

void mods_check_mem(void)
{
    if (km_usage != 0)
    {
        mods_warning_printk("memory leaks detected: 0x%x bytes\n", km_usage);
        mods_list_mem();
        mods_del_list_mem();
    }
}
int mods_map_pages(void)
{
    struct sysinfo val;
    unsigned int size;
    rwlock_init(&mods_vmlist_lock);

    LOG_ENT();

    si_meminfo(&val);
    size = P2M(val.totalram);
    mods_debug_printk(DEBUG_MEM_DETAILED, "memsize %dM\n", size);
    if (size > 4 * 1024)
    {
        mods_error_printk("the memory size should be not above 4G on remap "
                          "way\nbe sure that mem=nnG option is added to grub\n");
        return -ENOMEM;
    }

#ifdef CONFIG_X86_64
    vm_start = ioremap_nocache(REMAP_MEM_START,  REMAP_MEM_SIZE);
#else
    /* 32bit pae kernel */
    vm_start = (void *)(VMALLOC_START + 0x100000);
    /* false kernel virtual addresses, only for
     * memory region management.
     * Don't write any value into the region in
     * kernel space.
     */
#endif

    if (!vm_start)
    {
         mods_error_printk("can't ioremap 4G physical address\n");
         return -ENOMEM;
    }
    else
        printk(KERN_NOTICE"phys 0x%llx (size %dM)  is mapped to vir: %p\n",
                            REMAP_MEM_START, (unsigned int)(REMAP_MEM_SIZE >> 20), vm_start);

    mods_info_printk("driver loaded\n");
    LOG_EXT();
    return OK;
}

void mods_unmap_pages(void)
{
    struct mods_vm_struct **p, *tmp;

    LOG_ENT();

    for (p = &mods_vmlist ; (tmp = *p) != NULL; )
    {
        *p = tmp->next;
        mods_error_printk("warning remain vm: addr 0x%llx, phys 0x%llx, "
                          "size 0x%lx\n", tmp->addr, tmp->phys_addr,
                          tmp->size);

        MODS_KFREE(tmp, sizeof(*tmp));
    }

#ifdef CONFIG_X86_64
    iounmap(vm_start);
#endif
    vm_start = NULL;
    mods_set_highmem4g(0);
    LOG_EXT();
    return;
}

void mods_unregister_all_alloc(struct file *fp)
{
    PSYS_MEM_MODS_INFO  p_mem_info;

    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    struct list_head  *head = private_data->mods_alloc_list;
    struct list_head  *iter;
    struct list_head  *tmp;

    list_for_each_safe(iter, tmp, head)
    {
        p_mem_info = list_entry(iter, SYS_MEM_MODS_INFO, list);
        mods_unregister_and_free(fp, p_mem_info);
    }
}

/* Returns an offset of given physical address                             
 * If physical address doesn't belong to the allocation, returns ERROR     
 */
int mods_get_alloc_offset(PSYS_MEM_MODS_INFO p_mem_info, NvU64 physAddress, NvU32 *retOffset)
{
    int i;
    int offset = 0;

    if (p_mem_info->contiguous)
    {
        if (p_mem_info->phys_addr <= physAddress &&
            p_mem_info->phys_addr + p_mem_info->length > physAddress)
        {
            *retOffset = physAddress - p_mem_info->phys_addr;
            return OK;
        }
    }
    /* noncontiguous */
    else
    {
        /* One page at a time */
        for (i = 0; i < p_mem_info->num_pages; i++)
        {
            if (p_mem_info->p_page_tbl[i]->phys_addr <= physAddress &&
                 p_mem_info->p_page_tbl[i]->phys_addr + PAGE_SIZE > physAddress)
            {
                offset = offset + physAddress - p_mem_info->p_page_tbl[i]->phys_addr;
                *retOffset = offset;
                return OK;
            }
            offset += PAGE_SIZE;
        }
    }

    /* Physical address doesn't belong to the allocation */
    return ERROR;
}

PSYS_MEM_MODS_INFO mods_find_alloc(struct file *fp, NvU64 physAddress)
{
    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    struct list_head    *plistHead = private_data->mods_alloc_list;
    struct list_head    *plistIter;
    PSYS_MEM_MODS_INFO   p_mem_info;
    NvU32                offset;

    list_for_each(plistIter, plistHead)
    {
        p_mem_info = list_entry(plistIter, SYS_MEM_MODS_INFO, list);
        if (mods_get_alloc_offset(p_mem_info, physAddress, &offset) == OK)
        {
            /* physical address belongs to p_mem_info memory allocation */
            return p_mem_info;
        }
    }
    /* physical address doesn't belong to any memory allocation */
    return NULL;
}

/************************
 * ESCAPE CALL FUNCTONS *
 ************************/

/************************************************************************ */
/*  esc_mods_alloc_pages                                                  */
/************************************************************************ */
int esc_mods_alloc_pages(struct file *fp, MODS_ALLOC_PAGES *p)
{
    PSYS_MEM_MODS_INFO  p_mem_info;

    LOG_ENT();

    switch (p->Attrib)
    {
        case MODS_MEMORY_CACHED:
        case MODS_MEMORY_UNCACHED:
        case MODS_MEMORY_WRITECOMBINE:
            break;

        default:
            mods_error_printk("invalid memory type: %u\n", p->Attrib);
            return -EINVAL;
    }

    MODS_KMALLOC(p_mem_info, sizeof(SYS_MEM_MODS_INFO));
    if (unlikely(!p_mem_info))
    {
        LOG_EXT();
        return -ENOMEM;
    }

    p_mem_info->contiguous = p->Contiguous;
    p_mem_info->cache_type = p->Attrib;
    p_mem_info->length = p->NumBytes;
    p_mem_info->order = 0;
    p_mem_info->k_mapping_ref_cnt = 0;
    p_mem_info->logical_addr = 0;
    p_mem_info->p_page_tbl = NULL;
    p_mem_info->addr_bits = p->AddressBits;
    p_mem_info->p_page = NULL;
    p_mem_info->num_pages = 
        (p->NumBytes >> PAGE_SHIFT) + ((p->NumBytes & ~PAGE_MASK) ? 1 : 0);
    
    mods_debug_printk(DEBUG_MEM_DETAILED, "esc_mods_alloc_pages is going to allocate %d pages\n",
                      (int) p_mem_info->num_pages);

    p->MemoryHandle = 0;

    if (p->Contiguous)
    {
        if (p->AddressBits == 64 && mods_get_highmem4g())
        {
            mods_alloc_contig_sys_hi_pages(p_mem_info);
        }
        else
        {
            mods_alloc_contig_sys_pages(p_mem_info);
        }
        if (p_mem_info->logical_addr == 0 && p_mem_info->p_page == NULL)
        {
            mods_error_printk("failed to alloc contiguous system pages \n");
            MODS_KFREE(p_mem_info, sizeof(SYS_MEM_MODS_INFO));
            LOG_EXT();
            return -ENOMEM;
        }
    }
    else
    {
        mods_alloc_noncontig_sys_pages(p_mem_info);
        if (p_mem_info->p_page_tbl == NULL)
        {
            mods_error_printk("failed to alloc noncontiguous system pages \n");
            MODS_KFREE(p_mem_info, sizeof(SYS_MEM_MODS_INFO));
            LOG_EXT();
            return -ENOMEM;
        }
    }

    p->MemoryHandle = (NvU64) (long) p_mem_info;

    // Register the allocation of the memory
    mods_register_alloc(fp, p_mem_info);
    LOG_EXT();
    return OK;
}


/************************************************************************ */
/*  esc_mods_free_pages                                                        */
/************************************************************************ */
int esc_mods_free_pages(struct file *fp, MODS_FREE_PAGES *p)
{
    LOG_ENT();

    // unregister and free the allocation of the memory
    mods_unregister_and_free(fp, (PSYS_MEM_MODS_INFO) (long) p->MemoryHandle);

    LOG_EXT();

    return OK;
}

/************************************************************************ */
/*  esc_mods_set_mem_type                                                  */
/************************************************************************ */
int esc_mods_set_mem_type(struct file *fp, MODS_MEMORY_TYPE *p)
{
    PSYS_MEM_MODS_INFO p_mem_info;
    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);

    LOG_ENT();

    p_mem_info = mods_find_alloc(fp, p->PhysAddr);
    if (p_mem_info != NULL)
    {
        mods_error_printk("unable to change memory type of an address which was"
                          " already allocated!\n");
        LOG_EXT();
        return -EINVAL;
    }

    switch (p->Type)
    {
        case MODS_MEMORY_CACHED:
        case MODS_MEMORY_UNCACHED:
        case MODS_MEMORY_WRITECOMBINE:
            break;

        default:
            mods_error_printk("invalid memory type: %u\n", p->Type);
            LOG_EXT();
            return -EINVAL;
    }

    private_data->mem_type.phys_addr  = p->PhysAddr;
    private_data->mem_type.size = p->Size;
    private_data->mem_type.type = p->Type;

    LOG_EXT();
    return OK;
}

/************************************************************************ */
/*  esc_mods_get_phys_addr                                                     */
/************************************************************************ */
int esc_mods_get_phys_addr(struct file *fp, MODS_GET_PHYSICAL_ADDRESS *p)
{
    PSYS_MEM_MODS_INFO  p_mem_info = (PSYS_MEM_MODS_INFO) (long) p->MemoryHandle;
    NvU32   pageNr;
    NvU32   pageOffset;

    LOG_ENT();

    if (p_mem_info->contiguous)
    {
        p->PhysicalAddress = p_mem_info->phys_addr + p->Offset;
    }
    else
    {
        pageNr = p->Offset >> PAGE_SHIFT;
        pageOffset = p->Offset % PAGE_SIZE;

        if (pageNr >= p_mem_info->num_pages)
        {
            mods_error_printk("get_phys_addr query exceeds allocation's"
                              " boundary!\n");
            LOG_EXT();
            return -EINVAL;
        }
        mods_debug_printk(DEBUG_MEM_DETAILED, "esc_mods_get_phys_addr with offset=0x%x =>"
                          " pageNr=%d, pageOffset=0x%x\n", (int) p->Offset,
                          (int) pageNr, (int) pageOffset);

        p->PhysicalAddress = 0;
        p->PhysicalAddress = 
            p_mem_info->p_page_tbl[pageNr]->phys_addr + pageOffset;

        mods_debug_printk(DEBUG_MEM_DETAILED, "esc_mods_get_phys_addr: phys_addr "
                          "0x%llx, returned phys_addr 0x%llx\n",
                          p_mem_info->p_page_tbl[pageNr]->phys_addr,
                          p->PhysicalAddress);
    }
    LOG_EXT();
    return OK;
}


/************************************************************************ */
/*  esc_mods_virtual_to_phys                                                   */
/************************************************************************ */
int esc_mods_virtual_to_phys(struct file *fp, MODS_VIRTUAL_TO_PHYSICAL *p)
{
    MODS_GET_PHYSICAL_ADDRESS getPhysAddrData;
    PSYS_MAP_MEMORY p_map_mem;
    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    struct list_head *head = private_data->mods_mapping_list;
    struct list_head *iter;
    NvU32   phys_offset;
    NvU32   virt_offset;
    NvU32   rc;

    LOG_ENT_C("virtAddr=0x%llx \n", p->VirtualAddress);

    list_for_each(iter, head)
    {
        p_map_mem = list_entry(iter, SYS_MAP_MEMORY, list);

        if (p_map_mem->virtual_addr <= p->VirtualAddress &&
            p_map_mem->virtual_addr + p_map_mem->mapping_length 
            > p->VirtualAddress)
        {
            virt_offset = p->VirtualAddress - p_map_mem->virtual_addr;

            if (p_map_mem->contiguous)
            {
                p->PhysicalAddress = p_map_mem->phys_addr + virt_offset;
                LOG_EXT_C("phys: 0x%llx\n", p->PhysicalAddress);
                return OK;
            }
            /* memory noncontiguous */
            else
            {
                if (mods_get_alloc_offset(p_map_mem->p_mem_info,
                                          p_map_mem->phys_addr,
                                          &phys_offset) != OK)
                    return -EINVAL;

                getPhysAddrData.MemoryHandle = (NvU64) (long) p_map_mem->p_mem_info;
                getPhysAddrData.Offset = virt_offset + phys_offset;

                rc = esc_mods_get_phys_addr(fp, &getPhysAddrData);
                if (rc != OK)
                    return rc;

                p->PhysicalAddress = getPhysAddrData.PhysicalAddress;
                LOG_EXT_C("phys: 0x%llx\n", p->PhysicalAddress);
                return OK;
            }
        }
    }

    mods_error_printk("esc_mods_virtual_to_phys query has invalid virtual address, "
                      "mapping doesn't exist \n");
    return -EINVAL;
}


/************************************************************************ */
/*  esc_mods_phys_to_virtual                                                   */
/************************************************************************ */
int esc_mods_phys_to_virtual(struct file *fp, MODS_PHYSICAL_TO_VIRTUAL *p)
{
    PSYS_MAP_MEMORY p_map_mem;
    mods_file_private_data *private_data = MODS_GET_FILE_PRIVATE(fp);
    struct list_head *head = private_data->mods_mapping_list;
    struct list_head *iter;
    NvU32   offset;
    NvU32   map_offset;

    LOG_ENT_C("physAddr=0x%llx\n", p->PhysicalAddress);

    list_for_each(iter, head)
    {
        p_map_mem = list_entry(iter, SYS_MAP_MEMORY, list);

        if (p_map_mem->contiguous)
        {
            if(p_map_mem->phys_addr <= p->PhysicalAddress &&
               p_map_mem->phys_addr + p_map_mem->mapping_length 
               > p->PhysicalAddress)
            {
                offset = p->PhysicalAddress - p_map_mem->phys_addr;
                p->VirtualAddress = p_map_mem->virtual_addr + offset;
                LOG_EXT_C("virt:0x%llx\n", p->VirtualAddress);
                return OK;
            }
        }
        /* noncontiguous memory */
        else
        {
            if (mods_get_alloc_offset(p_map_mem->p_mem_info, p->PhysicalAddress,
                                      &offset) == OK)
            {
                /* offset the mapping starts from */
                if (mods_get_alloc_offset(p_map_mem->p_mem_info, 
                                          p_map_mem->phys_addr,
                                          &map_offset) == OK)
                {
                    if (map_offset <= offset && map_offset + p_map_mem->mapping_length > offset)
                    {
                        p->VirtualAddress = p_map_mem->virtual_addr + offset - map_offset;
                        LOG_EXT_C("virt:0x%llx\n", p->VirtualAddress);
                        return OK;
                    }
                }
            }
        }
    }
    mods_error_printk("esc_mods_virtual_to_phys query has invalid phys_addr, "
                      "mapping doesn't exist \n");
    return -EINVAL;
}
