/*
 * mods_irq.c - This file is part of NVIDIA MODS kernel driver.
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

#include "mods.h"
#include "driverAPI.h"
#include <linux/sched.h>

#define PCI_VENDOR_ID_NVIDIA 0x10de
#define INDEX_IRQSTAT(irq)  (irq / BITS_NUM)
#define POS_IRQSTAT(irq)     (irq & ( BITS_NUM - 1))

struct nv_device
{
    char name[20];
    struct mods_priv * isrPri;
    void *pri[MODS_CHANNEL_MAX];
};

/*********************
 * PRIVATE FUNCTIONS *
 *********************/
static struct mods_priv mp;
static struct nv_device nv_dev = { "nvidia mods", &mp, {0} };

static struct mods_priv *get_all_data(void)
{
    return &mp;
}

static struct nv_device *get_dev(void)
{
    return &nv_dev;
}

static int mods_enable_device(mods_file_private_data *priv, struct pci_dev *pdev)
{
    int ret = -1;
    struct en_dev_entry *entry = priv->enabled_devices;
    while (entry != 0)
    {
        if (entry->dev == pdev)
        {
            return 0;
        }
        entry = entry->next;
    }

    ret = MODS_PCI_ENABLE_DEVICE(pdev);
    if (ret == 0)
    {
        entry = 0;
        MODS_KMALLOC(entry, sizeof(*entry));
        if (unlikely(!entry))
            return 0;
        entry->dev = pdev;
        entry->next = priv->enabled_devices;
        priv->enabled_devices = entry;
    }
    return ret;
}

static unsigned int get_cur_time(void)
{
    /* This is not very precise, sched_clock() would be better */
    return jiffies_to_usecs(jiffies);
}

static int id_is_valid(unsigned char channel)
{
    if (channel <= 0 || channel > MODS_CHANNEL_MAX)
        return ERROR;

    return OK;
}

static inline int mods_check_interrupt(struct dev_irq_map *t)
{
    if (t->dev_irq_state && t->dev_irq_enabled)
    {
        /* GPU device */
        return *t->dev_irq_state && *t->dev_irq_enabled;
    }
    else
    {
        /* Non-GPU device - we can't tell */
        return true;
    }
}

static void mods_disable_interrupts(struct dev_irq_map *t)
{
    if (t->dev_irq_enabled)
    {
        *t->dev_irq_enabled = 0;
    }
}

static void rec_irq_done(struct nv_device *dev, unsigned char channel,
                         struct dev_irq_map *t, unsigned int irq_time)
{
    struct irq_q_info *q;
    struct mods_priv *pmp = dev->isrPri;
    mods_file_private_data *private_data = dev->pri[channel];

    /* Get interrupt queue */
    q = &pmp->rec_info[channel - 1];

    /* Don't do anything if the IRQ has already been recorded */
    if (q->head != q->tail)
    {
        unsigned int i;
        for (i = q->head; i != q->tail; i++)
        {
            if (t->dev)
            {
                if (q->data[i & (MODS_MAX_IRQS - 1)].dev == t->dev)
                    return;
            }
            else
            {
                if (q->data[i & (MODS_MAX_IRQS - 1)].irq == t->apic_irq)
                    return;
            }
        }
    }

    /* Print an error if the queue is full */
    /* This is deadly! */
    if (q->tail - q->head == MODS_MAX_IRQS)
    {
        mods_error_printk("IRQ queue is full\n");
        return;
    }

    /* Record the device which generated the IRQ in the queue */
    q->data[q->tail & (MODS_MAX_IRQS - 1)].dev = t->dev;
    q->data[q->tail & (MODS_MAX_IRQS - 1)].irq = t->apic_irq;
    q->data[q->tail & (MODS_MAX_IRQS - 1)].time = irq_time;
    q->tail++;

    if (t->dev)
    {
        mods_debug_printk(DEBUG_ISR_DETAILED,
            "%s IRQ 0x%x for %x:%02x.%x, time=%uus\n",
            (t->type == MODS_IRQ_TYPE_MSI) ? "MSI" : "INTx",
            t->apic_irq,
            (unsigned)MODS_PCI_BUS_NUMBER(t->dev),
            (unsigned)MODS_PCI_SLOT_NUMBER(t->dev),
            (unsigned)MODS_PCI_FUNCTION_NUMBER(t->dev),
            irq_time);
    }
    else
    {
        mods_debug_printk(DEBUG_ISR_DETAILED,
            "CPU IRQ 0x%x, time=%uus\n",
            t->apic_irq,
            irq_time);
    }

    /* Wake MODS to handle the interrupt */
    if (private_data)
    {
        MODS_UNLOCK(pmp->lock);
        wake_up_interruptible(&private_data->interrupt_event);
        MODS_LOCK(pmp->lock);
    }
}

/* mods_irq_handle - interrupt function */
static irqreturn_t mods_irq_handle(int irq, void *data
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
            ,struct pt_regs *regs
#endif
)
{
    struct nv_device *dev = (struct nv_device *)data;
    struct mods_priv *pmp = dev->isrPri;
    struct dev_irq_map *t = NULL;
    unsigned char channel_idx;
    unsigned long flags;
    int found = 0;
    unsigned int irq_time = get_cur_time();

    MODS_LOCK_IRQ(pmp->lock, flags);

    for (channel_idx=0; channel_idx < MODS_CHANNEL_MAX; channel_idx++)
    {
        if (!(pmp->channel_flags & (1 << channel_idx)))
            continue;

        list_for_each_entry(t, &pmp->irq_head[channel_idx], list)
        {
            if ((t->apic_irq == irq) && mods_check_interrupt(t))
            {
                /* Disable interrupts on this device to prevent interrupt storm */
                mods_disable_interrupts(t);

                /* Record IRQ for MODS and wake MODS up */
                rec_irq_done(dev, channel_idx+1, t, irq_time);
                found |= 1;

                /* MSI and CPU interrupts are not shared, so stop looking */
                if (t->type != MODS_IRQ_TYPE_INT)
                {
                    channel_idx = MODS_CHANNEL_MAX;
                    break;
                }
            }
        }
    }

    MODS_UNLOCK_IRQ(pmp->lock, flags);
    return IRQ_RETVAL(found);
}

static int mods_lookup_irq(unsigned char channel, struct pci_dev *pdev, unsigned int irq)
{
    unsigned char channel_idx;
    struct mods_priv *pmp = get_all_data();
    int ret = IRQ_NOT_FOUND;

    LOG_ENT();

    for (channel_idx=0; channel_idx < MODS_CHANNEL_MAX; channel_idx++)
    {
        struct dev_irq_map *t = NULL;
        struct dev_irq_map *next = NULL;
        list_for_each_entry_safe(t, next, &pmp->irq_head[channel_idx], list)
        {
            if ((pdev && (t->dev == pdev))
                || (!pdev && (t->apic_irq == irq)))
            {
                if (channel == 0)
                {
                    ret = IRQ_FOUND;
                }
                else
                {
                    ret = (channel == channel_idx + 1) ? IRQ_FOUND : IRQ_NOT_FOUND;
                }

                // Break out of the outer loop
                channel_idx = MODS_CHANNEL_MAX;
                break;
            }
        }
    }

    LOG_EXT();
    return ret;
}

static int add_irq_map(unsigned char channel, struct pci_dev *pdev, NvU32 irq, unsigned int type)
{
    struct dev_irq_map *newmap = NULL;
    struct mods_priv *pmp = get_all_data();
    struct nv_device *nvdev = get_dev();
    unsigned short class_code;

    LOG_ENT();

    /* Allocate memory for the new entry */
    MODS_KMALLOC(newmap, sizeof(*newmap));
    if (unlikely(!newmap))
    {
        LOG_EXT();
        return -ENOMEM;
    }

    /* Fill out the new entry */
    newmap->apic_irq = irq;
    newmap->dev = pdev;
    newmap->channel = channel;
    newmap->dev_irq_enabled = 0;
    newmap->dev_irq_state = 0;
    newmap->type = type;

    /* Enable IRQ for this device in the kernel */
    if (request_irq(
            irq,
            &mods_irq_handle,
            (type == MODS_IRQ_TYPE_INT) ? IRQF_SHARED : 0,
            nvdev->name,
            nvdev))
    {
        mods_error_printk("unable to enable IRQ 0x%x\n", irq);
        MODS_KFREE(newmap, sizeof(*newmap));
        LOG_EXT();
        return ERROR;
    }

    /* Add the new entry to the list of all registered interrupts */
    list_add(&newmap->list, &pmp->irq_head[channel - 1]);

    /* Map BAR0 of a graphics card to be able to disable interrupts */
    if (type == MODS_IRQ_TYPE_INT)
    {
        MODS_PCI_READ_CONFIG_WORD(pdev, PCI_CLASS_DEVICE, &class_code);
        if ((class_code == PCI_CLASS_DISPLAY_VGA) || (class_code == PCI_CLASS_DISPLAY_3D))
        {
            char* bar0 = ioremap_nocache(pci_resource_start(pdev, 0), 0x200);
            newmap->dev_irq_enabled = (NvU32*)(bar0 + 0x140);
            newmap->dev_irq_state = (NvU32*)(bar0 + 0x100);
        }
    }

    /* Print out successful registration string */
    if (type == MODS_IRQ_TYPE_INT)
    {
        mods_debug_printk(DEBUG_ISR, "registered INTx IRQ 0x%x for device %x:%02x.%x\n",
                pdev->irq,
                (unsigned)MODS_PCI_BUS_NUMBER(pdev),
                (unsigned)MODS_PCI_SLOT_NUMBER(pdev),
                (unsigned)MODS_PCI_FUNCTION_NUMBER(pdev));
    }
#ifdef CONFIG_PCI_MSI
    else if (type == MODS_IRQ_TYPE_MSI)
    {
        u16 control;
        u16 data;
        int cap_pos = MODS_PCI_FIND_CAPABILITY(pdev, PCI_CAP_ID_MSI);
        MODS_PCI_READ_CONFIG_WORD(pdev, MSI_CONTROL_REG(cap_pos), &control);
        if (IS_64BIT_ADDRESS(control))
            MODS_PCI_READ_CONFIG_WORD(pdev, MSI_DATA_REG(cap_pos, 1), &data);
        else
            MODS_PCI_READ_CONFIG_WORD(pdev, MSI_DATA_REG(cap_pos, 0), &data);
        mods_debug_printk(DEBUG_ISR, "registered MSI IRQ 0x%x with data 0x%02x for device %x:%02x.%x\n",
                pdev->irq,
                (unsigned)data,
                (unsigned)MODS_PCI_BUS_NUMBER(pdev),
                (unsigned)MODS_PCI_SLOT_NUMBER(pdev),
                (unsigned)MODS_PCI_FUNCTION_NUMBER(pdev));
    }
#endif
    else if (type == MODS_IRQ_TYPE_CPU)
    {
        mods_debug_printk(DEBUG_ISR, "registered CPU IRQ 0x%x\n", irq);
    }

    LOG_EXT();
    return OK;
}

static void mods_free_map(struct dev_irq_map *del)
{
    LOG_ENT();

    /* Disable interrupts on the device */
    mods_disable_interrupts(del);

    /* Unmap graphics device registers */
    if (del->dev_irq_state)
    {
        iounmap(((char*)del->dev_irq_state) - 0x100);
    }

    /* Unhook interrupts in the kernel */
    free_irq(del->apic_irq, get_dev());

    /* Disable MSI */
#ifdef CONFIG_PCI_MSI
    if (del->type == MODS_IRQ_TYPE_MSI)
    {
        MODS_PCI_DISABLE_MSI(del->dev);
    }
#endif

    /* Free memory */
    MODS_KFREE(del, sizeof(*del));

    LOG_EXT();
}

/*******************
* PUBLIC FUNCTIONS *
********************/
void mods_init_irq(void)
{
    int i;
    struct mods_priv *pmp = get_all_data();

    LOG_ENT();

    memset(pmp, 0, sizeof(struct mods_priv));
    for (i = 0; i < MODS_CHANNEL_MAX; i++)
    {
        INIT_LIST_HEAD(&pmp->irq_head[i]);
    }

    MODS_INIT_LOCK(pmp->lock);
    LOG_EXT();
}

void mods_cleanup_irq(void)
{
    int i;
    struct mods_priv *pmp = get_all_data();

    LOG_ENT();
    for (i = 0; i < MODS_CHANNEL_MAX; i++)
    {
        if (pmp->channel_flags && (1 << i))
            mods_free_channel(i + 1);
    }
    LOG_EXT();
}

void mods_irq_dev_set_pri(unsigned char id, void *pri)
{
    struct nv_device * dev = get_dev();
    dev->pri[id] = pri;
}

void mods_irq_dev_clr_pri(unsigned char id)
{
    struct nv_device * dev = get_dev();
    dev->pri[id] = 0;
}

int mods_irq_event_check(unsigned char channel)
{
    struct mods_priv *pmp = get_all_data();
    struct irq_q_info *q = &pmp->rec_info[channel - 1];
    unsigned int pos = (1 << (channel - 1));

    if (!(pmp->channel_flags & pos))
        return POLLERR; /* irq has quit */

    if (q->head != q->tail)
        return POLLIN; /* irq generated */

    return 0;
}

unsigned char mods_alloc_channel(void)
{
    struct mods_priv *pmp = get_all_data();
    int i = 0;
    unsigned char channel = MODS_CHANNEL_MAX + 1;
    unsigned char max_channels = mods_get_multi_instance() ? MODS_CHANNEL_MAX : 1;

    LOG_ENT();

    for (i = 0; i < max_channels; i++)
    {
        if (!test_and_set_bit(i, &pmp->channel_flags))
        {
            channel = i + 1;
            mods_debug_printk(DEBUG_IOCTL, "open channel %u (bit mask 0x%lx)\n",
                              (unsigned)(i+1), pmp->channel_flags);
            break;
        }

    }

    LOG_EXT();
    return channel;
}

void mods_free_channel(unsigned char channel)
{
    struct mods_priv *pmp = get_all_data();
    struct dev_irq_map *del = NULL;
    struct dev_irq_map *next = NULL;
    struct irq_q_info *q = &pmp->rec_info[channel - 1];

    LOG_ENT();

    /* Release all interrupts */
    list_for_each_entry_safe(del, next, &pmp->irq_head[channel - 1], list)
    {
        list_del(&del->list);
        mods_warning_printk("%s IRQ 0x%x for device %x:%02x.%x is still hooked, unhooking\n",
                (del->type == MODS_IRQ_TYPE_MSI) ? "MSI" : "INTx",
                del->dev->irq,
                (unsigned)MODS_PCI_BUS_NUMBER(del->dev),
                (unsigned)MODS_PCI_SLOT_NUMBER(del->dev),
                (unsigned)MODS_PCI_FUNCTION_NUMBER(del->dev));
        mods_free_map(del);
    }

    /* Clear queue */
    memset(q, 0, sizeof(*q));

    /* Indicate the channel is free */
    clear_bit(channel - 1, &pmp->channel_flags);

    mods_debug_printk(DEBUG_IOCTL, "closed channel %u\n", (unsigned)channel);
    LOG_EXT();
}

static int mods_register_pci_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    struct pci_dev *dev;
    unsigned int devfn;
    unsigned char channel;

    LOG_ENT();

    /* Identify the caller */
    channel = MODS_GET_FILE_PRIVATE_ID(pfile);
    assert(id_is_valid(channel) == OK);

    /* Get the PCI device structure for the specified device from the kernel */
    devfn = PCI_DEVFN(p->dev.device, p->dev.function);
    dev = MODS_PCI_GET_SLOT(p->dev.bus, devfn);
    if (!dev)
    {
        LOG_EXT();
        return ERROR;
    }

    /* Determine if the interrupt is already hooked */
    if (mods_lookup_irq(0, dev, 0) == IRQ_FOUND)
    {
        mods_error_printk("IRQ for device %x:%02x.%x has already been registered\n",
                (unsigned)p->dev.bus, (unsigned)p->dev.device, (unsigned)p->dev.function);
        LOG_EXT();
        return ERROR;
    }

    /* Determine if the device supports MSI */
    if (p->type == MODS_IRQ_TYPE_MSI)
    {
#ifdef CONFIG_PCI_MSI
        if (0 == MODS_PCI_FIND_CAPABILITY(dev, PCI_CAP_ID_MSI))
        {
            mods_error_printk("device %x:%02x.%x does not support MSI\n",
                    (unsigned)p->dev.bus, (unsigned)p->dev.device, (unsigned)p->dev.function);
            LOG_EXT();
            return ERROR;
        }
#else
        mods_error_printk("MSI interrupts requested, "
                "but the kernel has not been configured to support them!\n");
        return ERROR;
#endif
    }

    /* Enable device on the PCI bus */
    if (mods_enable_device(MODS_GET_FILE_PRIVATE(pfile), dev))
    {
        mods_error_printk("unable to enable device %x:%02x.%x\n",
                (unsigned)p->dev.bus, (unsigned)p->dev.device, (unsigned)p->dev.function);
        LOG_EXT();
        return ERROR;
    }

    /* Enable MSI */
#ifdef CONFIG_PCI_MSI
    if (p->type == MODS_IRQ_TYPE_MSI)
    {
        if (0 != MODS_PCI_ENABLE_MSI(dev))
        {
            mods_error_printk("unable to enable MSI on device %x:%02x.%x\n",
                    (unsigned)p->dev.bus, (unsigned)p->dev.device, (unsigned)p->dev.function);
            return ERROR;
        }
    }
#endif

    /* Register interrupt */
    if (add_irq_map(channel, dev, dev->irq, p->type) != OK)
    {
#ifdef CONFIG_PCI_MSI
        if (p->type == MODS_IRQ_TYPE_MSI)
        {
            MODS_PCI_DISABLE_MSI(dev);
        }
#endif
        LOG_EXT();
        return ERROR;
    }

    return OK;
}

static int mods_register_cpu_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    unsigned char channel;
    unsigned int irq;

    LOG_ENT();

    irq = p->dev.bus;

    /* Identify the caller */
    channel = MODS_GET_FILE_PRIVATE_ID(pfile);
    assert(id_is_valid(channel) == OK);

    /* Determine if the interrupt is already hooked */
    if (mods_lookup_irq(0, 0, irq) == IRQ_FOUND)
    {
        mods_error_printk("CPU IRQ 0x%x has already been registered\n", irq);
        LOG_EXT();
        return ERROR;
    }

    /* Register interrupt */
    if (add_irq_map(channel, 0, irq, p->type) != OK)
    {
        LOG_EXT();
        return ERROR;
    }

    return OK;
}

static int mods_unregister_pci_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    struct mods_priv *pmp = get_all_data();
    struct dev_irq_map *del = NULL;
    struct dev_irq_map *next;
    struct pci_dev *dev;
    unsigned int devfn;
    unsigned char channel;

    LOG_ENT();

    /* Identify the caller */
    channel = MODS_GET_FILE_PRIVATE_ID(pfile);
    assert(id_is_valid(channel) == OK);

    /* Get the PCI device structure for the specified device from the kernel */
    devfn = PCI_DEVFN(p->dev.device, p->dev.function);
    dev = MODS_PCI_GET_SLOT(p->dev.bus, devfn);
    if (!dev)
    {
        LOG_EXT();
        return ERROR;
    }

    /* Determine if the interrupt is already hooked by this client */
    if (mods_lookup_irq(channel, dev, 0) == IRQ_NOT_FOUND)
    {
        mods_error_printk("unable to unhook IRQ for device %x:%02x.%x as it has not been registered\n",
                (unsigned)p->dev.bus, (unsigned)p->dev.device, (unsigned)p->dev.function);
        LOG_EXT();
        return ERROR;
    }

    /* Delete device interrupt from the list */
    list_for_each_entry_safe(del, next, &pmp->irq_head[channel - 1], list)
    {
        if (dev == del->dev)
        {
            if (del->type != p->type)
            {
                mods_error_printk("wrong IRQ type passed\n");
                LOG_EXT();
                return ERROR;
            }
            list_del(&del->list);
            mods_debug_printk(DEBUG_ISR, "unregistered %s IRQ 0x%x for device %x:%02x.%x\n",
                    (del->type == MODS_IRQ_TYPE_MSI) ? "MSI" : "INTx",
                    del->dev->irq,
                    (unsigned)p->dev.bus,
                    (unsigned)p->dev.device,
                    (unsigned)p->dev.function);
            mods_free_map(del);
            break;
        }
    }

    LOG_EXT();
    return OK;
}

static int mods_unregister_cpu_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    struct mods_priv *pmp = get_all_data();
    struct dev_irq_map *del = NULL;
    struct dev_irq_map *next;
    unsigned int irq;
    unsigned char channel;

    LOG_ENT();

    irq = p->dev.bus;

    /* Identify the caller */
    channel = MODS_GET_FILE_PRIVATE_ID(pfile);
    assert(id_is_valid(channel) == OK);

    /* Determine if the interrupt is already hooked by this client */
    if (mods_lookup_irq(channel, 0, irq) == IRQ_NOT_FOUND)
    {
        mods_error_printk(
                "unable to unhook IRQ 0x%x as it has not been registered\n",
                irq);
        LOG_EXT();
        return ERROR;
    }

    /* Delete device interrupt from the list */
    list_for_each_entry_safe(del, next, &pmp->irq_head[channel - 1], list)
    {
        if ((irq == del->apic_irq) && (del->dev == 0))
        {
            if (del->type != p->type)
            {
                mods_error_printk("wrong IRQ type passed\n");
                LOG_EXT();
                return ERROR;
            }
            list_del(&del->list);
            mods_debug_printk(DEBUG_ISR, "unregistered CPU IRQ 0x%x\n",
                    irq);
            mods_free_map(del);
            break;
        }
    }

    LOG_EXT();
    return OK;
}

/*************************
 * ESCAPE CALL FUNCTIONS *
 *************************/

/************************************************************************ */
/*  esc_mods_register_irq                                                 */
/************************************************************************ */
int esc_mods_register_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    if (p->type == MODS_IRQ_TYPE_CPU)
    {
        return mods_register_cpu_irq(pfile, p);
    }
    else
    {
        return mods_register_pci_irq(pfile, p);
    }
}

/************************************************************************ */
/*  esc_mods_unregister_irq                                               */
/************************************************************************ */
int esc_mods_unregister_irq(struct file *pfile, MODS_REGISTER_IRQ *p)
{
    if (p->type == MODS_IRQ_TYPE_CPU)
    {
        return mods_unregister_cpu_irq(pfile, p);
    }
    else
    {
        return mods_unregister_pci_irq(pfile, p);
    }
}

/************************************************************************ */
/*  esc_mods_query_irq                                                    */
/************************************************************************ */
int esc_mods_query_irq(struct file *pfile, MODS_QUERY_IRQ *p)
{
    unsigned char channel;
    struct irq_q_info *q = NULL;
    struct mods_priv *pmp = get_all_data();
    unsigned int i = 0;
    unsigned long flags;
    unsigned int cur_time = get_cur_time();

    /* Lock IRQ queue */
    MODS_LOCK_IRQ(pmp->lock, flags);
    LOG_ENT();

    /* Identify the caller */
    channel = MODS_GET_FILE_PRIVATE_ID(pfile);
    assert(id_is_valid(channel) == OK);

    /* Clear return array */
    memset(p->irq_list, 0xFF, sizeof(p->irq_list));

    /* Fill in return array with IRQ information */
    q = &pmp->rec_info[channel - 1];
    for (i=0; (q->head != q->tail) && (i < MODS_MAX_IRQS); q->head++, i++)
    {
        unsigned int index = q->head & (MODS_MAX_IRQS - 1);
        struct pci_dev *dev = q->data[index].dev;
        if (dev)
        {
            p->irq_list[i].dev.bus = MODS_PCI_BUS_NUMBER(dev);
            p->irq_list[i].dev.device = MODS_PCI_SLOT_NUMBER(dev);
            p->irq_list[i].dev.function = MODS_PCI_FUNCTION_NUMBER(dev);
        }
        else
        {
            p->irq_list[i].dev.bus = q->data[index].irq;
            p->irq_list[i].dev.device = 0xFFU;
            p->irq_list[i].dev.function = 0xFFU;
        }
        p->irq_list[i].delay = cur_time - q->data[index].time;

        /* Print info about IRQ status returned */
        if (dev)
        {
            mods_debug_printk(DEBUG_ISR_DETAILED,
                "retrieved IRQ for %x:%02x.%x, time=%uus, delay=%uus\n",
                (unsigned)p->irq_list[i].dev.bus,
                (unsigned)p->irq_list[i].dev.device,
                (unsigned)p->irq_list[i].dev.function,
                q->data[index].time,
                p->irq_list[i].delay);
        }
        else
        {
            mods_debug_printk(DEBUG_ISR_DETAILED,
                "retrieved IRQ 0x%x, time=%uus, delay=%uus\n",
                (unsigned)p->irq_list[i].dev.bus,
                q->data[index].time,
                p->irq_list[i].delay);
        }
    }

    /* Indicate if there are more IRQs pending */
    if (q->head != q->tail)
    {
        p->more = 1;
    }

    /* Unlock IRQ queue */
    LOG_EXT();
    MODS_UNLOCK_IRQ(pmp->lock, flags);

    return OK;
}
