/*
 * mods_dev.c - This file is part of NVIDIA MODS kernel driver.
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

/************************
 * PCI ESCAPE FUNCTIONS *
 ************************/

/************************************************************************ */
/*  esc_mods_find_pci_dev                                                 */
/************************************************************************ */
int esc_mods_find_pci_dev(struct file *pfile, MODS_FIND_PCI_DEVICE *p)
{
    struct pci_dev *dev;
    int index = 0;

    mods_debug_printk(DEBUG_PCICFG, "find pci dev %04x:%04x, index %d\n",
                      (int) p->VendorId, (int) p->DeviceId, (int) p->Index);

    dev = MODS_PCI_GET_DEVICE(p->VendorId, p->DeviceId, NULL);

    while (dev)
    {
        if (index == p->Index)
        {
            p->BusNumber      = MODS_PCI_BUS_NUMBER(dev);
            p->DeviceNumber   = MODS_PCI_SLOT_NUMBER(dev);
            p->FunctionNumber = MODS_PCI_FUNCTION_NUMBER(dev);
            //pci_dev_put(dev);
            return OK;
        }
        dev = MODS_PCI_GET_DEVICE(p->VendorId, p->DeviceId, dev);
        index++;
    }

    return -EINVAL;
}

/************************************************************************ */
/*  esc_mods_find_pci_class_code                                          */
/************************************************************************ */
int esc_mods_find_pci_class_code(struct file *pfile, MODS_FIND_PCI_CLASS_CODE *p)
{
    struct pci_dev *dev;
    int index = 0;

    mods_debug_printk(DEBUG_PCICFG, "find pci class code %04x, index %d\n",
                      (int) p->ClassCode, (int) p->Index);

    dev = MODS_PCI_GET_CLASS(p->ClassCode, NULL);

    while (dev)
    {
        if (index == p->Index)
        {
            p->BusNumber        = MODS_PCI_BUS_NUMBER(dev);
            p->DeviceNumber     = MODS_PCI_SLOT_NUMBER(dev);
            p->FunctionNumber   = MODS_PCI_FUNCTION_NUMBER(dev);
            //pci_dev_put(dev);
            return OK;
        }
        dev = MODS_PCI_GET_CLASS(p->ClassCode, dev);
        index++;
    }

    return -EINVAL;
}

/************************************************************************ */
/*  esc_mods_pci_read                                                     */
/************************************************************************ */
int esc_mods_pci_read(struct file *pfile, MODS_PCI_READ *p)
{
    struct pci_dev *dev;
    unsigned int devfn;

    devfn = PCI_DEVFN(p->DeviceNumber, p->FunctionNumber);
    dev = MODS_PCI_GET_SLOT(p->BusNumber, devfn);

    if (dev == NULL)
    {
        return -EINVAL;
    }

    mods_debug_printk(DEBUG_PCICFG, "pci read %x:%02x.%x, addr 0x%04x, size %d\n",
                      (int) p->BusNumber, (int) p->DeviceNumber,
                      (int) p->FunctionNumber, (int) p->Address, (int) p->DataSize);

    p->Data = 0;
    switch (p->DataSize)
    {
        case 1:
            MODS_PCI_READ_CONFIG_BYTE(dev, p->Address, (u8 *) &p->Data);
            break;
        case 2:
            MODS_PCI_READ_CONFIG_WORD(dev, p->Address, (u16 *) &p->Data);
            break;
        case 4:
            MODS_PCI_READ_CONFIG_DWORD(dev, p->Address, (u32 *) &p->Data);
            break;
        default:
            return -EINVAL;
    }
    return OK;
}

/************************************************************************ */
/*  esc_mods_pci_write                                                    */
/************************************************************************ */
int esc_mods_pci_write(struct file *pfile, MODS_PCI_WRITE *p)
{
    struct pci_dev *dev;
    unsigned int devfn;

    mods_debug_printk(DEBUG_PCICFG, "pci write %x:%02x.%x, addr 0x%04x, size %d, data 0x%x\n",
                      (int) p->BusNumber, (int) p->DeviceNumber, (int) p->FunctionNumber,
                      (int) p->Address, (int) p->DataSize, (int) p->Data);

    devfn = PCI_DEVFN(p->DeviceNumber, p->FunctionNumber);
    dev = MODS_PCI_GET_SLOT(p->BusNumber, devfn);

    if (dev == NULL)
    {
        mods_error_printk("pci write to %x:%02x.%x, addr 0x%04x, size %d failed\n",
                      (unsigned)p->BusNumber,
                      (unsigned)p->DeviceNumber,
                      (unsigned)p->FunctionNumber,
                      (unsigned)p->Address,
                      (int)p->DataSize);
        return -EINVAL;
    }

    switch (p->DataSize)
    {
        case 1:
            MODS_PCI_WRITE_CONFIG_BYTE(dev, p->Address, p->Data);
            break;
        case 2:
            MODS_PCI_WRITE_CONFIG_WORD(dev, p->Address, p->Data);
            break;
        case 4:
            MODS_PCI_WRITE_CONFIG_DWORD(dev, p->Address, p->Data);
            break;
        default:
            return -EINVAL;
    }
    return OK;
}

/************************************************************************ */
/*  esc_mods_pci_bus_add_dev                                              */
/************************************************************************ */
int esc_mods_pci_bus_add_dev(struct file *pfile, MODS_PCI_BUS_ADD_DEVICES *scan)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)) && defined(CONFIG_PCI)
    mods_info_printk("scanning pci bus %x\n", scan->Bus);

    /* initiate a PCI bus scan to find hotplugged PCI devices in domain 0 */
    MODS_PCI_SCAN_CHILD_BUS(MODS_PCI_FIND_BUS(0, scan->Bus));

    /* add newly found devices */
    MODS_PCI_BUS_ADD_DEVICES(MODS_PCI_FIND_BUS(0, scan->Bus));

    return OK;
#else
    return -EINVAL;
#endif
}

/************************
 * PIO ESCAPE FUNCTIONS *
 ************************/

/************************************************************************ */
/*  esc_mods_pio_read                                                     */
/************************************************************************ */
int esc_mods_pio_read(struct file *pfile, MODS_PIO_READ *p)
{
    LOG_ENT();
    switch (p->DataSize)
    {
        case 1:
            p->Data = MODS_PIO_READ_BYTE(p->Port);
            break;
        case 2:
            p->Data = MODS_PIO_READ_WORD(p->Port);
            break;
        case 4:
            p->Data = MODS_PIO_READ_DWORD(p->Port);
            break;
        default:
            return -EINVAL;
    }
    LOG_EXT();
    return OK;
}


/************************************************************************ */
/*  esc_mods_pio_write                                                    */
/************************************************************************ */
int esc_mods_pio_write(struct file *pfile, MODS_PIO_WRITE  *p)
{
    LOG_ENT();
    switch (p->DataSize)
    {
        case 1:
            MODS_PIO_WRITE_BYTE(p->Data, p->Port);
            break;
        case 2:
            MODS_PIO_WRITE_WORD(p->Data, p->Port);
            break;
        case 4:
            MODS_PIO_WRITE_DWORD(p->Data, p->Port);
            break;
        default:
            return -EINVAL;
    }
    LOG_EXT();
    return OK;
}
