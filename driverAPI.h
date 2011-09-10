/*
 * driverAPI.h - This file is part of NVIDIA MODS kernel driver.
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

#ifndef _DRIVER_API_H_
#define _DRIVER_API_H_

/* Driver version */
#define MODS_DRIVER_VERSION_MAJOR 3
#define MODS_DRIVER_VERSION_MINOR 19
#define MODS_DRIVER_VERSION ((MODS_DRIVER_VERSION_MAJOR << 8) | \
                             ((MODS_DRIVER_VERSION_MINOR/10) << 4) | \
                             (MODS_DRIVER_VERSION_MINOR%10))

#pragma pack(1)

/* *************************************************************************** */
/* ** ESCAPE INTERFACE STRUCTURE                                               */
/* *************************************************************************** */

struct mods_pci_dev
{
    NvU16 bus;
    NvU8  device;
    NvU8  function;
};

/* MODS_ESC_ALLOC_PAGES */
typedef struct 
{
    /* IN */
    NvU32   NumBytes;
    NvU32   Contiguous;
    NvU32   AddressBits;
    NvU32   Attrib;

    /* OUT */
    NvU64   MemoryHandle;

} MODS_ALLOC_PAGES;


/* MODS_ESC_FREE_PAGES */
typedef struct 
{
    /* IN */
    NvU64   MemoryHandle; 

} MODS_FREE_PAGES;


/* MODS_ESC_GET_PHYSICAL_ADDRESS */
typedef struct  
{
    /* IN */
    NvU64   MemoryHandle;
    NvU32   Offset;

    /* OUT */
    NvU64   PhysicalAddress;
    
} MODS_GET_PHYSICAL_ADDRESS;


/* MODS_ESC_VIRTUAL_TO_PHYSICAL */
typedef struct 
{
    /* IN */
    NvU64   VirtualAddress;

    /* OUT */
    NvU64   PhysicalAddress;

} MODS_VIRTUAL_TO_PHYSICAL;


/* MODS_ESC_PHYSICAL_TO_VIRTUAL */
typedef struct 
{
    /* IN */
    NvU64   PhysicalAddress;

    /* OUT */
    NvU64   VirtualAddress;

} MODS_PHYSICAL_TO_VIRTUAL;


/* MODS_ESC_FIND_PCI_DEVICE */
typedef struct 
{
    /* IN */
    NvU32     DeviceId;
    NvU32     VendorId;
    NvU32     Index;

    /* OUT */
    NvU32     BusNumber;
    NvU32     DeviceNumber;
    NvU32     FunctionNumber;
    
} MODS_FIND_PCI_DEVICE;


/* MODS_ESC_FIND_PCI_CLASS_CODE */
typedef struct 
{
    /* IN */
    NvU32   ClassCode;
    NvU32   Index;

    /* OUT */
    NvU32   BusNumber;
    NvU32   DeviceNumber;
    NvU32   FunctionNumber;

} MODS_FIND_PCI_CLASS_CODE;


/* MODS_ESC_PCI_READ */
typedef struct 
{
    /* IN */
    NvU32   BusNumber;
    NvU32   DeviceNumber;
    NvU32   FunctionNumber;
    NvU32   Address;
    NvU32   DataSize;

    /* OUT */
    NvU32    Data;

} MODS_PCI_READ;


/* MODS_ESC_PCI_WRITE */
typedef struct 
{
    /* IN */
    NvU32   BusNumber;
    NvU32   DeviceNumber;
    NvU32   FunctionNumber;
    NvU32   Address;
    NvU32   Data;
    NvU32   DataSize;

} MODS_PCI_WRITE;


/* MODS_ESC_PCI_BUS_ADD_DEVICES*/
typedef struct
{
    /* IN */
    NvU32    Bus;
} MODS_PCI_BUS_ADD_DEVICES;


/* MODS_ESC_PIO_READ */
typedef struct
{
    /* IN */
    NvU16   Port;
    NvU32   DataSize;

    /* OUT */
    NvU32   Data;

} MODS_PIO_READ;


/* MODS_ESC_PIO_WRITE */
typedef struct
{
    /* IN */
    NvU16   Port;
    NvU32   Data;
    NvU32   DataSize;

} MODS_PIO_WRITE;


#define INQ_CNT 8

struct IrqData
{
    NvU32 irq;
    NvU32 delay;
};

struct IrqStatus
{
    struct IrqData data[INQ_CNT];
    NvU32 irqbits : INQ_CNT;
    NvU32 otherirq : 1;
};


/* MODS_ESC_IRQ */
typedef struct mods_data
{
    /* IN */
    NvU32 cmd;
    NvU32 size;             /* memory size */
    NvU32 irq;              /* the irq number to be registered in driver */

    /* IN OUT */
    NvU32 channel;          /* application id which is allocated by driver. */

    /* OUT */
    struct IrqStatus stat;  /* for querying irq */
    NvU64            phys;  /* the memory physical address */

} MODS_IRQ;

/* MODS_ESC_REGISTER_IRQ */
/* MODS_ESC_UNREGISTER_IRQ */
typedef struct
{
    /* IN */
    struct mods_pci_dev dev;    /* device whose interrupt we want to register */
    NvU8                type;   /* MODS_IRQ_TYPE_* */
} MODS_REGISTER_IRQ;

struct mods_irq
{
    NvU32               delay;  /* delay in ns between the irq occuring and MODS querying for it */
    struct mods_pci_dev dev;    /* device which generated the interrupt */
};

#define MODS_MAX_IRQS 32

/* MODS_ESC_QUERY_IRQ */
typedef struct
{
    /* OUT */
    struct mods_irq irq_list[MODS_MAX_IRQS];
    NvU8            more;       /* indicates that more interrupts are waiting */
} MODS_QUERY_IRQ;

#define MODS_IRQ_TYPE_INT  0
#define MODS_IRQ_TYPE_MSI  1
#define MODS_IRQ_TYPE_CPU  2

#define ACPI_MODS_TYPE_INTEGER      1
#define ACPI_MODS_TYPE_BUFFER       2
#define ACPI_MAX_BUFFER_LENGTH      4096
#define ACPI_MAX_METHOD_LENGTH      12
#define ACPI_MAX_ARGUMENT_NUMBER    12

typedef union
{
    NvU32   Type;

    struct
    {
        NvU32 Type;
        NvU32 Value;
    } Integer;

    struct
    {
        NvU32   Type;
        NvU32   Length;
        NvU32   Offset;
    } Buffer;

} ACPI_ARGUMENT, *PACPI_ARGUMENT;


/* MODS_ESC_EVAL_ACPI_METHOD */
typedef struct
{
    /* IN */
    char            MethodName[ACPI_MAX_METHOD_LENGTH];
    NvU32           ArgumentCount;
    ACPI_ARGUMENT   Argument[ACPI_MAX_ARGUMENT_NUMBER];
    NvU8            InBuffer[ACPI_MAX_BUFFER_LENGTH];

    /* IN OUT */
    NvU32           OutDataSize;

    /* OUT */
    NvU8            OutBuffer[ACPI_MAX_BUFFER_LENGTH];
    NvU32           OutStatus;

} MODS_EVAL_ACPI_METHOD;


/* MODS_ESC_EVAL_DEV_ACPI_METHOD */
typedef struct
{
    /* IN OUT */
    MODS_EVAL_ACPI_METHOD method;

    /* IN */
    struct mods_pci_dev device;

} MODS_EVAL_DEV_ACPI_METHOD;


/* MODS_ESC_ACPI_GET_DDC */
typedef struct
{
    /* OUT */
    NvU32               out_data_size;
    NvU8                out_buffer[ACPI_MAX_BUFFER_LENGTH];

    /* IN */
    struct mods_pci_dev device;

} MODS_ACPI_GET_DDC;


/* MODS_ESC_GET_VERSION */
typedef struct
{
    /* OUT */
    NvU64           Version;

} MODS_GET_VERSION;

/* MODS_ESC_SET_PARA */
typedef struct
{
    /* IN */
    NvU64           Highmem4g;
    NvU64           Debug;

} MODS_SET_PARA;

/* MODS_ESC_SET_MEMORY_TYPE */
typedef struct
{
    /* IN */
    NvU64           PhysAddr;
    NvU64           Size;
    NvU32           Type;

} MODS_MEMORY_TYPE;

#define MAX_CLOCK_HANDLE_NAME 64

/* MODS_ESC_GET_CLOCK_HANDLE */
typedef struct
{
    /* OUT */
    NvU32           clockHandle;

    /* IN */
    char            deviceName[MAX_CLOCK_HANDLE_NAME];
    char            contextName[MAX_CLOCK_HANDLE_NAME];
} MODS_GET_CLOCK_HANDLE;

/* MODS_ESC_SET_CLOCK_RATE, MODS_ESC_GET_CLOCK_RATE */
typedef struct
{
    /* IN/OUT */
    NvU64           clockRateHz;

    /* IN */
    NvU32           clockHandle;
} MODS_CLOCK_RATE;

/* MODS_ESC_SET_CLOCK_PARENT, MODS_ESC_GET_CLOCK_PARENT */
typedef struct
{
    /* IN */
    NvU32           clockHandle;

    /* IN/OUT */
    NvU32           clockParentHandle;
} MODS_CLOCK_PARENT;

/* MODS_ESC_ENABLE_CLOCK, MODS_ESC_DISABLE_CLOCK, MODS_ESC_CLOCK_RESET_ASSERT, MODS_ESC_CLOCK_RESET_DEASSERT */
typedef struct
{
    /* IN */
    NvU32           clockHandle;
} MODS_CLOCK_HANDLE;

/* MODS_ESC_IS_CLOCK_ENABLED */
typedef struct
{
    /* IN */
    NvU32           clockHandle;

    /* OUT */
    NvU8            enabled;
} MODS_CLOCK_ENABLED;

/* The ids match MODS ids */
#define MODS_MEMORY_CACHED          5
#define MODS_MEMORY_UNCACHED        1
#define MODS_MEMORY_WRITECOMBINE    2

#pragma pack()

/* *************************************************************************** */
/* *************************************************************************** */
/* **                                                                          */
/* ** ESCAPE CALLS                                                             */
/* **                                                                          */
/* *************************************************************************** */
/* *************************************************************************** */
#define MODS_IOC_MAGIC    'x'
#define MODS_ESC_ALLOC_PAGES            _IOWR(MODS_IOC_MAGIC, 0, MODS_ALLOC_PAGES)
#define MODS_ESC_FREE_PAGES             _IOWR(MODS_IOC_MAGIC, 1, MODS_FREE_PAGES)
#define MODS_ESC_GET_PHYSICAL_ADDRESS   _IOWR(MODS_IOC_MAGIC, 2, MODS_GET_PHYSICAL_ADDRESS)
#define MODS_ESC_VIRTUAL_TO_PHYSICAL    _IOWR(MODS_IOC_MAGIC, 3, MODS_VIRTUAL_TO_PHYSICAL)
#define MODS_ESC_PHYSICAL_TO_VIRTUAL    _IOWR(MODS_IOC_MAGIC, 4, MODS_PHYSICAL_TO_VIRTUAL)
#define MODS_ESC_FIND_PCI_DEVICE        _IOWR(MODS_IOC_MAGIC, 5, MODS_FIND_PCI_DEVICE)
#define MODS_ESC_FIND_PCI_CLASS_CODE    _IOWR(MODS_IOC_MAGIC, 6, MODS_FIND_PCI_CLASS_CODE)
#define MODS_ESC_PCI_READ               _IOWR(MODS_IOC_MAGIC, 7, MODS_PCI_READ)
#define MODS_ESC_PCI_WRITE              _IOWR(MODS_IOC_MAGIC, 8, MODS_PCI_WRITE)
#define MODS_ESC_PIO_READ               _IOWR(MODS_IOC_MAGIC, 9, MODS_PIO_READ)
#define MODS_ESC_PIO_WRITE              _IOWR(MODS_IOC_MAGIC, 10, MODS_PIO_WRITE)
#define MODS_ESC_IRQ_REGISTER           _IOWR(MODS_IOC_MAGIC, 11, MODS_IRQ)
#define MODS_ESC_IRQ_FREE               _IOWR(MODS_IOC_MAGIC, 12, MODS_IRQ)
#define MODS_ESC_IRQ_INQUIRY            _IOWR(MODS_IOC_MAGIC, 13, MODS_IRQ)
#define MODS_ESC_EVAL_ACPI_METHOD       _IOWR(MODS_IOC_MAGIC, 16, MODS_EVAL_ACPI_METHOD)
#define MODS_ESC_GET_API_VERSION        _IOWR(MODS_IOC_MAGIC, 17, MODS_GET_VERSION)
#define MODS_ESC_GET_KERNEL_VERSION     _IOWR(MODS_IOC_MAGIC, 18, MODS_GET_VERSION)
#define MODS_ESC_SET_DRIVER_PARA        _IOWR(MODS_IOC_MAGIC, 19, MODS_SET_PARA)
#define MODS_ESC_MSI_REGISTER           _IOWR(MODS_IOC_MAGIC, 20, MODS_IRQ)
#define MODS_ESC_REARM_MSI              _IOWR(MODS_IOC_MAGIC, 21, MODS_IRQ)
#define MODS_ESC_SET_MEMORY_TYPE        _IOW( MODS_IOC_MAGIC, 22, MODS_MEMORY_TYPE)
#define MODS_ESC_PCI_BUS_ADD_DEVICES    _IOW( MODS_IOC_MAGIC, 23, MODS_PCI_BUS_ADD_DEVICES)
#define MODS_ESC_REGISTER_IRQ           _IOW( MODS_IOC_MAGIC, 24, MODS_REGISTER_IRQ)
#define MODS_ESC_UNREGISTER_IRQ         _IOW( MODS_IOC_MAGIC, 25, MODS_REGISTER_IRQ)
#define MODS_ESC_QUERY_IRQ              _IOR( MODS_IOC_MAGIC, 26, MODS_QUERY_IRQ)
#define MODS_ESC_EVAL_DEV_ACPI_METHOD   _IOWR(MODS_IOC_MAGIC, 27, MODS_EVAL_DEV_ACPI_METHOD)
#define MODS_ESC_ACPI_GET_DDC           _IOWR(MODS_IOC_MAGIC, 28, MODS_ACPI_GET_DDC)
#define MODS_ESC_GET_CLOCK_HANDLE       _IOWR(MODS_IOC_MAGIC, 29, MODS_GET_CLOCK_HANDLE)
#define MODS_ESC_SET_CLOCK_RATE         _IOW( MODS_IOC_MAGIC, 30, MODS_CLOCK_RATE)
#define MODS_ESC_GET_CLOCK_RATE         _IOWR(MODS_IOC_MAGIC, 31, MODS_CLOCK_RATE)
#define MODS_ESC_SET_CLOCK_PARENT       _IOW( MODS_IOC_MAGIC, 32, MODS_CLOCK_PARENT)
#define MODS_ESC_GET_CLOCK_PARENT       _IOWR(MODS_IOC_MAGIC, 33, MODS_CLOCK_PARENT)
#define MODS_ESC_ENABLE_CLOCK           _IOW( MODS_IOC_MAGIC, 34, MODS_CLOCK_HANDLE)
#define MODS_ESC_DISABLE_CLOCK          _IOW( MODS_IOC_MAGIC, 35, MODS_CLOCK_HANDLE)
#define MODS_ESC_IS_CLOCK_ENABLED       _IOWR(MODS_IOC_MAGIC, 36, MODS_CLOCK_ENABLED)
#define MODS_ESC_CLOCK_RESET_ASSERT     _IOW( MODS_IOC_MAGIC, 37, MODS_CLOCK_HANDLE)
#define MODS_ESC_CLOCK_RESET_DEASSERT   _IOW( MODS_IOC_MAGIC, 38, MODS_CLOCK_HANDLE)

#endif /* _DRIVER_API_H_  */
