/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mman.h>
#include <linux/mm.h>

#include "kshram.h"

static unsigned int major = 0;
static dev_t dev;
//static struct cdev c_dev[8];
static struct class *clazz;

struct DeviceData{
	char* buffer;
	unsigned long bufferSize;
	struct cdev cdev; 
	struct vm_area_struct *vm_area;
};

static struct DeviceData devices[8];

void turnOnPagePerserved(unsigned long start, unsigned long size){
	unsigned long end = start + size;
	struct page *page;
    for (; start < end; start += PAGE_SIZE) {
        page = virt_to_page(start);
        SetPageReserved(page);
    }
}

void turnOffPagePerserved(unsigned long start, unsigned long size){
	unsigned long end = start + size;
	struct page *page;
    for (; start < end; start += PAGE_SIZE) {
        page = virt_to_page(start);
        ClearPageReserved(page);
    }
}

static int kshram_dev_open(struct inode *i, struct file *f) {
	
	//unsigned int devMajor = imajor(i);
	unsigned int devMinor = iminor(i);
	struct DeviceData* device = NULL;
	device = &devices[devMinor];
	f->private_data = device;

	return 0;
}

static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	struct DeviceData* device = (struct DeviceData*)fp->private_data;
	void* memoryPtr = NULL;

	switch(cmd){
		case KSHRAM_GETSLOTS: return sizeof(devices)/sizeof(devices[0]);
		case KSHRAM_GETSIZE: return device->bufferSize;
		case KSHRAM_SETSIZE: 
			turnOffPagePerserved((unsigned long)device->buffer, device->bufferSize);
			memoryPtr = krealloc(device->buffer, arg, GFP_ATOMIC);
			if(memoryPtr == NULL) {
				printk(KERN_WARNING "[target] krealloc(): out of memory\n");
				return -ENOMEM;
			}
			device->buffer = (char*)memoryPtr;
			device->bufferSize = arg;
			turnOnPagePerserved((unsigned long)device->buffer, device->bufferSize);
			return 0;
	}
	
	return 0;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vm_area){
	struct DeviceData* device = (struct DeviceData*)fp->private_data;
	unsigned long start = vm_area->vm_start;
    unsigned long size = vm_area->vm_end - vm_area->vm_start;
    unsigned long offset = vm_area->vm_pgoff << PAGE_SHIFT;
    unsigned long phys = page_to_pfn(virt_to_page((void *)device->buffer)+ offset);
	
	printk(KERN_INFO "kshram/mmap: offset:%lu phys:%lu\n", offset, phys);

    if (remap_pfn_range(vm_area, start, phys , size, vm_area->vm_page_prot)){
		printk(KERN_INFO "kshram/mmap: error\n");
        return -EAGAIN;
	}

	printk(KERN_INFO "kshram/mmap: idx %lu size %lu\n", device - &devices[0] ,size);
    return 0;
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.mmap = kshram_dev_mmap,
	.unlocked_ioctl = kshram_dev_ioctl,
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	int i;

	for(i=0 ; i< 8; i++)
		seq_printf(m, "%02d: %lu\n", i, devices[i].bufferSize);

	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int construct_device(struct DeviceData *deviceData, int minor, struct class *class) {
	int err = 0;
	dev_t devno = MKDEV(major, minor);
	struct device *device = NULL;
	
	cdev_init(&deviceData->cdev, &kshram_dev_fops);
	err = cdev_add(&deviceData->cdev, devno, 1);
	if(err){
		printk(KERN_WARNING "Error %d while trying to add device %d",
			err, minor);
		return err;
	}
	device = device_create(clazz, NULL, devno, NULL, "kshram%d" , minor);
	if(IS_ERR(device)){
		err = PTR_ERR(device);
		printk(KERN_WARNING "Error %d while trying to add device %d",
			err, minor);
		cdev_del(&deviceData->cdev);
		return err;
	}
	deviceData->bufferSize = 4096;
	deviceData->buffer = (unsigned char*)kzalloc(deviceData->bufferSize, GFP_ATOMIC);
	deviceData->vm_area = NULL;
	// mark the pages as reserved
    turnOnPagePerserved((unsigned long)deviceData->buffer, deviceData->bufferSize);
    
	printk(KERN_INFO "ksharm%d: %lu bytes allocated @ %16lx\n", minor, deviceData->bufferSize, (unsigned long)deviceData->buffer);
	if (deviceData->buffer == NULL)	{
		printk(KERN_WARNING "open(): out of memory\n");
		return -ENOMEM;
	}

	return 0;
}

static int __init kshram_init(void) {
	int i;
	int err = 0;
	// create char dev
	if(alloc_chrdev_region(&dev, 0, 8, "updev") < 0)
		return -1;

	major = MAJOR(dev);

	if((clazz = class_create(THIS_MODULE, "upclass")) == NULL)
		goto release_region;
	clazz->devnode = kshram_devnode;
	
	
	for(i=0; i < 8; i++){
		err = construct_device(&devices[i], i,clazz);
		if(err!=0){
			printk(KERN_WARNING "[target] Construct device %d error: %d",
			i, err);
			goto release_device;
		}
	}

	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, dev);
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(dev, 8);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	int i;
	remove_proc_entry("kshram", NULL);
	printk(KERN_INFO "kshram: cleaned up.\n");
	
	for(i = 0; i < 8; i++){
		device_destroy(clazz, MKDEV(major, i));
		turnOffPagePerserved((unsigned long)devices[i].buffer, devices[i].bufferSize);
		kfree(devices[i].buffer);
		cdev_del(&devices[i].cdev);	
	}
	class_destroy(clazz);
	unregister_chrdev_region(dev, 8);
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YsTse Chen");
MODULE_DESCRIPTION("112 Unix Programming Lab5");
