/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Clifford Loo"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev; /* device information */

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; /* for other methods */
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read (mutex) %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = filp->private_data;
    size_t offset_rtn = 0;

    if (mutex_lock_interruptible( &dev->lock ))
	return -ERESTARTSYS;

    struct aesd_buffer_entry *rtnentry =
	aesd_circular_buffer_find_entry_offset_for_fpos( &dev->buffer,
							 *f_pos,
							 &offset_rtn );
    if (!rtnentry) {
	PDEBUG("null entry returned");
	goto out;
    }
    PDEBUG("found %zu-byte entry in circular buffer, offset %zu",
	   rtnentry->size, offset_rtn);
    if (rtnentry->size < offset_rtn+count) {
	count = rtnentry->size - offset_rtn;
	PDEBUG("requested bytes limited by entry size to %zu", count);
    }
    if (copy_to_user( buf, rtnentry->buffptr + offset_rtn, count )) {
	retval = -EFAULT;
	goto out;
    }
    *f_pos += count;
    retval = count;
    
  out:
    mutex_unlock( &dev->lock );
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write (mutex) %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    struct aesd_dev *dev = filp->private_data;

    if (mutex_lock_interruptible( &dev->lock ))
	return -ERESTARTSYS;

    dev->entry.buffptr = kmalloc( count, GFP_KERNEL );
    if (!dev->entry.buffptr) goto out;
    dev->entry.size = count;
    if (copy_from_user( dev->entry.buffptr, buf, count )) {
	retval = -EFAULT;
	goto out;
    }
    PDEBUG("created entry with %zu bytes", count);
    const char *rtnptr = aesd_circular_buffer_add_entry( &dev->buffer,
							 &dev->entry );
    PDEBUG("entry added to circular buffer, replacing 0x%x", rtnptr);
    kfree( rtnptr );
    retval = count;

  out:
    mutex_unlock( &dev->lock );
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    PDEBUG("init_module");
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     * e.g. locking primitives
     */

    aesd_circular_buffer_init(&aesd_device.buffer);

    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    PDEBUG("cleanup_module");
    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     * hint: balance with init()
     */
    struct aesd_buffer_entry *entry;
    uint8_t index;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
	if (entry->buffptr) kfree( entry->buffptr );
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

