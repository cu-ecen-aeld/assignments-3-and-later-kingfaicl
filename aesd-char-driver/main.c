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
 * Clifford Loo
 * added aesd_llseek(), aesd_adjust_file_offset() & aesd_ioctl()
 * 2024-09-28
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
#include "aesd_ioctl.h"
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
    const char *prevptr;
    size_t prevsize;

    if (mutex_lock_interruptible( &dev->lock ))
	return -ERESTARTSYS;

    /* check if entry ptr is non-NULL */
    if (dev->entry.buffptr) {
	/* append command by replacing the previous with concatenated result */
	prevptr = dev->entry.buffptr;
	prevsize = dev->entry.size;
	dev->entry.buffptr = kmalloc( prevsize+count, GFP_KERNEL );
	if (!dev->entry.buffptr) goto out;
	memcpy( dev->entry.buffptr, prevptr, prevsize );
	PDEBUG("copied previous entry of %zu bytes", prevsize);
	kfree( prevptr );
	if (copy_from_user( dev->entry.buffptr+prevsize, buf, count )) {
	    retval = -EFAULT;
	    goto out;
	}
	PDEBUG("appended previous entry with %zu bytes", count);
	dev->entry.size += count;
    } else {
	/* set entry ptr to the new command */
	dev->entry.buffptr = kmalloc( count, GFP_KERNEL );
	if (!dev->entry.buffptr) goto out;
	if (copy_from_user( dev->entry.buffptr, buf, count )) {
	    retval = -EFAULT;
	    goto out;
	}
	PDEBUG("created new entry with %zu bytes", count);
	dev->entry.size = count;
    }
    /* check if entry is now \n-terminated */
    if (dev->entry.buffptr[dev->entry.size-1] == '\n') {
	/* add to circular buffer and reset entry ptr to NULL */
	const char *rtnptr = aesd_circular_buffer_add_entry( &dev->buffer,
							     &dev->entry );
	dev->entry.buffptr = NULL;
	dev->entry.size = 0;
	PDEBUG("entry added to circular buffer, replacing 0x%x", rtnptr);
	kfree( rtnptr ); /* free any storage for the replaced entry */
    } else {
	/* leave the entry as is for later appends */
	PDEBUG("entry pending continuation");
    }
    *f_pos += count; /* update f_pos */
    retval = count;

  out:
    mutex_unlock( &dev->lock );
    return retval;
}

loff_t aesd_llseek( struct file *filp, loff_t off, int whence )
{
    struct aesd_dev *dev = filp->private_data;
    PDEBUG("llseek with offset %lld, whence %d", off, whence);
    size_t size = aesd_circular_buffer_size( &dev->buffer );
    PDEBUG("buffer size = %lu", size);
    /* use wrapper function fixed_size_llseek(), with locking and logging */
    return fixed_size_llseek( filp, off, whence, size );
}


/*
 * Adjust the file offset (f_pos) parameter of @param filp based on
 * the location specified by @param write_cmd 9the zero referenced
 * command to locate) and @param write_cmd_offset 9the zero referenced
 * offset into the commdn)
 * @return 0 if successful, negative if error occurred:
 *	-ERESTARTSYS if mutex could not be obtained
 *	-EINVAL if write command or write_cmd_offset was out of range
 */
static long aesd_adjust_file_offset( struct file *filp,
				     unsigned int write_cmd,
				     unsigned int write_cmd_offset )
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_circular_buffer buffer = dev->buffer;
    uint8_t here = buffer.out_offs, end = buffer.out_offs;
    loff_t start_off = 0;

    PDEBUG("adjust file offset to cmd %u offset %u",
	   write_cmd, write_cmd_offset);
    /* check for valid cmd offset */
    if (write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
	/* out of range */
	return -EINVAL;
    }
    if ((here == end) && !buffer.full) {
	/* empty buffer */
	return -EINVAL;
    }
    do {
	if (write_cmd == here) {
	    /* found */
	    PDEBUG("found entry %u (at offset %u) of size %u",
		   here, start_off, buffer.entry[here].size);
	    if (write_cmd_offset >= buffer.entry[here].size) {
		/* out of range */
		return -EINVAL;
	    } else {
		/* add cmd offset and save as f_pos */
		filp->f_pos = start_off + write_cmd_offset;
		return 0;
	    }
	} else {
	    /* add size to start offset */
	    start_off += buffer.entry[here].size;
	    /* next */
	    PDEBUG("entry %u: adding size %u to offset",
		   here, buffer.entry[here].size);
	    here = (here+1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	}
    } while (here != end);
    /* not found */
    return -EINVAL;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    struct aesd_seekto seekto;
    
    PDEBUG("ioctl with cmd %u, arg %lu", cmd, arg);
    /*
     * extract the type and number bitfields, and don't decode
     * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
     */
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

    switch(cmd) {

	case AESDCHAR_IOCSEEKTO:
	    if (copy_from_user( &seekto, (const void __user *) arg,
				sizeof(seekto)) != 0) {
		retval = EFAULT;
	    } else {
		retval = aesd_adjust_file_offset( filp, seekto.write_cmd,
						  seekto.write_cmd_offset );
	    }
	    break;

	default:  /* redundant, as cmd was checked against MAXNR */
	    return -ENOTTY;
    }
    return retval;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .llseek =	aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
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

