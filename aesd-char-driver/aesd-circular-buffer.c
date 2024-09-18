/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/printk.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(
    struct aesd_circular_buffer *buffer,
    size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    *
    * assume buffer has been properly initialized with valid fields
    */
    uint8_t a = buffer->in_offs, b = buffer->out_offs;
    size_t size;
    PDEBUG("find_entry for offset %zu, buffer(%u,%u)",char_offset, a, b);
    /* return if empty buffer */
    if ((a == b) && !buffer->full) return NULL;
    /* else go through the size of each entry */
    PDEBUG("circular buffer not empty",char_offset);
    do {
	size = buffer->entry[b].size;
	if (char_offset >= size) {
	    /* not this entry, subtract char_offset by size and see next */
	    PDEBUG("entry %u (%zu bytes): no", b, size);
	    char_offset -= size;
	    b = (b+1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	} else {
	    /* requested offset found at this entry */
	    PDEBUG("entry %u (%zu bytes): yes", b, size);
	    *entry_offset_byte_rtn = char_offset;
	    return &buffer->entry[b];
	}
    } while (a != b);
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    uint8_t a = buffer->in_offs;
    const char *oldbuffptr = buffer->entry[a].buffptr; /* store old ptr for dealloc */
    /* copy entry */
    buffer->entry[a].buffptr = add_entry->buffptr;
    buffer->entry[a].size = add_entry->size;
    /* increment in_offs */
    buffer->in_offs = (a+1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    if (buffer->full) {
	/* increment out_offs too; i.e. sync with in_offs */
	buffer->out_offs = buffer->in_offs;
    } else if (buffer->in_offs == buffer->out_offs) {
	/* set full flag */
	buffer->full = true;
    }
    return oldbuffptr; /* assume buffer has been properly initialized; i.e. NULL if not full */
}


/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

