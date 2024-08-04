/*
 *	queue.h
 *
 *      20-Nov-1993	Clifford Loo	Created.
 *      18-Mar-1996	Clifford Loo	Added queue_free().
 *	11-Feb-1999	Clifford Loo	Reformated.
 *	02-Aug-2024	Clifford Loo	Added queue_insert(),
 *					changed queue_print() into
 *					queue_foreach(),
 *					changed queue_delete() into
 *					queue_delete_first_match(),
 *					added queue_delete_all_matches().
 */

#ifndef _QUEUE_H
#define _QUEUE_H

typedef struct queue_s {
    void *item;
    struct queue_s *next;
} queue_node;

typedef int (*cmp_fn)( void *item1, void *item2 );
typedef void (*act_fn)( void *item );

void queue_append( void *new_item, queue_node **head );
/* *head should be initialized to 0 */

void queue_insert( void *new_item, queue_node **head );
/* *head should be initialized to 0 */

void *queue_search( void *item, cmp_fn cmp, queue_node *head );
/* seach terminates upon the first matching item */

void queue_delete_first_match( void *item, cmp_fn cmp, queue_node **head );
/* only the first matching item will get deleted */

void queue_delete_all_matches( void *item, cmp_fn cmp, queue_node **head );
/* all matching items will get deleted */

void queue_free( queue_node **head );
/* the entire structure will be freed; *head should be reset to avoid
 being a "dangling pointer" */

void queue_foreach( act_fn act, queue_node *head );
/* act on all items on the queue using the supplied action function */

#endif

