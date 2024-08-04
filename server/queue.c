/*
 *	queue.c
 *
 *      A simple queue ADT, accommodating data item of any type.
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
 *	04-Aug-2024	Clifford Loo	Fixed bug in queue_free().
 */

#include <stdlib.h>
#include "queue.h"

void queue_append( void *new_item, queue_node **head )
/*
 *  Add item to end of queue.
 */
{
    queue_node **end;

    for (end = head; *end; end = &((*end)->next));	/* search for end */
    *end = (queue_node *) malloc( sizeof( queue_node ) );
    (*end)->item = new_item;
    (*end)->next = 0;
}

void queue_insert( void *new_item, queue_node **head )
/*
 *  Add item to head of queue.
 */
{
    queue_node *old_head = *head;

    *head = (queue_node *) malloc( sizeof( queue_node ) );
    (*head)->item = new_item;
    (*head)->next = old_head;
}

void queue_foreach( act_fn act, queue_node *head )
/*
 *  Act on each item of queue.
 */
{
    for (; head; head = head->next)
    {
	act( head->item );
    }
}

void *queue_search( void *item, cmp_fn cmp, queue_node *head )
/*
 *  Return matching item from queue, given a key item.
 */
{
    for (; head; head = head->next)
    {
	if (!cmp( item, head->item ))		/* found */
	{
	    return head->item;
	}
    }
    return 0;
}

void queue_delete_first_match( void *item, cmp_fn cmp, queue_node **head )
/*
 *  Remove the first matching item from queue.
 */
{
    queue_node **ptr, *tmp;

    for (ptr = head; *ptr; ptr = &((*ptr)->next))
    {
	if (!cmp( item, (*ptr)->item ))		/* found */
	{
	    tmp = *ptr;
	    (*ptr) = ((*ptr)->next); /* relink */
	    free( tmp->item );
	    free( tmp );
	    break;
	}
    }
}

void queue_delete_all_matches( void *item, cmp_fn cmp, queue_node **head )
/*
 *  Remove all matching items from queue.
 */
{
    queue_node **ptr, *tmp;

    for (ptr = head; *ptr;)
    {
	if (!cmp( item, (*ptr)->item ))		/* found */
	{
	    tmp = *ptr;
	    (*ptr) = ((*ptr)->next); /* relink */
	    free( tmp->item );
	    free( tmp );
	} else {
	    ptr = &((*ptr)->next); /* inspect next */
	}
    }
}

void queue_free( queue_node **head )
/*
 *  Release storage from queue and reset pointer.
 */
{
    queue_node *ptr, *tmp;

    ptr = *head;
    while (ptr)
    {
	tmp = ptr;
	ptr = ptr->next;
	free( tmp->item );
	free( tmp );
    }
    *head = 0;
}

