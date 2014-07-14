//
//  main.c
//  chumma2
//
//  Created by bhavana srinivas on 9/5/13.
//  Copyright (c) 2013 bhavana srinivas. All rights reserved.
//

//
//  main.c
//  chumma
//
//  Created by bhavana srinivas on 5/26/13.
//  Copyright (c) 2013 bhavana srinivas. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "cs402.h"
#include "my402list.h"



int My402ListInit(My402List* pt)
{
    pt->anchor.next= &(pt->anchor);
    pt->anchor.prev= &(pt->anchor);
    pt->anchor.obj= NULL;
    pt->num_members=0;
    return(1);
}


int  My402ListLength(My402List* pt)
{
    return(pt->num_members);
}

int  My402ListEmpty(My402List* pt)
{
    if((pt->anchor.next==&(pt->anchor)&&(pt->anchor.prev==&(pt->anchor))))
    {
        return 1;
    }
    else
        return 0;
    
}

My402ListElem *My402ListFirst(My402List* pt)
{
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        return(NULL);
    }
    else
    {
        return ( pt->anchor.next);
    }
    
}

My402ListElem *My402ListLast(My402List* pt)
{
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        return(NULL);
    }
    else
    {
        return ( pt->anchor.prev);
    }
    
}

My402ListElem *My402ListNext(My402List* pt, My402ListElem* Elem)
{
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        return(NULL);
    }
    else if(Elem == pt->anchor.prev)
    {
        return NULL;
    }
    else
    {
        return Elem->next;
    }
}

My402ListElem *My402ListPrev(My402List* pt, My402ListElem* Elem)
{
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        return(NULL);
    }
    else if(Elem == pt->anchor.next)
    {
        return NULL;
    }
    else
    {
        return Elem->prev;
    }
}



int  My402ListAppend(My402List* pt, void* info)
{
    My402ListElem *newnode, *last;
    newnode = (My402ListElem *)malloc(sizeof(My402ListElem));
    if(newnode==NULL)
    {
        return 0;
    }
    
    else if((pt->anchor.next==&(pt->anchor)&&(pt->anchor.prev==&(pt->anchor))))
    {
        newnode->next = &(pt->anchor);
        newnode->prev = &(pt->anchor);
        pt->anchor.next = pt->anchor.prev = newnode;
        newnode->obj = info;
        pt->num_members++;
        return(1);
    }
    else
    {
        
        last = My402ListLast(pt);
        newnode->next = &(pt->anchor);
        newnode->prev = pt->anchor.prev;
        last->next = newnode;
        pt->anchor.prev = newnode;
        newnode->obj = info;
        pt->num_members++;
        return(1);
    }
    
}

int  My402ListPrepend(My402List* pt, void* info)
{
    My402ListElem *newnode, *first;
    newnode = (My402ListElem *)malloc(sizeof(My402ListElem));
    if(newnode==NULL)
    {
        return 0;
    }
    
    else if((pt->anchor.next==&(pt->anchor)&&(pt->anchor.prev==&(pt->anchor))))
    {
        newnode->next = &(pt->anchor);
        newnode->prev = &(pt->anchor);
        pt->anchor.next = pt->anchor.prev = newnode;
        newnode->obj = info;
        pt->num_members++;
        return(1);
    }
    else
    {
        
        first = My402ListFirst(pt);
        newnode->prev = &(pt->anchor);
        newnode->next = pt->anchor.next;
        first->prev = newnode;
        pt->anchor.next = newnode;
        newnode->obj = info;
        pt->num_members++;
        return(1);
    }
    
}


My402ListElem *My402ListFind(My402List* list_ptr, void* object)

{
    if(list_ptr->num_members==0)
    {
        fprintf(stderr,"List is Empty\n");
        return(NULL);
    }
    else
    {
        My402ListElem *temp = &(list_ptr->anchor);
        temp=temp->next;
        while(temp->obj != object)
        {
            if(temp==&(list_ptr->anchor))
            {
                return(NULL);
            }
            temp=(temp->next);
        }
        return(temp);
    }
}


int  My402ListInsertAfter(My402List* pt, void* info, My402ListElem* elem)
{
    My402ListElem *newnode;
    newnode = (My402ListElem *)malloc(sizeof(My402ListElem));
    newnode->obj=info;
    
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        int temp=0;
        temp=My402ListAppend(pt,info);
        if(temp==1)
            return 1;
        else
            return 0;
    }
    else
    {
        
        My402ListElem* elem_nxt;
        elem_nxt =elem->next;
        // elem_nxt=My402ListNext(pt,elem);
        newnode->next = elem_nxt;
        newnode->prev = elem;
        elem->next = newnode;
        elem_nxt->prev = newnode;
        pt->num_members++;
        return 1;
        
    }
    
}


int  My402ListInsertBefore(My402List* pt, void* info, My402ListElem* elem)
{
    My402ListElem *newnode;
    newnode = (My402ListElem *)malloc(sizeof(My402ListElem));
    newnode->obj=info;
    
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev== &(pt->anchor)))
    {
        int temp=0;
        temp=My402ListPrepend(pt,info);
        if(temp==1)
            return 1;
        else
            return (0);
    }
    else
    {
        if(newnode!=NULL)
        {
            My402ListElem* elem_prv;
            elem_prv = elem->prev;
            newnode->next = elem;
            newnode->prev = elem_prv;
            elem_prv->next = newnode;
            elem->prev = newnode;
            pt->num_members++;
            return 1;
        }
        else
        {
            return 0;
        }
        
    }
}


/*void My402ListUnlink(My402List* pt, My402ListElem* elem)
 {
 My402ListElem *before, *after;
 if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev == &(pt->anchor)))
 printf(" list is empty");
 else if((elem->next == &(pt->anchor) && (elem->prev == &(pt->anchor))))
 {
 free(elem);
 pt->anchor.next=&(pt->anchor);
 pt->anchor.prev = &(pt->anchor);
 
 }
 else if(My402ListFirst(pt)==elem)
 {
 after=My402ListNext(pt,elem);
 free(elem);
 pt->anchor.next=after;
 after->prev=&(pt->anchor);
 }
 else if(My402ListLast(pt)==elem)
 {
 before=My402ListPrev(pt,elem);
 free(elem);
 pt->anchor.prev=before;
 before->next=&(pt->anchor);
 
 }
 else
 
 {
 My402ListElem *before, *after;
 before = My402ListPrev(pt,elem);
 after = My402ListNext(pt,elem);
 free(elem);
 after->prev = before;
 before->next=after;
 
 }
 pt->num_members--;
 }
 
 */

void My402ListUnlink(My402List* pt, My402ListElem* elem)

{
    
    My402ListElem *before, *after;
    
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev == &(pt->anchor)))
        
        printf(" ");
    
    else if((elem->next == &(pt->anchor) && (elem->prev == &(pt->anchor))))
        
    {
        
        free(elem);
        
        pt->anchor.next=&(pt->anchor);
        
        pt->anchor.prev = &(pt->anchor);
        
        
        
    }
    
    else if(My402ListFirst(pt)==elem)
        
    {
        
        after=My402ListNext(pt,elem);
        
        free(elem);
        
        pt->anchor.next=after;
        
        after->prev=&(pt->anchor);
        
    }
    
    else if(My402ListLast(pt)==elem)
        
    {
        
        before=My402ListPrev(pt,elem);
        
        free(elem);
        
        pt->anchor.prev=before;
        
        before->next=&(pt->anchor);
        
        
        
    }
    
    else
        
        
        
    {
        
        My402ListElem *before, *after;
        
        before = My402ListPrev(pt,elem);
        
        after = My402ListNext(pt,elem);
        
        free(elem);
        
        after->prev = before;
        
        before->next=after;
        
        
        
    }
    
    pt->num_members--;
    
}


extern void My402ListUnlinkAll(My402List* pt)


{
    
    if((pt->anchor.next == &(pt->anchor)) && (pt->anchor.prev == &(pt->anchor)))
        
        printf(" ");
    
    else
        
    {
        
        My402ListElem *temp;
        
        temp=&(pt->anchor);
        
        temp=temp->next;
        
        while(temp!=&(pt->anchor))
            
        {
            
            My402ListUnlink(pt,temp);
            
            temp=temp->next;
            
        }
        
        //  pt->anchor.next=&(pt->anchor);
        
        //  pt->anchor.prev = &(pt->anchor);
        
    }
    
    
    
}
