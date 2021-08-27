#include <stdio.h>
#include "salmalloc.h"


sList memlist = {0};
sList memlist_1B = {0};
sList memlist_2B = {0};
sList memlist_4B = {0};

void *g_sal_head = NULL;
void *g_sal_end = NULL;

static void print_debug();

static void countNodesAhead(sNode *, sNode *, nodeType);

static sNode *test_insert();

static sList *return_list_of_size(size_t);

extern void link_skip_nodes(sNode *temp)
{
  /* Set node type. */
  if (memlist.length % HUNDRED == ZERO)
  {

    if (memlist.length == HUNDRED)
    {

      sNode *prev = (sNode *)memlist.skipNodes.prev_tenSpecialNode;

      /* 
	 Previous special node points to 100th node
	 which is also a tenSpecialNode.
      */
      prev->skipNodes.fwd_tenSpecialNode = temp;

      memlist.head->skipNodes.fwd_hundredSpecialNode = temp;
      memlist.head->vNodeType = eHundreds;

      temp->vNodeType = eHundreds;
      temp->skipNodes.prev_tenSpecialNode = prev;
      temp->skipNodes.prev_hundredSpecialNode = memlist.head;
      temp->skipNodes.fwd_hundredSpecialNode = NULL;

      memlist.skipNodes.prev_tenSpecialNode = temp;
      memlist.skipNodes.prev_hundredSpecialNode = temp;

      memlist.head->tenNodesAhead = memlist.head->numNodesAhead;

      temp->numNodesAhead = ONE;

      countNodesAhead(memlist.head, temp, eHundreds);

      //print_debug(temp->numNodesAhead);
    }
    else
    {

      sNode *prev = (sNode *)memlist.skipNodes.prev_tenSpecialNode;
      sNode *prevHundred = (sNode *)memlist.skipNodes.prev_hundredSpecialNode;

      /* connect current and previous ten special nodes. */
      prev->skipNodes.fwd_tenSpecialNode = temp;
      temp->skipNodes.prev_tenSpecialNode = prev;

      /* connect current and previous 100 special nodes. */
      prevHundred->skipNodes.fwd_hundredSpecialNode = temp;
      temp->skipNodes.fwd_hundredSpecialNode = NULL;
      temp->skipNodes.prev_hundredSpecialNode = (sNode *)prevHundred;

      prevHundred->tenNodesAhead = prevHundred->numNodesAhead;

      memlist.skipNodes.prev_tenSpecialNode = temp;

      temp->vNodeType = eHundreds;

      temp->numNodesAhead = ONE;

      countNodesAhead(prevHundred, temp, eHundreds);
    }
  }
  else if (memlist.length % TEN == ZERO)
  {

    temp->vNodeType = eTens;

    if (memlist.length == TEN)
    {
      /*
	a -> fwd_special = j;
	j -> prev_special = a;
	a -> prev_special = j;
	j -> fwd_special = a;
	memlist.tensSpecial = j;
      */

      memlist.head->skipNodes.fwd_tenSpecialNode = temp;
      memlist.head->skipNodes.prev_tenSpecialNode = temp;

      temp->skipNodes.prev_tenSpecialNode = memlist.head;
      temp->skipNodes.fwd_tenSpecialNode = NULL;

      memlist.skipNodes.prev_tenSpecialNode = temp;

      //memlist.head->numNodesAhead = ONE;
      temp->numNodesAhead = ONE;

      memlist.head->vNodeType = eTens;
    }
    else
    {

      /*
	prev = memlist.tenSpecial
	temp -> prev_special = prev;
	temp -> fwd_special  = head;

	prev -> fwd_special  = temp;
	memlist.tenSpecial   = temp;
      */

      sNode *prev = (sNode *)memlist.skipNodes.prev_tenSpecialNode;

      //prev->numNodesAhead = TEN;

      temp->skipNodes.prev_tenSpecialNode = (void *)prev;
      temp->skipNodes.fwd_tenSpecialNode = NULL;

      prev->skipNodes.fwd_tenSpecialNode = (void *)temp;
      memlist.skipNodes.prev_tenSpecialNode = temp;

      temp->numNodesAhead = ONE;
    }
  }
}

extern void *insert_salmalloc(size_t size)
{
  smem_blk_seg *seg = NULL; /* memory segment  */
  void *sNodeLocation = NULL;
  sNode *temp = NULL;

  /* Get node location. Save it for future reference. */
  sNodeLocation = (void *)sbrk(0);

  if (g_sal_head == NULL)
  {
    g_sal_head = sNodeLocation;
  }

  /* extend heap by sNode */
  temp = (sNode *)sbrk(sizeof(sNode));

  /* 
     Get current end of heap.
     Algorithm is: sNode + mem_seg. sNode carries 
     metadata about the mem_seg, for example if it
     is free or not.
  */
  seg = (smem_blk_seg *)sbrk(0);

  /* Extend heap */
  temp->memSegment = (void *)sbrk(size + sizeof(smem_blk_seg));

  seg->isFree = FALSE;
  seg->size = size;

  seg->locationOfsNode = sNodeLocation;

  temp->vNodeType = eNormal;

  g_sal_end = temp->memSegment + size + sizeof(smem_blk_seg);

  return temp;
}

/*
  Function to add a node to linked list. 
  @param size is the size of the object.
  ToDo: Make it more dynamic. 
*/
extern void *salmalloc(size_t size)
{
  smem_blk_seg *seg = NULL; /* memory segment  */

  /* If list is currently NULL add a new node. */
  if (memlist.head == NULL)
  {

    memlist.head = (sNode *)insert_salmalloc(size);

    memlist.head->numNodesAhead = ONE;

    memlist.head->next = NULL;
    memlist.length = 0;
    memlist.flagUpdateCurrIsFree = 0;

    //print_mem(memlist.head);
    memlist.head->skipNodes.prev_tenSpecialNode = memlist.head;
    memlist.head->skipNodes.fwd_tenSpecialNode = NULL;
    memlist.skipNodes.prev_tenSpecialNode = memlist.head;

    // printf("salmalloc ret:%p\n", memlist.head->memSegment + sizeof(smem_blk_seg));
    /* return start of our memory segment. */
    return memlist.head->memSegment + sizeof(smem_blk_seg);
  }
  else
  {

    sNode *temp = memlist.head;

    /* There are two possibilities here as to where to insert this node
       1. Either the node is free. so just return.
       2. Node is not free. got to allocate a new one. In this case,
       we need to return the previous node.       
    */
    //temp = placeToInsertNode(size);

    temp = test_insert(size);

    /* If there is free space. */
    if (memlist.flagUpdateCurrIsFree == TRUE)
    {

      memlist.flagUpdateCurrIsFree = FALSE;
      seg = temp->memSegment;
      seg->isFree = FALSE;

      return temp->memSegment + sizeof(smem_blk_seg);
    }

    temp->next = (struct sNode *)insert_salmalloc(size);

    /* set next node to NULL */
    temp = (sNode *)temp->next;
    temp->next = NULL;

    /* extend length of list. */
    set_length();

    link_skip_nodes(temp);

    if (temp->vNodeType == eNormal)
    {

      sNode *aheadNodes = (sNode *)memlist.skipNodes.prev_tenSpecialNode;

      aheadNodes->numNodesAhead++;
    }

    seg = temp->memSegment;
    seg->isFree = FALSE;
    seg->size = size;

    /* return memory segment */
    // printf("salmalloc ret:%p\n", temp->memSegment + sizeof(smem_blk_seg));
    return temp->memSegment + sizeof(smem_blk_seg);
  }
}

extern sNode *placeToInsertNode(size_t sizeObject)
{
  sNode *tempTenSkipNode = memlist.head;
  sNode *temp;
  smem_blk_seg *seg = tempTenSkipNode->memSegment;

  /* If there are no nodes yet ahead, so return NULL and add new node. */
  if (seg->isFree == TRUE && seg->size >= sizeObject)
  {
    memlist.flagUpdateCurrIsFree = 1;
    seg->isFree = FALSE;
    return tempTenSkipNode;
  }

  /* 
     Now for each ten Skip node, check
     two things. 1) Is this skip node free to be populated? If yes
     return it. 2) Are the number of elements in front of this skip Node
     less than 9? Now there are two possibilities. Either there is a node
     which is now free which was previously populated. In this case just
     return the node which is to be repopulated. Or number of nodes are
     less than 9. In this case, we need to add another node in front of
     the second last node, so return the second last node and inform
     insert and it needs to append this node.

     What if this Skip Node does not have space? Well, then move forward
     to next skip node until all Skip nodes are done for. If there is still
     no space, create another skip node and start populating it.
  */
  while (tempTenSkipNode != NULL)
  {

    smem_blk_seg *seg = tempTenSkipNode->memSegment;

    /* If this free space */
    if (seg->isFree == TRUE && seg->size >= sizeObject)
    {
      memlist.flagUpdateCurrIsFree = 1;
      seg->isFree = FALSE;
      return tempTenSkipNode;
    }

    /* If there is space for a node in front. */
    else if (tempTenSkipNode->numNodesAhead <= NINE)
    {
      sNode *temp = NULL;

      /* Nodes ahead are zero so just add a new node. */
      if (tempTenSkipNode->next == NULL)
      {
        return tempTenSkipNode;
      }

      temp = (sNode *)parse_eNormal_Nodes((sNode *)tempTenSkipNode, sizeObject);

      if (memlist.flagUpdateCurrIsFree == 1)
      {
        tempTenSkipNode->numNodesAhead++;
        return temp;
      }

      //print_debug(sizeObject);

      if (temp != NULL && seg->size >= sizeObject)
      {
        //print_mem(temp);
        seg->isFree = FALSE;

        //memlist.flagUpdateCurrIsFree = 1;
        return temp;
      }
    }

    /* If next fwd_TenSpecialNode is null, then we just return 
       the second last node to that null node and list is appended
       from front of it.
    */
    if (tempTenSkipNode->skipNodes.fwd_tenSpecialNode == NULL)
    {
      temp = tempTenSkipNode;
      while (temp->next != NULL)
      {
        temp = (sNode *)temp->next;
      }
      return temp;
    }

    //print_mem(tempTenSkipNode->skipNodes.fwd_tenSpecialNode);
    //printf("I am here.\n");
    tempTenSkipNode = tempTenSkipNode->skipNodes.fwd_tenSpecialNode;
  }

  return NULL;
}

/*
  function to free the allocated memory. @ptr is the pointer
  to allocated memory.
*/
extern void salfree(void *ptr)
{

  if (ptr == NULL)
  {
    return;
  }

  if (ptr < g_sal_head || ptr > g_sal_end)
  {
    return;
  }

  smem_blk_seg *seg = (ptr - sizeof(smem_blk_seg));
  sNode *temp = NULL;

  /* 
     seg is our node. Now either it is a normal node in which case
     we move forward to next skip node and then find our way back
     and update our node numNodes ahead. 
  */
  temp = seg->locationOfsNode;

  /* Ensure that it is a eNormal node. */

  /* 
     Now move back to next eTens node. Either you find the next
     eTens node ahead or the list has not been populated yet for a next
     eTens node. In former case, you just decrement its numNodesAhead.
     In latter, skip list has the location of last prev special eTens node,
     so go back and update it.
  */

  seg->isFree = TRUE;

  /* check if size of list is greater than 100 */
  if (get_length() > 99)
  {

    /* If this is a eHundreds type node, no need to go ahead, just update and move. */
    if (temp->vNodeType == eHundreds)
    {

      temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;
      temp->tenNodesAhead == 0 ? 0 : temp->tenNodesAhead--;

    } /* else if it is a eTens node */
    else if (temp->vNodeType == eTens)
    {

      sNode *prev = (sNode *)temp->skipNodes.prev_tenSpecialNode;

      /* update nodes ahead */
      temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;

      /* go and fine the next eHundreds node */
      while (temp != NULL && temp->vNodeType != eHundreds)
      {
        temp = (sNode *)temp->next;
      }

      /* If this is null, find the last 100 node and update numnodes ahead. */
      if (temp == NULL)
      {
        temp = memlist.skipNodes.prev_hundredSpecialNode;
        temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;
      }
      /* else get the last hundreds type node and update nodes ahead. */
      else if (temp->vNodeType == eHundreds)
      {
        prev = (sNode *)temp->skipNodes.prev_hundredSpecialNode;
        prev->numNodesAhead == 0 ? 0 : prev->numNodesAhead--;
      }
    } /* its a normal node. just find the next eTens for eHundreds node and update numnodes ahead. */
    else
    {

      while (temp != NULL && temp->vNodeType != eTens)
      {
        temp = (sNode *)temp->next;
      }

      if (temp != NULL)
      {
        temp = temp->skipNodes.fwd_tenSpecialNode;

        while (temp != NULL && temp->vNodeType != eHundreds)
        {
          temp = temp->skipNodes.fwd_tenSpecialNode;
        }

        if (temp != NULL)
        {
          sNode *prev = temp->skipNodes.prev_tenSpecialNode;
          prev->numNodesAhead == 0 ? 0 : prev->numNodesAhead--;
          temp = temp->skipNodes.prev_hundredSpecialNode;
          temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;
        }
      }
    }
  }
  else
  {

    /* else list is still less than hundred.
       Find the next eTens node and update nodes ahead.
    */
    if (temp->vNodeType != eNormal)
    {
      temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;
    }
    else
    {

      while (temp != NULL && temp->vNodeType != eTens)
      {
        temp = (sNode *)temp->next;
      }

      if (temp == NULL)
      {
        temp = memlist.skipNodes.prev_tenSpecialNode;
      }
      else
      {
        temp = temp->skipNodes.prev_tenSpecialNode;
      }

      temp->numNodesAhead == 0 ? 0 : temp->numNodesAhead--;
    }
  }
}

extern void print_salmalloc()
{
  sNode *temp = memlist.head;
  size_t listIndex = 0;

  while (temp != NULL)
  {
    ssize_t *ch = temp->memSegment + sizeof(smem_blk_seg);
    smem_blk_seg *seg = temp->memSegment;
    printf("listIndex: %d. Location of sNode: %p. isFree %d. character in address %p and print: %zd. Size is %d.\n", listIndex, seg->locationOfsNode, seg->isFree, (temp->memSegment) + sizeof(smem_blk_seg),
           *ch, seg->size);
    listIndex++;
    temp = (sNode *)temp->next;
  }
}

extern void print_skip_nodes(nodeType type)
{
  if (type == eTens)
  {
    size_t i = 0;
    sNode *temp = memlist.head;

    while (temp != NULL)
    {
      ssize_t *ch = temp->memSegment + sizeof(smem_blk_seg);
      printf("i == %d and ch: %zd.\n", i, *ch);
      temp = temp->skipNodes.fwd_tenSpecialNode;
      //printf("%p.\n", temp->memSegment + sizeof(smem_blk_seg));
      i++;
    }
  }
}

extern size_t get_length()
{
  return memlist.length;
}

extern size_t set_length()
{
  return memlist.length++;
}

extern sNode *copy_list(size_t size)
{
  return memlist.head;
}

extern void copy_list_1(sNode *temp)
{
  temp = (sNode *)memlist.head;
  printf("ch: %p.\n", temp->memSegment + sizeof(smem_blk_seg));
}

extern void print_length()
{
  printf("Length of list: %zd.\n", memlist.length);
}

/*
  function to find the next free node ahead of this
  special ten node. @temp is the current node. @objectSize
  is the size of object to be allocated memory.
*/

extern void *parse_eNormal_Nodes(sNode *temp, size_t objectSize)
{
  sNode *prev = (sNode *)temp;

  //printf("temp type: %d.\n", temp->vNodeType);

  /* Traverse the nodes till the next eTens special node */
  while (temp != NULL && temp->vNodeType == eNormal)
  {

    smem_blk_seg *seg = temp->memSegment;

    /* if this node is free and it can accomodate this object, return this node */
    if (seg->isFree == TRUE && seg->size >= objectSize)
    {
      /* If this is 1 that means add a new node in front of previous node */
      seg->isFree = FALSE;

      /* flag will be TRUE if this node can be returned to user */
      memlist.flagUpdateCurrIsFree = TRUE;

      //print_debug(objectSize);

      return temp;
    }

    prev = temp;
    temp = (sNode *)temp->next;
  }
  //print_mem(prev);
  return prev;
}

extern void print_mem(sNode *temp)
{
  smem_blk_seg *seg = temp->memSegment;
  ssize_t *ch = temp->memSegment + sizeof(smem_blk_seg);
  printf("temp address: %p and value: %zd. isFree: %d.\n", temp->memSegment + sizeof(smem_blk_seg), *ch, seg->isFree);
}

static void print_debug(size_t size)
{
  {
    printf("number is: %zd.\n", size);
  }
}

/*
  Function to find num nodes ahead of current 
  eHundred node. @curr is the previous node. @dest
  is the node to where to crawl upto. We jump in
  shapes of 10 nodes using tenSpecial node.
*/
static void countNodesAhead(sNode *curr, sNode *dest, nodeType type)
{
  size_t count = 0;
  sNode *temp = (sNode *)curr; /* copy current node location into temp.  */

  /* move from current to last node. */
  while (curr != dest)
  {
    //print_mem(curr);
    /* increment count. if curr is a tenSpecialNode, check
       if it is free or not. This is important because we
       don't count the special node along with its numNodesAhead.
    */

    count = count + curr->numNodesAhead;

    /* If type is hundred, move ten special node. */
    if (type == eHundreds)
    {
      curr = (sNode *)curr->skipNodes.fwd_tenSpecialNode;
    }
  }

  temp->numNodesAhead = count;
}

static sNode *test_insert(size_t sizeObject)
{
  sNode *temp = copy_list(sizeObject);
  smem_blk_seg *seg = temp->memSegment;

  while (temp != NULL)
  {
    seg = temp->memSegment;
    /*print_debug(temp->numNodesAhead);
      print_debug(seg->isFree);
      print_mem(temp);
    */
    /* If the skip node is free and can accomodate this object */
    if (seg->isFree == TRUE && seg->size >= sizeObject)
    {

      memlist.flagUpdateCurrIsFree = 1;
      seg->isFree = FALSE;
      temp->numNodesAhead++;
      return temp;
    }
    /* If the next node in front of skip node has not been populated */
    else if (temp->next == NULL)
    {
      return temp;
    }

    /* if head is free and number of free nodes ahead are less
       than totalNumNodesAhead - 2.
    */
    else if (temp->numNodesAhead < TEN)
    {

      sNode *prev = (sNode *)temp;

      temp = (sNode *)parse_eNormal_Nodes((sNode *)temp->next, sizeObject);

      if (memlist.flagUpdateCurrIsFree == 1)
      {

        seg = temp->memSegment;
        seg->isFree = FALSE;
        prev->numNodesAhead++;
        //print_debug(prev->numNodesAhead);

        return temp;
      }

      return temp;
    }

    /* else if the next skip special node is not there */
    else if (temp->skipNodes.fwd_tenSpecialNode == NULL)
    {
      while (temp->next != NULL)
      {
        temp = (sNode *)temp->next;
      }
      return temp;
    }

    /* else move to next special ten skip node */
    temp = (sNode *)temp->skipNodes.fwd_tenSpecialNode;
  }
  return temp;
}

/*
  return the correct size list
*/
static sList *return_list_of_size(size_t size)
{
  if (size == SIZE_1B)
  {
    return &memlist_1B;
  }
  else if (size == SIZE_2B)
  {
    return &memlist_2B;
  }
  else if (size == SIZE_4B)
  {
    return &memlist_4B;
  }

  return 0;
}

void *salcalloc(unsigned int sz, unsigned int n)
{
  void *p = salmalloc(sz * n);
  memset(p, 0, sz * n);
  return p;
}

void *salrealloc(void *ptr, unsigned int sz)
{
  smem_blk_seg *seg = (ptr - sizeof(smem_blk_seg));

  void *p = salmalloc(sz);

  if (ptr == NULL)
  {
    return p;
  }

  if (p != NULL)
  {
    if (sz > seg->size)
      memcpy(p, ptr, seg->size);
    else
      memcpy(p, ptr, sz);
  }
  salfree(ptr);
  return p;
}