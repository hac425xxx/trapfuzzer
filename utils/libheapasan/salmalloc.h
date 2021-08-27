#include <stdlib.h>
#include <unistd.h>

#define ZERO 0
#define ONE 1
#define NINE 9
#define TEN 10
#define HUNDRED 100
#define THOUSAND 1000
#define THREE 3


#define SIZE_1B 1
#define SIZE_2B 2
#define SIZE_4B 4
#define SIZE_64 64
#define SIZE_128 128
#define SIZE_256 256
#define SIZE_512 512
#define SIZE_1024 1024

#define TRUE 1
#define FALSE 0

#define EMPTY -1

typedef enum nodeSize {
  e64,
  e128,
  e256,
  e512,
  e1024,
  eRandom
} nodeSize;



#define SET_NODE_SIZE(vNode, size)						\
  if (size <= SIZE_64){vNode->vNodeSize = e64;}					\
  else if (size > SIZE_64 && size <= SIZE_128){vNode->vNodeSize = e128;} 	\
  else if (size > SIZE_128 && size <= SIZE_256){vNode->vNodeSize = e256;} 	\
  else if (size > SIZE_256 && size <= SIZE_512){vNode->vNodeSize = e512;} 	\
  else if (size > SIZE_512 && size <= SIZE_1024){vNode->vNodeSize = e1024;} 	\
  else {vNode->vNodeSize = eRandom;}						\

typedef struct mem_blk_seg {
  ssize_t isFree;
  size_t size;
  void *locationOfsNode;
}smem_blk_seg;

typedef enum nodeType {
  eNormal,
  eTens,
  eHundreds,
  eThousands
}nodeType;


typedef struct skip_list_nodes {
  void *prev_tenSpecialNode;
  void *prev_hundredSpecialNode;
  void *prev_thousandSpecialNode;
  void *fwd_tenSpecialNode;
  void *fwd_hundredSpecialNode;
  void *fwd_thousandSpecialNode;  
}skip_list_nodes;

typedef struct Node {
  struct sNode *next;
  void *memSegment;
  size_t spaceAhead;
  nodeType vNodeType;
  nodeSize vNodeSize;
  ssize_t numNodesAhead;
  skip_list_nodes skipNodes;
  ssize_t tenNodesAhead;

#define tenSkipNodeFree 1
#define hundredSkipNodeFree 2
#define thousandSkipNodeFree 4

}sNode;


typedef struct List {
  sNode *head;
  size_t length;
  sNode *tens;
  sNode *hundreds;
  sNode *thousands;
  skip_list_nodes skipNodes;
  size_t flagUpdateCurrIsFree;
}sList;




void *salmalloc(size_t);
void salfree(void *);
void *salrealloc(void *ptr, unsigned int sz);
void *salcalloc(unsigned int sz, unsigned int n);

extern void print_salmalloc();
extern void link_skip_nodes(sNode*);
extern void print_skip_nodes(nodeType);
extern size_t get_length();
extern size_t set_length();
extern void print_length();
extern sNode* copy_list(size_t);
extern void copy_list_1(sNode*);
extern void *skipSalmalloc(size_t);
extern void *insert_salmalloc(size_t);
extern sNode* placeToInsertNode(size_t);
extern void *parse_eNormal_Nodes(sNode *, size_t);
extern void print_mem(sNode*);
extern void *return_list_of_size_requested(size_t);
