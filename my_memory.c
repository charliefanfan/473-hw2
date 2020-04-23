// Include files
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define  N_OBJS_PER_SLAB  64
#define MIN_CHUNK_SIZE 1024
#define MIN_POWER 10
#define buddy_debug 0
#define slab_debug 0

typedef struct UserSpace {
    int malloc_type;
    int mem_size;
    void *start_of_memory;
    void *end_of_memory;
} UserSpace;

typedef struct BuddyNode {
    void *address;
    int tag; // 0-free 1-allocated
    struct BuddyNode *next;
} BuddyNode;

typedef struct BuddyHead {
    BuddyNode *head;
    int nFree;
    int nBusy;
    int chunkSize;
} BuddyHead;

typedef struct Slab {
    void *start_of_slab;
    int *bitmap;
    int used;
    struct Slab *next;
} Slab;

typedef struct SlabController {
    int type; // size of each object
    int size; // total memory size of slabs with the same type
    // int nObjects; // number of objects with the the same type
    int used;
    int nSlabs;
    struct Slab *first;
    struct SlabController *next;
} SlabHead;

typedef struct SlabDescriptorTable {
    int nEntries;
    struct SlabController *head;
} SlabDescriptorTable;

int maxPower;
UserSpace *userSpace;
BuddyHead *allocTable;
SlabDescriptorTable *slabDT;

// Functional prototypes
void setup(int malloc_type, int mem_size, void *start_of_memory);

void *my_malloc(int size);

void my_free(void *ptr);

void init_user_space(int, int, void *);

void buddy_setup();

void slab_setup();

void *buddy_alloc(int size);

void buddy_free(void *ptr);

void printAllocTable();

void printSlabDescriptorTable();

///////////////////////////////////////////////////////////////////////////
void init_user_space(int malloc_type, int mem_size, void *start_of_memory) {
    assert(mem_size == 1 << 20);

    assert(mem_size % MIN_CHUNK_SIZE == 0);

    userSpace = (UserSpace *) malloc(sizeof(UserSpace));
    userSpace->malloc_type = malloc_type;
    userSpace->mem_size = mem_size;
    userSpace->start_of_memory = start_of_memory;
    userSpace->end_of_memory = start_of_memory + mem_size;
}

////////////////////////////////////////////////////////////////////////////
void buddy_setup() {
    allocTable = (BuddyHead *) malloc(sizeof(BuddyHead) * (maxPower + 1));
    int base = MIN_CHUNK_SIZE;
    for (int i = MIN_POWER; i <= maxPower; ++i) {
        allocTable[i].head = NULL;
        allocTable[i].nFree = 0;
        // allocTable[i].chunkSize = (int) pow(2.0, i);
        allocTable[i].chunkSize = base;
        base *= 2;
    }

    allocTable[maxPower].head = (BuddyNode *) malloc(sizeof(BuddyNode));
    allocTable[maxPower].head->address = userSpace->start_of_memory;
    allocTable[maxPower].nFree++;
    allocTable[maxPower].head->next = NULL;

    if (buddy_debug)
        printAllocTable();
}

////////////////////////////////////////////////////////////////////////////
void slab_setup() {
    slabDT = (SlabDescriptorTable *) malloc(sizeof(SlabDescriptorTable));
    slabDT->nEntries = 0;
    slabDT->head = NULL;
}

////////////////////////////////////////////////////////////////////////////
//
// Function     : setup
// Description  : initialize the memory allocation system
//
// Inputs       : malloc_type - the type of memory allocation method to be used [0..3] where
//                (0) Buddy System
//                (1) Slab Allocation

void setup(int malloc_type, int mem_size, void *start_of_memory) {
    init_user_space(malloc_type, mem_size, start_of_memory);
    // maxPower = (int) log2((double) mem_size);
    maxPower = 20;
    buddy_setup();
    if (malloc_type == 1) { // Slab Allocation
        slab_setup();
    }
}

////////////////////////////////////////////////////////////////////////////
//
// Function     : my_malloc
// Description  : allocates memory segment using specified allocation algorithm
//
// Inputs       : size - size in bytes of the memory to be allocated
// Outputs      : -1 - if request cannot be made with the maximum mem_size requirement

void *my_malloc(int size) {
    if (userSpace->malloc_type == 0)
        return buddy_alloc(size);

    if (slab_debug) {
        printf("request %d\nbefore alloc\n", size);
        printSlabDescriptorTable();
    }

    int type = size + 4;
    SlabHead *p;
    p = slabDT->head;
    while (p && p->type != type)p = p->next; // find matched slab type

    if (p == NULL || p->used == p->nSlabs * N_OBJS_PER_SLAB) { // if not found or there is no enough space unused
        if (p == NULL) {
            // create new Slab Head
            SlabHead *newSlabHead;
            newSlabHead = (SlabHead *) malloc(sizeof(SlabHead));
            newSlabHead->next = NULL;
            newSlabHead->first = NULL;
            newSlabHead->used = 0;
            newSlabHead->type = type;
            newSlabHead->nSlabs = 0;
            newSlabHead->size = type * N_OBJS_PER_SLAB;

            // insert to Slab Descriptor Table
            newSlabHead->next = slabDT->head;
            slabDT->head = newSlabHead;
            p = slabDT->head;
        }

        void *start_of_slab;
        Slab *slab;

        start_of_slab = buddy_alloc(p->size);
        if (start_of_slab == NULL || start_of_slab == -1)
            return -1;

        slab = (Slab *) malloc(sizeof(slab));
        slab->start_of_slab = start_of_slab;
        slab->used = 0;

        slab->bitmap = (int *) malloc(sizeof(int) * N_OBJS_PER_SLAB);
        for (int i = 0; i < N_OBJS_PER_SLAB; ++i) {
            slab->bitmap[i] = 0;
        }

        // insert slab
        slab->next = p->first;
        p->first = slab;
        p->nSlabs++;
    }

    Slab *tSlab;
    tSlab = p->first;

    while (tSlab && tSlab->used == N_OBJS_PER_SLAB)tSlab = tSlab->next;
    assert(tSlab != NULL);

    int i = 0;
    while (i < N_OBJS_PER_SLAB && tSlab->bitmap[i] == 1)++i;
    assert(i < N_OBJS_PER_SLAB);
    tSlab->bitmap[i] = 1;
    tSlab->used++;
    p->used++;

    void *ptr;
    ptr = tSlab->start_of_slab + type * i;

    ((int *) ptr)[0] = type;

    //printf("alloc %d\n", (int)(ptr - userSpace->start_of_memory));
    ptr += 4;

    if (slab_debug) {
        printf("after alloc\n");
        printSlabDescriptorTable();
    }

    return ptr;
}

////////////////////////////////////////////////////////////////////////////
//
// Function     : my_free
// Description  : deallocated the memory segment being passed by the pointer
//
// Inputs       : ptr - pointer to the memory segment to be free'd
// Outputs      :

void my_free(void *ptr) {
    if (userSpace->malloc_type == 0) {
        buddy_free(ptr);
        return;
    }

    ptr -= 4;
    int type = ((int *) ptr)[0];

    // find matched type
    SlabHead *h;
    h = slabDT->head;
    while (h && h->type != type)h = h->next;
    if (h == NULL)return;

    // find matched slab
    Slab *slab;
    slab = h->first;
    void *end;
    while (slab) {
        end = slab->start_of_slab + N_OBJS_PER_SLAB * type;
        if (slab->start_of_slab <= ptr && ptr < end)
            break;
        slab = slab->next;
    }
    if (slab == NULL)return;

    // find matched object
    for (int i = 0; i < N_OBJS_PER_SLAB; ++i) {
        end = slab->start_of_slab + type * i;
        if (end == ptr) {
            if (slab->bitmap[i] == 0)
                return;
            slab->bitmap[i] = 0;
            slab->used--;
            h->used--;
            break;
        }
    }

    // if the whole slab is free, then free it
    if (slab->used == 0) {
        // first remove the slab from the list: h
        Slab *prev = h->first;
        if (prev == slab) {
            h->first = prev->next;
        } else {
            assert(prev != NULL);
            while (prev->next != slab)prev = prev->next;
            assert(prev != NULL);
            prev->next = slab->next;
        }

        // return the space to buddy system
        buddy_free(slab->start_of_slab);

        h->nSlabs--;
    }
}

///////////////////////////////////////////////////////////////////////////
void *buddy_alloc(int size) {
    if (buddy_debug)
        printf("request %d\n", size);

    int needSize = size + 4;
    BuddyNode *p, *q;
    void *ret = NULL;
    int needk;
    int flag = 1;

    for (int i = MIN_POWER; i <= maxPower; ++i) {
        if (flag && allocTable[i].chunkSize >= needSize) {
            flag = 0;
            needk = i;
        }

        if (allocTable[i].chunkSize >= needSize && allocTable[i].nFree > 0) { // satisfy
            void *minAddr = userSpace->start_of_memory + userSpace->mem_size + 1;
            p = allocTable[i].head;
            q = p;
            while (p) { // find the min address
                if (p->tag == 0 && p->address < minAddr) {
                    minAddr = p->address;
                    q = p;
                }
                p = p->next;
            }
            ret = minAddr + 4;

            p = allocTable[i].head;
            // remove q from allocTable[i]
            if (p == q) {
                allocTable[i].head = p->next;
            } else {
                while (p->next && p->next != q)p = p->next; // find q's previous node
                assert(p->next != NULL);
                p->next = p->next->next;
                free(q);
            }
            allocTable[i].nFree--;

            // insert new busy node to needk
            BuddyNode *newBusyNode = (BuddyNode *) malloc(sizeof(BuddyNode));
            newBusyNode->tag = 1;
            newBusyNode->address = minAddr;
            newBusyNode->next = allocTable[needk].head;
            allocTable[needk].head = newBusyNode;
            allocTable[needk].nBusy++;

            minAddr += allocTable[needk].chunkSize;

            // allocate rest space to allocTable[needk...i-1]
            for (int j = needk; j < i; ++j) {
                BuddyNode *newFreeNode = (BuddyNode *) malloc(sizeof(BuddyNode));
                newFreeNode->address = minAddr;
                newFreeNode->tag = 0;
                newFreeNode->next = allocTable[j].head;
                allocTable[j].head = newFreeNode;
                allocTable[j].nFree++;
                minAddr += allocTable[j].chunkSize;
            }

            break;
        }
    }

    if (buddy_debug)
        printAllocTable();

    return ret ? ret : -1;
}

///////////////////////////////////////////////////////////////////////////
void buddy_free(void *ptr) {
    ptr -= 4;
    int intPtr = (int) (ptr - userSpace->start_of_memory);

    if (buddy_debug) {
        printf("free %d\n", (int) (ptr - userSpace->start_of_memory));
        printAllocTable();
    }


    int targetIndex = -1;
    BuddyNode *target, *p;
    int found = 0;
    for (int i = MIN_POWER; i <= maxPower; ++i) { // find target
        if (found) break;
        p = allocTable[i].head;
        while (p) {
            if (p->address == ptr) {
                targetIndex = i;
                target = p;
                target->tag = 0;
                p = NULL;
                found = 1;
                break;
            }
            p = p->next;
        }
    }

    if (buddy_debug)printf("found target index: %d\n", targetIndex);

    if (targetIndex == -1) return;

    // remove target
    if (buddy_debug)printf("remove target\n");
    BuddyNode *prev = allocTable[targetIndex].head;
    if (prev == target) {
        allocTable[targetIndex].head = prev->next;
    } else {
        while (prev->next != target)prev = prev->next;
        prev->next = prev->next->next;
    }
    allocTable[targetIndex].nBusy--;

    if (buddy_debug)printAllocTable();


    // try to combine
    for (int i = targetIndex; i <= maxPower; ++i) {
        void *buddyAddr;
        int curChunkSize = allocTable[i].chunkSize;
        int nextChunkSize = curChunkSize * 2;
        unsigned long rest = (ptr - userSpace->start_of_memory) % nextChunkSize;
        if (rest == 0)
            buddyAddr = ptr + curChunkSize;
        else if (rest == curChunkSize)
            buddyAddr = ptr - curChunkSize;

        intPtr = (int) (ptr - userSpace->start_of_memory);
        int intBuddy = (int) (buddyAddr - userSpace->start_of_memory);

        // find buddy
        p = allocTable[i].head;
        while (p) {
            if (p->address == buddyAddr) {
                break;
            }
            p = p->next;
        }

        // int intPaddr = (int) (p->address - userSpace->start_of_memory);

        if (p == NULL || p->tag == 1) { // if buddy is busy
            target->tag = 0;
            target->address = ptr;
            target->next = allocTable[i].head;
            allocTable[i].head = target;
            allocTable[i].nFree++;
            break;
        } else { // if buddy is free, remove it
            prev = allocTable[i].head;
            if (prev == p) {
                allocTable[i].head = prev->next;
            } else {
                while (prev->next != p)prev = prev->next;
                prev->next = prev->next->next;
                free(p);
            }
            allocTable[i].nFree--;

            if (buddy_debug) {
                printf("after remove buddy\n");
                printAllocTable();
            }

            // update ptr
            if (buddyAddr < ptr) ptr = buddyAddr;
        }

    }
    if (buddy_debug) {
        printf("after free\n");
        printAllocTable();
    }
}

///////////////////////////////////////////////////////////////////////////
void printAllocTable() {
    int base = 1024;
    printf("allocTable:\n");
    for (int i = MIN_POWER; i <= maxPower; ++i) {
        printf("%d(%d): ", i, base);

        BuddyNode *p;
        p = allocTable[i].head;
        if (p == NULL) {
            printf("null\n");
        } else {
            while (p) {
                printf("[%d-%d] ", (int) (p->address - userSpace->start_of_memory),
                       (int) (p->address - userSpace->start_of_memory) + base);
                if (p->tag == 1)
                    printf("busy ");
                else
                    printf("free ");
                printf("-> ");
                p = p->next;
            }
            printf("null\n");
        }
        base *= 2;
    }
    printf("##############################################################@\n");
}


void printSlab(Slab *p, int objSize) {
    void *loc;
    printf("[");
    printf("%d, ", (int) (p->start_of_slab - userSpace->start_of_memory));

    loc = p->start_of_slab + N_OBJS_PER_SLAB * objSize;
    printf("%d", (int) (loc - userSpace->start_of_memory));
    printf("]\n#");
    for (int i = 0; i < N_OBJS_PER_SLAB; ++i) {
        printf("%d", p->bitmap[i]);
    }
}

void printSlabList(Slab *p, int objSize) {
    while (p) {
        printSlab(p, objSize);
        printf("->");
        p = p->next;
    }
    printf("null\n");
}

void printSlabDescriptorTable() {
    printf("\n############################################################\n");
    SlabHead *h = slabDT->head;
    printf("#SlabDescriptorTable\n");
    while (h) {
        printf("#type: %d ", h->type);
        printSlabList(h->first, h->type);
        h = h->next;
    }
    printf("############################################################\n\n");
}