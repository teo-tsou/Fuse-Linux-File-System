
#ifndef _LIST_H_
#define _LIST_H_

#include <limits.h>
#include <fuse.h>

typedef struct Node{
	char block_name[NAME_MAX];
	unsigned int block_fd;
	int flags;
	int unlink;
	struct Node *cursor;
	struct Node *next;
	struct Node *prev;
} block_t;

void append(block_t **head_ref, block_t new_data);
void insertAfter(struct Node *prev_node, block_t new_data);
void deleteNode(block_t **head_ref, block_t *del);
void printlist(struct Node *head);
block_t *createList(const char *name, unsigned int fd, int flags, int unlink, struct Node *cursor);

#endif