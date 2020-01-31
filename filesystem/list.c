

#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "log.h"

block_t *createList(const char *name, unsigned int fd, int flags, int unlink, struct Node *cursor){

	block_t *block = (block_t *) malloc(sizeof(block_t));

	if (block == NULL){
		return NULL;
	}

	strcpy(block->block_name, name);
	block->block_fd = fd;
	block->flags = flags;
	block->unlink = unlink;
	block->cursor = cursor;
	block->next = NULL;
	block->prev = NULL;

	return block;
}

void insertAfter(struct Node *prev_node, block_t new_data){
	if (prev_node == NULL){
		printf("the given previous node cannot be NULL");
		return;
	}
	struct Node *new_node = (struct Node *)malloc(sizeof(struct Node));

	strcpy(new_node->block_name, new_data.block_name);
	new_node->block_fd = new_data.block_fd;
	new_node->cursor = new_data.cursor;
	new_node->flags = new_data.flags;
	new_node->unlink = new_data.unlink;

	new_node->next = prev_node->next;

	prev_node->next = new_node;

	new_node->prev = prev_node;

	if (new_node->next != NULL)
		new_node->next->prev = new_node;
}

void append(struct Node **head_ref, block_t new_data){

	struct Node *new_node = (struct Node *)malloc(sizeof(struct Node));

	struct Node *last = *head_ref;

	strcpy(new_node->block_name, new_data.block_name);
	new_node->block_fd = new_data.block_fd;
	new_node->cursor = new_data.cursor;
	new_node->flags = new_data.flags;
	new_node->unlink = new_data.unlink;

	new_node->next = NULL;

	if (*head_ref == NULL)
	{
		new_node->prev = NULL;
		*head_ref = new_node;
		return;
	}

	while (last->next != NULL)
		last = last->next;

	last->next = new_node;

	new_node->prev = last;

	return;
}

void deleteNode(struct Node **head_ref, struct Node *del){

	if (*head_ref == NULL || del == NULL)
		return;

	if (*head_ref == del)
		*head_ref = del->next;

	if (del->next != NULL)
		del->next->prev = del->prev;

	if (del->prev != NULL)
		del->prev->next = del->next;

	free(del);
	return;
}

void printlist(struct Node *head){
	struct Node *cur;

	log_msg("\n\t[LIST]\n");

	for(cur = head; cur != NULL; cur = cur->next){
		log_msg("\n\t\tblock: %p\n\t\tblock_name: %s\n\t\tblock_fd: %d\n\t\tcursor: %p\n", cur, cur->block_name, cur->block_fd, cur->cursor);
	}
	log_msg("\n\t[END_LIST]\n");
}