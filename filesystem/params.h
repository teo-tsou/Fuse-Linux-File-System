/*
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  There are a couple of symbols that need to be #defined before
  #including all the headers.
*/

#ifndef _PARAMS_H_
#define _PARAMS_H_

// The FUSE API has been changed a number of times.  So, our code
// needs to define the version of the API that we assume.  As of this
// writing, the most current API version is 26
#define FUSE_USE_VERSION 26

// need this to get pwrite().  I have to use setvbuf() instead of
// setlinebuf() later in consequence.
#define _XOPEN_SOURCE 500

// maintain CORN-e-LIUS state in here
#include "list.h"
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define MAGIC_NUMBER "CORN-e-LIUS\0"
#define OPEN_FDS_MAX 100
#define NUM_BLOCKS 100
#define OPEN_BLOCKS_MAX 1000
#define BLOCK_SIZE 4096

// Struct representing the metadata
// of a single file
typedef struct meta{
	uid_t st_uid;
	gid_t st_gid;
	off_t st_size;
	struct timespec st_atim;
	struct timespec st_mtim;
} meta_t;

// Struct that represents an open
// block file
typedef struct open_block{
	char block_name[NAME_MAX];
	unsigned int block_fd;
	unsigned int open_file_ref;
} open_block_t;

// Struct that represents the block sequence
// needed in oreder to construct a particular
// file.
typedef struct block_links{
	unsigned int num_blocks;
	char blocks[NUM_BLOCKS][NAME_MAX];
} block_links_t;

struct os_state {
    FILE *logfile;
    char *rootdir;
	unsigned int fds_last_pos;
	block_t *file_descriptors[OPEN_FDS_MAX]; // TODO: Change it to dynamic at the end
	unsigned int num_open_blocks;
	open_block_t open_blocks[OPEN_BLOCKS_MAX]; //TODO: Change it to dynamic at the end
};

#define OS_DATA ((struct os_state *) fuse_get_context()->private_data)

#endif
