/*
  Big Brother File System
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h

  The point of this FUSE filesystem is to provide an introduction to
  FUSE.  It was my first FUSE filesystem as I got to know the
  software; hopefully, the comments in this code will help people who
  follow later to get a gentler introduction.

  This might be called a no-op filesystem:  it doesn't impose
  filesystem semantics on top of any other existing structure.  It
  simply reports the requests that come in, and passes them to an
  underlying filesystem.  The information is saved in a logfile named
  CORN-e-LIUS.log, in the directory from which you run CORN-e-LIUS.
*/
#include "config.h"
#include "params.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <math.h>
#include <openssl/sha.h>

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include "log.h"
#include "list.h"

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.
static void os_fullpath(char fpath[PATH_MAX], const char *path){


    strcpy(fpath, OS_DATA->rootdir);

	if('/' != path[0]){
		strncat(fpath, "/", 1);
	}

    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
				    // break here

    log_msg("    os_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
	    OS_DATA->rootdir, path, fpath);
}

// This function will update the metadata struct written in the instruction file
// the reason behind using so many arguments is to be able to file tune which of
// the metadata we wish to update and not update all of them.
int os_update_meta(int fd, uid_t *new_uid, gid_t *new_gid, off_t *new_size, time_t *new_atime, time_t *new_mtime){
	meta_t old_meta;

	while (lseek(fd, sizeof(MAGIC_NUMBER), SEEK_SET) != sizeof(MAGIC_NUMBER));

	while(read(fd, &old_meta, sizeof(meta_t)) != sizeof(meta_t)){
		lseek(fd, sizeof(MAGIC_NUMBER), SEEK_SET);
	}

	if(new_uid != NULL){
		old_meta.st_uid = (uid_t) *new_uid;
	}

	if(new_gid != NULL){
		old_meta.st_gid = (gid_t) *new_gid;
	}

	// Not good practice but meeehhhh...
	if(new_size != NULL){
		if (*new_size < 0){
			old_meta.st_size = (off_t) -(*new_size);
		}
		else{
			old_meta.st_size += (off_t) (*new_size);
		}
	}

	if(new_mtime == NULL){
		old_meta.st_mtim.tv_sec = time(NULL);
	}else{
		old_meta.st_mtim.tv_sec = (long int) *new_mtime;
	}

	if (new_atime == NULL){
		old_meta.st_atim.tv_sec = time(NULL);
	}else{
		old_meta.st_atim.tv_sec = (long int) *new_atime;
	}

	while (lseek(fd, sizeof(MAGIC_NUMBER), SEEK_SET) != sizeof(MAGIC_NUMBER));

	while(write(fd, &old_meta, sizeof(meta_t)) != sizeof(meta_t)){
		lseek(fd, sizeof(MAGIC_NUMBER), SEEK_SET);
	}

	return 0;
}

void convertSHA1ToString(const unsigned char *hash, char *str)
{
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		sprintf(&str[i * 2], "%02X", hash[i]);
	}

	str[2 * SHA_DIGEST_LENGTH] = 0;
}

void logOpenBlocks(void){
	int i;

	log_msg("\n    [OPEN_BLOCKS]\n");

	for(i = 0; i < OS_DATA->num_open_blocks; i++){
		log_msg("\n\t\tBlock_name: %s\n\t\tBlock_fd: %d\n\t\tBlock_refs: %d\n", OS_DATA->open_blocks[i].block_name, OS_DATA->open_blocks[i].block_fd, OS_DATA->open_blocks[i].open_file_ref);
	}

	log_msg("\n    [END_OPEN_BLOCKS\n");
}

///////////////////////////////////////////////////////////
//
// Prototypes for all these functions, and the C-style comments,
// come from /usr/include/fuse.h
//
/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.  The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */

int os_getattr(const char *path, struct stat *statbuf){
    char fpath[PATH_MAX], magic[sizeof(MAGIC_NUMBER) + 1] = {'\0'};
	int file_fd, ret;
	meta_t file_meta;
	struct stat path_stat;

	log_msg("\nos_getattr(path=\"%s\", statbuf=0x%08x)\n", path, statbuf);

    os_fullpath(fpath, path);

	ret = log_syscall("\n    [stat]", stat(fpath, &path_stat), 0);

	if (ret < 0){
		log_stat(statbuf);
		return ret;
	}

	if (S_ISREG(path_stat.st_mode)){
		log_msg("\n    [TYPE] file %s\n", fpath);

		ret = log_syscall("\n    [access]", access(fpath, F_OK), 0);

		if (ret < 0){
			return ret;
		}

		file_fd = log_syscall("\n    [open]", open(fpath, O_RDONLY), 0);

		if (file_fd < 0){
			return file_fd;
		}

		// If the size of the whole file is less than the magic number there is no way
		// that this file is compatible with cornelius.
		if (path_stat.st_size < sizeof(MAGIC_NUMBER)){
			log_msg("\n    [COMPATIBILITY] Given file %s is not compatible with CORN-e-LIUS\n", fpath);

			memset(statbuf, 0, sizeof(struct stat));
			return -1;
		}

		do{
			ret = log_syscall("\n    [read]", pread(file_fd, &magic, sizeof(MAGIC_NUMBER), 0), 0);

			if(ret < 0){
				return ret;
			}

		}while(ret != sizeof(MAGIC_NUMBER));

		if(strncmp(magic, MAGIC_NUMBER, sizeof(MAGIC_NUMBER)) != 0){
			log_msg("\n    [COMPATIBILITY] Given file %s is not compatible with CORN-e-LIUS\n", fpath);

			memset(statbuf, 0, sizeof(struct stat));
			return -1;
		}

		ret = 0;

		do{
			ret = log_syscall("\n    [read]", pread(file_fd, &file_meta, sizeof(meta_t), sizeof(MAGIC_NUMBER)), 0);

			if(ret < 0){
				return ret;
			}

		}while(ret != sizeof(meta_t));

		ret = 0;

		ret = log_syscall("\n    [close]", close(file_fd), 0);

		if(ret < 0)
			return ret;

		stat(fpath, statbuf);

		statbuf->st_uid = file_meta.st_uid;
		statbuf->st_gid = file_meta.st_gid;
		statbuf->st_size = file_meta.st_size;
		statbuf->st_atime = file_meta.st_atim.tv_sec;
		statbuf->st_mtime = file_meta.st_mtim.tv_sec;

	}
	else if(S_ISDIR(path_stat.st_mode)){
		log_msg("\n    [TYPE] directory %s\n", fpath);

		ret = log_syscall("\n    [stat]", stat(fpath, statbuf), 0);

		 if (ret < 0){
			log_msg("\n    [DIRECTORY] %s does not exist! \n", fpath);

			return ret;
		}
	}

	log_stat(statbuf);

	return ret;
}

/** Create a file node
 *
 * There is no create() operation, mknod() will be called for
 * creation of all non-directory, non-symlink nodes.
 */
// shouldn't that comment be "if" there is no.... ?
int os_mknod(const char *path, mode_t mode, dev_t dev){
    int fd, ret;
    char fpath[PATH_MAX];

    log_msg("\nos_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n", path, mode, dev);

    os_fullpath(fpath, path);

	if(S_ISREG(mode)){
		fd = log_syscall("    \n[open]", open(fpath, O_CREAT | O_EXCL | O_RDWR, mode), 0);

		if(fd < 0){
			return fd;
		}

		// Structures needed to create the instruction file
		meta_t file_meta = {0};
		block_links_t block_info = {0};
		struct stat file_info = {0};

		ret = log_syscall("    \n[stat]", stat(fpath, &file_info), 0);
		log_stat(&file_info);

		if(ret < 0){
			return ret;
		}

	 	file_meta.st_uid = file_info.st_uid;
		file_meta.st_gid = file_info.st_gid;
		file_meta.st_size = file_info.st_size;
		file_meta.st_atim.tv_sec = time(NULL);
		file_meta.st_mtim.tv_sec =time(NULL);

		block_info.num_blocks = 0;

		do{
			ret = log_syscall("\n    [write]", pwrite(fd, MAGIC_NUMBER, sizeof(MAGIC_NUMBER), 0), 0);

			if(ret < 0)
				return ret;

		}while(ret != sizeof(MAGIC_NUMBER));

		ret = 0;

		do{
			ret = log_syscall("\n    [write]", pwrite(fd, &file_meta, sizeof(meta_t), sizeof(MAGIC_NUMBER)), 0);

			if(ret < 0)
				return ret;

		}while(ret != sizeof(meta_t));

		ret = 0;

		do{
			ret = log_syscall("\n    [write]", pwrite(fd, &block_info, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

			if(ret < 0)
				return ret;

		}while(ret != sizeof(block_links_t));

		ret = log_syscall("    \n[close]", close(fd), 0);

	}else{
		log_msg("   \n[mknod] Requested to create non regular file\n\tmode: %d", mode);
		return -1;
	}

	return ret;
}

/** Remove a file */
int os_unlink(const char *path){
	int ret = 0, file_fd, block_fd, found = 0, refs, i, j;
    char fpath[PATH_MAX];
	const char *path_ptr;
	block_links_t block_sq = {0};

	log_msg("os_unlink(path=\"%s\")\n", path);
	os_fullpath(fpath, path);

	path_ptr = path[0] == '/'? &path[1]: path;
	log_msg("\n    [unlink] request to unlink file %s\n", path_ptr);

	for(i = 0; i < OS_DATA->fds_last_pos; i++){
		if(strcmp(path_ptr, OS_DATA->file_descriptors[i]->block_name) == 0){
			log_msg("\n    [unlink] file: %s is open\n", path_ptr);
			OS_DATA->file_descriptors[i]->unlink = 1;

			log_msg("\n    [unlink] returning %d", ret);
			return ret;
		}
	}

	file_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

	if(file_fd < 0)
		return file_fd;

	do{
		ret = log_syscall("\n    [read]", pread(file_fd, &block_sq, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

		if(ret < 0)
			return ret;
	}while(ret < sizeof(block_links_t));

	for(i = 0; i < block_sq.num_blocks; i++){
		found = 0;

		for(j = 0; j < OS_DATA->num_open_blocks; j++){
			if(strcmp(block_sq.blocks[i], OS_DATA->open_blocks[j].block_name) == 0){
				log_msg("\n    [open] found block: %s with block_fd: %d with refs: %d updated refs: %d\n", block_sq.blocks[i], OS_DATA->open_blocks[j].block_fd, OS_DATA->open_blocks[j].open_file_ref, OS_DATA->open_blocks[j].open_file_ref - 1);

				found = 1;
				block_fd = OS_DATA->open_blocks[j].block_fd;

				if(--(OS_DATA->open_blocks[j].open_file_ref) == 0){
					memcpy(&OS_DATA->open_blocks[j], &OS_DATA->open_blocks[--(OS_DATA->num_open_blocks)], sizeof(open_block_t));
					memset(&OS_DATA->open_blocks[OS_DATA->num_open_blocks], 0, sizeof(open_block_t));
				}

				break;
			}
		}

		memset(fpath, 0, PATH_MAX);
		os_fullpath(fpath, block_sq.blocks[i]);

		if(!found){
			log_msg("\n    [unlink] openning block: %s internally\n", fpath);
			block_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

			if(block_fd < 0)
				return block_fd;
		}

		do{
			ret = log_syscall("\n    [read]", pread(block_fd, &refs, sizeof(int), sizeof(int)), 0);

			if(ret < 0)
				return ret;
		}while(ret < sizeof(int));

		log_msg("\n    [unlink] block's refs: %d\n    [unlink] updated refs: %d\n", refs, refs - 1);

		if((--refs) == 0){
			ret = log_syscall("\n    [unlink]", unlink(fpath), 0);

			if (ret < 0)
				return ret;
		}else{
			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if(ret < 0)
					return ret;
			}while(ret < sizeof(int));
		}

		ret = log_syscall("\n    [close]", close(block_fd), 0);

		if (ret < 0)
			return ret;
	}

	ret = log_syscall("\n    [close]", close(file_fd), 0);

	if (ret < 0)
		return ret;

	memset(fpath, 0, PATH_MAX);
	os_fullpath(fpath, path);

	log_msg("\n    [unlink] unlinking instruction file: %s\n", fpath);
	ret = log_syscall("\n    [unlink]", unlink(fpath), 0);

	if (ret < 0)
		return ret;

	return ret;
}

/** Change the size of a file */
int os_truncate(const char *path, off_t newsize){
    char fpath[PATH_MAX] = {'\0'}, block_name[NAME_MAX] = ".~";
	unsigned char block_hash[SHA_DIGEST_LENGTH + 1] = {'\0'};
	int ret = 0, newsize_in_blocks = 0, oldsize_in_blocks = 0, blocks_to_del = 0, blocks_to_add = 0, refs = 0, i, j;
	int file_fd = 0, block_fd, found = 0;
	meta_t file_meta = {0};
	block_links_t block_sq = {0};
	DIR *rootdir = NULL;
	struct dirent *dir_entry = NULL;

    log_msg("\nos_truncate(path=\"%s\", newsize=%lld)\n", path, newsize);
    os_fullpath(fpath, path);

	file_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

	if(file_fd < 0){
		return file_fd;
	}

	do{
		ret = log_syscall("\n    [read]", pread(file_fd, &file_meta, sizeof(meta_t), sizeof(MAGIC_NUMBER)), 0);

		if(ret < 0)
			return ret;
	}while(ret < sizeof(meta_t));

	do{
		ret = log_syscall("\n    [read]", pread(file_fd, &block_sq, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

		if (ret < 0)
			return ret;
	} while (ret < sizeof(block_links_t));

	newsize_in_blocks = (int)ceil((double)newsize / BLOCK_SIZE);
	oldsize_in_blocks = (int)ceil((double)file_meta.st_size / BLOCK_SIZE);

	log_msg("\n    [truncate] newsize_in_blocks: %d oldsize_in_blocks: %d", newsize_in_blocks, oldsize_in_blocks);

	if(file_meta.st_size > newsize){
		// Probably this is tha faulty part :(
		blocks_to_del = oldsize_in_blocks - newsize_in_blocks;
		log_msg("\n    [truncate] blocks_to_dell: %d\n", blocks_to_del);

		for(i = 0; i < blocks_to_del; i++){
			memset(fpath, 0, PATH_MAX);
			os_fullpath(fpath, block_sq.blocks[block_sq.num_blocks - 1]);

			for(j = 0; j < OS_DATA->num_open_blocks; j++){
				if(strcmp(OS_DATA->open_blocks[j].block_name, block_sq.blocks[block_sq.num_blocks - 1]) == 0){
					found = 1;
					block_fd = OS_DATA->open_blocks[j].block_fd;
					break;
				}
			}

			if(found){

				do{
					ret = log_syscall("\n    [read]", pread(block_fd, &refs, sizeof(int), sizeof(int)), 0);

					if (ret < 0)
						return ret;
				} while (ret < sizeof(int));

				refs--;

				do{
					ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

					if (ret < 0)
						return ret;
				} while (ret < sizeof(int));

				if(refs == 0){
					ret = log_syscall("\n    [close]", close(block_fd), 0);

					if(ret < 0)
						return ret;
				}

			}else{
				block_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

				if (block_fd < 0){
					return block_fd;
				}

				do{
					ret = log_syscall("\n    [read]", pread(block_fd, &refs, sizeof(int), sizeof(int)), 0);

					if (ret < 0)
						return ret;
				} while (ret < sizeof(int));

				refs--;

				do{
					ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

					if (ret < 0)
						return ret;
				} while (ret < sizeof(int));

				ret = log_syscall("\n    [close]", close(block_fd), 0);

				if (ret < 0){
					return ret;
				}
			}

			if (refs == 0){
				ret = log_syscall("\n    [unlink]", unlink(fpath), 0);

				if (ret < 0)
				{
					return ret;
				}
			}

			memset(block_sq.blocks[block_sq.num_blocks - 1], 0, NAME_MAX);

			log_msg("\n\t[BLOCK_LINKS]: %s\n", path);
			for (j = 0; j < block_sq.num_blocks; j++){
				log_msg("\n\t\tname: %s", block_sq.blocks[j]);
			}
			log_msg("\n\t[END_BLOCK_LINKS]\n");

			block_sq.num_blocks--;
		}
	}else{
		blocks_to_add = newsize_in_blocks - oldsize_in_blocks;
		log_msg("\n    [truncate] blocks_to_add: %d", blocks_to_add);

		char empty_buf[BLOCK_SIZE] = {'\0'};

		SHA1((unsigned char *)empty_buf, BLOCK_SIZE, block_hash);
		// block_name: .~HASH
		convertSHA1ToString(block_hash, &block_name[2]);

		rootdir = opendir(OS_DATA->rootdir);

		dir_entry = readdir(rootdir);

		if(dir_entry == NULL){
			return ret;
		}

		do{
			if (strcmp(dir_entry->d_name, block_name) == 0){
				log_msg("\n    [write] hash searched %s\tfound hash %s\n", block_name, dir_entry->d_name);
				found = 1;
				break;
			}
		}while((dir_entry = readdir(rootdir)) != NULL);

		if (!found){
			int block_size = BLOCK_SIZE;

			log_msg("\n    [write] creating new block with hash: %s\n\t", block_name);

			os_fullpath(fpath, block_name);

			block_fd = log_syscall("\n    [open]", open(fpath, O_CREAT | O_EXCL | O_RDWR, S_IRWXU), 0);

			if (block_fd < 0){
				return block_fd;
			}

			refs = 0;

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, &block_size, sizeof(int), 0), 0);

				if (ret < 0)
					return 0;
			} while (ret < sizeof(int));

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, empty_buf, BLOCK_SIZE, 2 * sizeof(int)), 0);

				if (ret < 0)
					return 0;
			} while (ret < BLOCK_SIZE);

		}else{
			memset(fpath, 0, PATH_MAX);
			os_fullpath(fpath, block_name);

			block_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

			if(block_fd < 0){
				return block_fd;
			}

			do{
				ret = log_syscall("\n    [read]", pread(block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if(ret < 0){
					return ret;
				}
			}while(ret < sizeof(int));
		}

		for(i = 0; i < blocks_to_add; i++){

			strcpy(block_sq.blocks[block_sq.num_blocks], block_name);
			block_sq.num_blocks++;
			refs++;
		}

		do{
			ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

			if(ret < 0){
				return ret;
			}
		}while(ret < sizeof(int));

		ret = log_syscall("\n    [close]", close(block_fd), 0);

		if(ret < 0)
			return ret;

		ret = log_syscall("\n    [closedir]", closedir(rootdir), 0);
	}

	off_t update_size = -newsize;
	log_msg("\n   [truncate] update_size: %d\n", update_size);
	os_update_meta(file_fd, NULL, NULL, &update_size, NULL, NULL);

	do{
		ret = log_syscall("\n    [write]", pwrite(file_fd, &block_sq, sizeof(block_links_t),sizeof(meta_t) + sizeof(MAGIC_NUMBER)), 0);

		if(ret < 0)
			return ret;
	}while(ret < sizeof(block_links_t));

	ret = log_syscall("\n    [close]", close(file_fd), 0);

	if(ret < 0)
		return ret;

	return ret;
}

/** Change the access and/or modification times of a file */
/* note -- I'll want to change this as soon as 2.6 is in debian testing */
int os_utime(const char *path, struct utimbuf *ubuf){
    int ret = 0;
	char fpath[PATH_MAX];

    log_msg("\nos_utime(path=\"%s\", ubuf=0x%08x)\n", path, ubuf);
    os_fullpath(fpath, path);

	ret = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

	if(ret < 0){
		return ret;
	}

	if(ubuf == NULL){
		os_update_meta(ret, NULL, NULL, NULL, NULL, NULL);
	}else{
		os_update_meta(ret, NULL, NULL, NULL, &ubuf->actime, &ubuf->modtime);
	}

	ret = log_syscall("\n    [close]", close(ret), 0);

    return ret;
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 * Changed in version 2.2
 */
int os_open(const char *path, struct fuse_file_info *fi){
    int ret = 0, file_fd = 0, found = 0, i, j;
    char fpath[PATH_MAX] = {'\0'};
	DIR *rootdir = NULL;
	struct dirent *dir_entry = NULL;
	block_links_t block_instructions = {0};
	block_t tmp_block = {};

    log_msg("\nos_open(path\"%s\", fi=0x%08x)\n",path, fi);
    os_fullpath(fpath, path);

	// Check if an open is requested on a file that does not
	// exist on the file-system.
	rootdir = opendir(OS_DATA->rootdir);
	dir_entry = readdir(rootdir);

	if (dir_entry == 0){
		ret = log_error("os_readdir readdir");
		return ret;
	}

	do{
		if(strcmp(&path[1], dir_entry->d_name) == 0){
			found = 1;
			log_msg("\n    [strcmp] requested: %s    found %s\n", path, dir_entry->d_name);
			break;
		}

	}while((dir_entry = readdir(rootdir)) != NULL);

	ret = log_syscall("\n    [closedir]", closedir(rootdir), 0);

	if(ret < 0)
		return ret;

	if(!found){
		log_msg("\n    File %s not found!\n", path);
		log_msg("    [ERROR] [open]: %s\n", strerror(ENOENT));
		return -ENOENT;
	}
	found = 0;

	// If an open is requested at a file that is already opened
	// then the file does not open again and only the flags and
	// the cursor are updated.
	for(i = 0; i < OS_DATA->fds_last_pos; i++){
		if(strcmp(OS_DATA->file_descriptors[i]->block_name, &path[1]) == 0){
			OS_DATA->file_descriptors[i]->flags = fi->flags;
			OS_DATA->file_descriptors[i]->cursor = OS_DATA->file_descriptors[i]->next;
			// Return a file handler the the requested (instruction) file.
			fi->fh = OS_DATA->file_descriptors[i]->block_fd;

			log_msg("\n    [open] file: %s is already open....returning %d\n", path, ret);
			os_update_meta(OS_DATA->file_descriptors[i]->block_fd, NULL, NULL, NULL, NULL, NULL);
			return ret;
		}
	}

	// Open the instruction file
    file_fd = log_syscall("open", open(fpath, O_RDWR), 0);
	os_update_meta(file_fd, NULL, NULL, NULL, NULL, NULL);

	if (file_fd < 0){
		ret = log_error("open");
		return ret;
	}
	// File descriptor of instruction file
	fi->fh = file_fd;
    log_fi(fi);

	// Bypass the MAGIC_NUMBER and the meta_t struct
	//TODO: check magic numberc
	// It is assumed that at this stage syscall getattr has already been called
	// and we don't need to chech again for existance and compatibility
	// Read the instructoins: block_links_t struct block_instructions
	do{
		ret = log_syscall("\n    [read]", pread(file_fd, &block_instructions, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

		if(ret < 0)
			return ret;

	}while(ret != sizeof(block_links_t));

	ret = 0;
	// Initialize the list head for this particular file
	// In the head is stored the name, file descriptor, cursor and the flags passed by open
	// for the instruction file, and each node of this list will represent the sequence of
	// blocks needed in order to construct the actual file with its data.
	log_msg("\n    [open] creating list head at pos: %d", OS_DATA->fds_last_pos);

	OS_DATA->file_descriptors[OS_DATA->fds_last_pos] = createList(&path[1], file_fd, fi->flags, 0, NULL);

	// For each block found in the instruction file:
	//		Search if the block file is already open in the OS_DATA->open_blocks
	//			IF YES:
	//				Just add the block at the end of the list of this particular file
	//				Update its references
	//			IF NO:
	//				Open the block file
	//				Add the block file in the OS_DATA->open_blocks array
	//				Append the block file at the end of list of this particular file

	log_msg("\n    [open] file contains %d blocks", block_instructions.num_blocks);

	for(i = 0; i < block_instructions.num_blocks; i++){
		strcpy(tmp_block.block_name, block_instructions.blocks[i]);
		log_msg("\n    [open] block_instruction.blocks[i]: %s\ttmp.block.block_name: %s",block_instructions.blocks[i], tmp_block.block_name);

		// Search the open block list:
		//
		//	IF the current requested block exists:
		//		Get its file descriptor
		//		Update its references
		//		Append the block to the file list
		//	ELSE:
		//		Open the block file
		//		Add the block's fd and name to the open blocks list
		//		Append the block to the file list

		for(j = 0; j < OS_DATA->num_open_blocks; j++){
			if(strcmp(block_instructions.blocks[i], OS_DATA->open_blocks[j].block_name) == 0){
				found = 1;

				tmp_block.block_fd = OS_DATA->open_blocks[j].block_fd;
				OS_DATA->open_blocks[j].open_file_ref++;
				log_msg("\n    [open] block %s found in open blocks", OS_DATA->open_blocks[j].block_name);
				break;
			}
		}

		if (found){
			found = 0;
			append(&OS_DATA->file_descriptors[OS_DATA->fds_last_pos], tmp_block);

			printlist(OS_DATA->file_descriptors[OS_DATA->fds_last_pos]);
			logOpenBlocks();
		}
		else{
			memset(fpath, 0, PATH_MAX);
			os_fullpath(fpath, block_instructions.blocks[i]);

			log_msg("\n    [open] opening block file: %s\n", fpath);

			file_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);

			if(file_fd < 0){
				ret = log_error("[open]");
				// The head of the list has already been initialized
				// but an error occured at block fetching.
				OS_DATA->fds_last_pos++;
				return ret;
			}

			// Add blck entry at the open blocks list
			log_msg("\n    [open] adding block with block_name %s\n", block_instructions.blocks[i]);
			strcpy(OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_name, block_instructions.blocks[i]);
			OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_fd = file_fd;
			// We are opening the block file now, so it has only one file reference
			OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref = 1;
			OS_DATA->num_open_blocks++;

			// Append at the end of the file list
			tmp_block.block_fd = file_fd;
			append(&OS_DATA->file_descriptors[OS_DATA->fds_last_pos], tmp_block);

			printlist(OS_DATA->file_descriptors[OS_DATA->fds_last_pos]);
			logOpenBlocks();
		}

		memset(&tmp_block, 0, sizeof(block_t));
	}

	// Set the file offset (cursor) at the first block of the block sequence of the file
	OS_DATA->file_descriptors[OS_DATA->fds_last_pos]->cursor = OS_DATA->file_descriptors[OS_DATA->fds_last_pos]->next;

	// Increment the number of open files
	OS_DATA->fds_last_pos++;

	log_msg("\n    [open] new last fd pos = %d    returning %d\n", OS_DATA->fds_last_pos, ret);

	printlist(OS_DATA->file_descriptors[OS_DATA->fds_last_pos - 1]);
	logOpenBlocks();

	return ret;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.  An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
// I don't fully understand the documentation above -- it doesn't
// match the documentation for the read() system call which says it
// can return with anything up to the amount of data requested. nor
// with the fusexmp code which returns the amount of data also
// returned by read.
int os_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    int ret = 0, found = 0, size_in_blocks, i, new_cursor_pos;
	char tmp_buf[BLOCK_SIZE] = {'\0'};
	size_t data_read = 0;
	block_t *cur_file;

    log_msg("\nos_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n", path, buf, size, offset, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

	// Search the open fds table to see if the fd on which the read is
	// requested on is a valid one.
	for(i = 0; i < OS_DATA->fds_last_pos; i++){
		if(OS_DATA->file_descriptors[i]->block_fd == fi->fh){
			found = 1;
			cur_file = OS_DATA->file_descriptors[i];
			log_msg("\n    [read] found file with name: %s and fd: %d\n", cur_file->block_name, cur_file->block_fd);
			break;
		}
	}

	// No valid fd: Return errno EBADF
	if(!found){
		log_msg("    [ERROR] [read]: %s\n", strerror(EBADF));
		return -EBADF;
	}
	found = 0;

	log_msg("\n    [read] file is opened with flags: %d\n", cur_file->flags);

	// Check if you have opened the file with read permisions
	// If not: Return errno EBADF
	if((cur_file->flags & (O_RDONLY | O_RDWR)) != 0){
		log_msg("\n    [ERROR] [read]: %s\n", strerror(EBADF));
		return -EBADF;
	}


	// Calculate the offset in blocks and move the cursor accordingly
	new_cursor_pos = (int) ceil((double) offset / BLOCK_SIZE);
	cur_file->cursor = cur_file->next;

	for(i = 0; i < new_cursor_pos; i++){
		if(cur_file->cursor == NULL){
			break;
		}

		cur_file->cursor = cur_file->cursor->next;
	}

	log_msg("\n    [read] requested size = %lu", size);
	// If the size parameter is 0 or the file offset (cursor) is
	// at the end or past the end of the file, return 0 (according to manual)
	if(size == 0 || cur_file->cursor == NULL){
		log_msg("\n    [read] requested size = %lu or offset is at or past end of file\n    [read] returning %d\n", size, ret);
		return ret;
	}

	// Determine how many blocks are requested to be read.
	// The function ceil is used for BLOCK_SIZE compatibility
	// issues between 4096 or 4000 bytes
	size_in_blocks = (int) ceil((double) size / BLOCK_SIZE);
	log_msg("\n    [read] size in blocks: %d\n", size_in_blocks);

	for(i = 0; i < size_in_blocks; i++){

		// Attempt to read BLOCK_SIZE bytes from the block file pointed to by the file cursor
		log_msg("\n    [read] cursor at block %p\tcursor_fd: %d", cur_file->cursor, cur_file->cursor->block_fd);
		do{
			ret = log_syscall("[pread]", pread(cur_file->cursor->block_fd, tmp_buf, BLOCK_SIZE, 2 * sizeof(int)), 0);

			if(ret < 0){
				// ret will contain the minus errno value
				return ret;
			}

		}while (ret != BLOCK_SIZE);

		// Keep account of how many bytes have been read from the file
		data_read += ret;

		// Copy the data read to the *buf provided as an argument
		memcpy(buf, tmp_buf, BLOCK_SIZE);
		buf += BLOCK_SIZE;

		// Advance the file cursor to point to the next block in the sequence
		cur_file->cursor = cur_file->cursor->next;

		// Reached end of file, return the number of data you have read.
		// This number might be less than the data requested.
		if(cur_file->cursor == NULL){
			break;
		}
	}

	log_msg("\n    [read] total data read: %lu\n", data_read);

    return data_read;
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
// As  with read(), the documentation above is inconsistent with the
// documentation for the write() system call.
int os_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
    int ret = 0, found = 0, block_fd = 0, size_in_blocks = 0, refs = 0, new_cursor_pos = 0, i, j;
	size_t data_written = 0;
	off_t data_appended = 0;
	char tmp_buf[BLOCK_SIZE] = {'\0'}, block_name[NAME_MAX] = ".~", fpath[PATH_MAX] = {'\0'};
	const char *buf_ptr = NULL;
	unsigned char block_hash[SHA_DIGEST_LENGTH + 1] = {'\0'};
	block_t *cur_file = NULL, new_block = {}, old_block = {};
	block_links_t block_sq = {0};
	DIR* rootdir = NULL;
	struct dirent *dir_entry = NULL;

    log_msg("\nos_write(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n", path, buf, size, offset, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

	// Search the open fds table to see if the fd on which the write is
	// requested on is a valid one.
	for (i = 0; i < OS_DATA->fds_last_pos; i++){
		if (OS_DATA->file_descriptors[i]->block_fd == fi->fh){
			found = 1;
			cur_file = OS_DATA->file_descriptors[i];
			log_msg("\n    [read] found file with name: %s and fd: %d\n", cur_file->block_name, cur_file->block_fd);
			break;
		}
	}

	// No valid fd: Return errno EBADF
	if (!found){
		log_msg("    [ERROR] [read]: %s\n", strerror(EBADF));
		return -EBADF;
	}
	found = 0;

	// Get the block squence that makes up the file
	do{
		ret = log_syscall("\n    [read]", pread(cur_file->block_fd, &block_sq, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

		if(ret < 0)
			return ret;
	}while(ret < sizeof(block_links_t));

	size_in_blocks = (int) ceil((double) size / BLOCK_SIZE);
	log_msg("\n    [write] request in blocks: %d\n", size_in_blocks);
	buf_ptr = buf;

	// We will search rootdir to fild wheather the hash generated for
	// this block is the same as an existing block.
	rootdir = opendir(OS_DATA->rootdir);
	dir_entry = readdir(rootdir);

	if (dir_entry == 0){
		ret = log_error("\n    [readdir]");
		return ret;
	}

	for(i = 0; i < size_in_blocks; i++){
		found = 0;

		// Copy BLOCK_SIZE data to the tmp_buf
		memcpy(tmp_buf, buf_ptr, BLOCK_SIZE);
		buf_ptr += BLOCK_SIZE;
		data_written += BLOCK_SIZE;

		SHA1((unsigned char *) tmp_buf, BLOCK_SIZE, block_hash);
		// block_name: .~HASH
		convertSHA1ToString(block_hash, &block_name[2]);

		do{
			if(strcmp(dir_entry->d_name, block_name) == 0){
				log_msg("\n    [write] hash searched %s\tfound hash %s\n", block_name, dir_entry->d_name);
				found = 1;
				break;
			}

		}while((dir_entry = readdir(rootdir)) != NULL);

		ret = log_syscall("\n    [closedir]", closedir(rootdir), 0);

		if(ret < 0)
			return ret;

		// If the hash does NOT exitst:
		// Create the block
		// Set its file references to 1 (only this file is depended on this block)
		// Add the new block at the open block list
		if(!found){
			int block_size = BLOCK_SIZE;

			log_msg("\n    [write] creating new block with hash: %s\n\t", block_name);

			os_fullpath(fpath, block_name);

			block_fd = log_syscall("\n    [open]", open(fpath, O_CREAT | O_EXCL | O_RDWR, S_IRWXU), 0);

			if(block_fd < 0){
				return block_fd;
			}

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, &block_size, sizeof(int), 0), 0);

				if(ret < 0)
					return 0;
			}while(ret < sizeof(int));

			refs = 1;

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if (ret < 0)
					return 0;
			} while (ret < sizeof(int));

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, tmp_buf, BLOCK_SIZE, 2 * sizeof(int)), 0);

				if (ret < 0)
					return 0;
			} while (ret < BLOCK_SIZE);

			log_msg("\n    [write] data_written: %ld", data_written);

			// Add the block file in the open blocks list
			log_msg("\n    [write] OS_DATA->num_open_blocks: %d", OS_DATA->num_open_blocks);
			strcpy(OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_name, block_name);
			OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_fd = block_fd;

			log_msg("\n    [write] old block_refs: %d\n", OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref);
			OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref = 1;
			log_msg("\n    [write] new block_refs: %d\n", OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref);

			OS_DATA->num_open_blocks++;
			log_msg("\n    [write] OS_DATA->num_open_blocks: %d", OS_DATA->num_open_blocks);

		}else{
			// If the has DOES exist:
			// Check if the block is already open:
			//	IF YES:
			//		Get its file descriptor
			//		Update its references (open blocks array)
			//		Update its references (inside the block file)
			//	IF NO:
			//		Open the block file
			//		Get its file descriptor
			//		Update its references (inside the block file)
			//		Add it to the open blocks array (refs = 1)


			found = 0;

			// Search open block list to see if this block is open
			for(j = 0; j < OS_DATA->num_open_blocks; j++){
				if(strcmp(block_name, OS_DATA->open_blocks[j].block_name) == 0){
					found = 1;
					block_fd = OS_DATA->open_blocks[j].block_fd;
					log_msg("\n    [write] found in open blocks block with fd: %d\n", block_fd);
					OS_DATA->open_blocks[j].open_file_ref++;
					break;
				}
			}

			if(!found){
				os_fullpath(fpath, block_name);

				block_fd = log_syscall("\n    [open]", open(fpath, O_RDWR), 0);
				log_msg("\n    [write] opening block: %s with fd:%d\n", block_name, block_fd);

				if(block_fd < 0){
					return block_fd;
				}

				// Add the block file in the open blocks list
				log_msg("\n    [write] OS_DATA->num_open_blocks: %d", OS_DATA->num_open_blocks);
				strcpy(OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_name, block_name);
				OS_DATA->open_blocks[OS_DATA->num_open_blocks].block_fd = block_fd;

				log_msg("\n    [write] old block_refs: %d", OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref);
				OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref = 1;
				log_msg("\n    [write] new block_refs: %d", OS_DATA->open_blocks[OS_DATA->num_open_blocks].open_file_ref);

				OS_DATA->num_open_blocks++;
				log_msg("\n    [write] OS_DATA->num_open_blocks: %d", OS_DATA->num_open_blocks);
			}



			do{
				ret = log_syscall("\n    [read]", pread(block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if(ret < 0)
					return ret;
			}while(ret < sizeof(int));

			log_msg("\n    [open] block: %s old refs: %d", block_name, refs);
			refs++;
			log_msg("\n    [open] block: %s new refs: %d", block_name, refs);

			do{
				ret = log_syscall("\n    [write]", pwrite(block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if (ret < 0)
					return ret;
			} while (ret < sizeof(int));
		}

		strcpy(new_block.block_name, block_name);
		new_block.block_fd = block_fd;
		new_block.cursor = NULL;
		new_block.flags = 0;
		log_msg("\n    [write] append block file in file list\n");

		// Calculate the offset in blocks and move the cursor accordingly
		new_cursor_pos = (int)ceil((double)offset / BLOCK_SIZE);

		cur_file->cursor = cur_file->next;

		for (i = 0; i < new_cursor_pos; i++){
			if (cur_file->cursor == NULL){
				break;
			}

			cur_file->cursor = cur_file->cursor->next;
		}

		if(cur_file->cursor == NULL){
			log_msg("\n    [write] appending block: %s at the end of file %s\n", block_name, cur_file->block_name);

			append(&cur_file, new_block);
			data_appended += BLOCK_SIZE;

			strcpy(block_sq.blocks[block_sq.num_blocks], block_name);
			block_sq.num_blocks++;

			cur_file->cursor = NULL;

		}else{
			found = 0;

			memcpy(&old_block, cur_file->cursor, sizeof(block_t));

			// Search open block list to for OLD block and update its references:
			for (j = 0; j < OS_DATA->num_open_blocks; j++){
				if (strcmp(old_block.block_name, OS_DATA->open_blocks[j].block_name) == 0){
					found = 1;

					log_msg("\n    [write] about to override block: %s with old refs: %d\n", old_block.block_name, OS_DATA->open_blocks[j].open_file_ref );

					OS_DATA->open_blocks[j].open_file_ref--;

					if (OS_DATA->open_blocks[j].open_file_ref == 0){

						log_msg("\n    [write] about to override block: %s with new refs: %d\n", old_block.block_name, OS_DATA->open_blocks[j].open_file_ref);

						// Move the last entry of the open blocks list at the newlly emptied position
						memcpy(&OS_DATA->open_blocks[j], &OS_DATA->open_blocks[--(OS_DATA->num_open_blocks)], sizeof(open_block_t));
					}

					break;
				}
			}

			do{
				ret = log_syscall("\n    [read]", pread(old_block.block_fd, &refs, sizeof(int), sizeof(int)), 0);

				if(ret < 0)
					return ret;
			}while(ret < sizeof(int));

			refs--;

			if(refs == 0){
				ret = log_syscall("\n    [close]", close(old_block.block_fd), 0);

				if(ret < 0)
					return ret;

				memset(fpath, 0, PATH_MAX);
				os_fullpath(fpath, old_block.block_name);

				ret = log_syscall("\n    [unlink]", unlink(fpath), 0);

				if(ret < 0)
					return ret;
			}else{
				do{
					ret = log_syscall("\n    [write]", pwrite(old_block.block_fd, &refs, sizeof(int), sizeof(int)), 0);

					if (ret < 0)
						return ret;
				} while (ret < sizeof(int));
			}

			if(found && (refs != 0)){
				ret = log_syscall("\n    [close]", close(old_block.block_fd), 0);

				if(ret < 0)
					return ret;
			}

			insertAfter(cur_file->cursor->prev, new_block);
			cur_file->cursor = cur_file->cursor->next;
			deleteNode(&cur_file, cur_file->cursor->prev);

			for(j = 0; j < block_sq.num_blocks; j++){
				if(strcmp(old_block.block_name, block_sq.blocks[j]) == 0){
					strcpy(block_sq.blocks[j], new_block.block_name);
				}
			}
		}

		memset(tmp_buf, 0, BLOCK_SIZE);
		memset(fpath, 0, PATH_MAX);
		memset(&old_block, 0, sizeof(block_t));
		memset(&new_block, 0, sizeof(block_t));
		strcpy(block_name, ".~");
	}

	log_msg("\n    [write] adding to file size, data_appended: %d", data_appended);
	os_update_meta(cur_file->block_fd, NULL, NULL, &data_appended, NULL, NULL);

	do{
		ret = log_syscall("\n    [write]", pwrite(cur_file->block_fd, &block_sq, sizeof(block_links_t), sizeof(MAGIC_NUMBER) + sizeof(meta_t)), 0);

		if (ret < 0)
			return ret;
	} while (ret < sizeof(block_links_t));

	log_msg("\n    [write] returning data_written: %d\n", data_written);

	return data_written;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().  This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.  It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
// this is a no-op in CORN-e-LIUS.  It just logs the call and returns success
int os_flush(const char *path, struct fuse_file_info *fi){
    log_msg("\nos_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
    // no need to get fpath on this one, since I work from fi->fh not the path
    log_fi(fi);

    return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int os_release(const char *path, struct fuse_file_info *fi){
	int ret = 0, unlink = 0, found = 0, cur_pos = 0, i;
	char file_name[NAME_MAX] = {'\0'};
	block_t *cur_file = NULL, *pos = NULL;

    log_msg("\nos_release(path=\"%s\", fi=0x%08x)\n", path, fi);
    log_fi(fi);

	// Search if the file to be closed is open
	for(i = 0; i < OS_DATA->fds_last_pos; i++){
		if(OS_DATA->file_descriptors[i]->block_fd == fi->fh){
			cur_file = OS_DATA->file_descriptors[i];
			cur_pos = i;
			found = 1;
			break;
		}
	}

	if(!found){
		log_error("[ERROR] file is not open\n");
		return -EBADF;
	}

	strcpy(file_name, cur_file->block_name);
	unlink = cur_file->unlink;
	log_msg("\n    [release] closing file: %s\n    [release] unlink flag: %d", file_name, unlink);

	for(pos = cur_file->next; pos != NULL; pos = cur_file->next){

		// Search the open block list to see if the block file is already open:
		for(i = 0; i < OS_DATA->num_open_blocks; i ++){
			if(strcmp(pos->block_name, OS_DATA->open_blocks[i].block_name) == 0){

				log_msg("\n    [release] found open block: %s with old refs: %d\n", pos->block_name, OS_DATA->open_blocks[i].open_file_ref);

				OS_DATA->open_blocks[i].open_file_ref--;

				log_msg("\n    [release] found open block: %s with new refs: %d\n", pos->block_name, OS_DATA->open_blocks[i].open_file_ref);

				// No more file refs to the block close it:
				if(OS_DATA->open_blocks[i].open_file_ref == 0){

					ret = log_syscall("\n    [close]", close(OS_DATA->open_blocks[i].block_fd), 0);

					if (ret < 0){
						return ret;
					}

					memcpy(&OS_DATA->open_blocks[i], &OS_DATA->open_blocks[OS_DATA->num_open_blocks - 1], sizeof(open_block_t));

					OS_DATA->num_open_blocks--;
				}
			}
		}

		deleteNode(&cur_file, pos);
	}

	ret = log_syscall("\n    [close]", close(cur_file->block_fd), 0);

	if (ret < 0){
		return ret;
	}

	deleteNode(&cur_file, cur_file);

	OS_DATA->file_descriptors[cur_pos] = OS_DATA->file_descriptors[OS_DATA->fds_last_pos - 1];
	OS_DATA->fds_last_pos--;

	OS_DATA->file_descriptors[OS_DATA->fds_last_pos] = NULL;

	if(unlink){
		log_msg("\n    [release] about to call unlink for file: %s\n", file_name);
		os_unlink(file_name);
	}

	return ret;
}

/** Open directory
	 *
	 * Unless the 'default_permissions' mount option is given,
	 * this method should check if opendir is permitted for this
	 * directory. Optionally opendir may also return an arbitrary
	 * filehandle in the fuse_file_info structure, which will be
	 * passed to readdir, closedir and fsyncdir.
	 *
	 * Introduced in version 2.3
	 */
int os_opendir(const char *path, struct fuse_file_info *fi){
    DIR *dp;
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nos_opendir(path=\"%s\", fi=0x%08x)\n", path, fi);
    os_fullpath(fpath, path);

    // since opendir returns a pointer, takes some custom handling of
    // return status.
    dp = opendir(fpath);
    log_msg("    opendir returned 0x%p\n", dp);

    if (dp == NULL)
		retstat = log_error("os_opendir opendir");

    fi->fh = (intptr_t) dp;

    log_fi(fi);

    return retstat;
}
// Releasedir:
int os_releasedir(const char *path, struct fuse_file_info *fi){
	int retstat = 0;

	log_msg("\nbb_releasedir(path=\"%s\", fi=0x%08x)\n",
			path, fi);
	log_fi(fi);

	closedir((DIR *)(uintptr_t)fi->fh);

	return retstat;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */

int os_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
	       struct fuse_file_info *fi){

	struct dirent *dir_entry;
	struct stat file_stat;
	DIR *dir;
	int ret = 0;

		log_msg("\nos_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
				path, buf, filler, offset, fi);


	dir = (DIR*) (uintptr_t) fi->fh;

	dir_entry = readdir(dir);
	log_msg("\n[readdir] returned 0x%p\n", dir_entry);

	if(dir_entry == 0){
		ret = log_error("os_readdir readdir");
		return ret;
	}


	do{
		if (strncmp(".~", dir_entry->d_name, 2) == 0)
			continue;

		if (os_getattr(dir_entry->d_name, &file_stat))
			continue;

		log_msg("\tCalling filler with name: %s\n", dir_entry->d_name);

		if (filler(buf, dir_entry->d_name, NULL, 0) != 0){
			log_msg("\n\t[ERROR] os_readdir filler: buffer full\n");
			return -ENOMEM;
		}
	} while ((dir_entry = readdir(dir)) != NULL);

	log_fi(fi);

	return ret;
}


/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to
// fuse_main().  Really seems like either it should be a third
// parameter coming in here, or else the fact should be documented
// (and this might as well return void, as it did in older versions of
// FUSE).
void *os_init(struct fuse_conn_info *conn){
    log_msg("\nos_init()\n");

	log_conn(conn);
	log_fuse_context(fuse_get_context());

	memset(OS_DATA->file_descriptors, 0, OPEN_FDS_MAX * sizeof(block_t));
	memset(OS_DATA->open_blocks, 0, OPEN_BLOCKS_MAX * sizeof(open_block_t));

	OS_DATA->fds_last_pos = 0;
	OS_DATA->num_open_blocks = 0;

	return OS_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void os_destroy(void *userdata){
    int i;
	block_t *cur;

	log_msg("\nos_destroy(userdata=0x%08x)\n", userdata);

	for(i = 0; i < OS_DATA->fds_last_pos; i++){
		for(cur = OS_DATA->file_descriptors[i]->next; cur != NULL; cur = cur->next){
			deleteNode(&OS_DATA->file_descriptors[i], cur);
		}

		deleteNode(&OS_DATA->file_descriptors[i], OS_DATA->file_descriptors[i]);
	}
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int os_access(const char *path, int mask){
    int retstat = 0;
    char fpath[PATH_MAX];

    log_msg("\nos_access(path=\"%s\", mask=0%o)\n",
	    path, mask);
    os_fullpath(fpath, path);

    retstat = access(fpath, mask);

    if (retstat < 0)
	retstat = log_error("os_access access");

    return retstat;
}

struct fuse_operations os_oper = {
  .getattr = os_getattr, // DONE CHECKED
  .getdir = NULL,
  .mknod = os_mknod, // DONE CHECKED
  .unlink = os_unlink, //DONE CHECKED
  .truncate = os_truncate, //DONE
  .utime = os_utime, //DONE CHECKED
  .open = os_open, // DONE CHECKED
  .read = os_read, // DONE CHECKED
  .write = os_write, //DONE CHECKED
  .flush = os_flush, // Leave it as it is
  .release = os_release, // DONE CHECKED
  .opendir = os_opendir, // DONE CHECKED
  .releasedir = os_releasedir, //DONE
  .readdir = os_readdir, // DONE CHECKED
  .init = os_init, // DONE CHECKED
  .destroy = os_destroy, //DONE
  .access = os_access, //DONE
};

void os_usage(){
    fprintf(stderr, "usage:  cornelius [FUSE and mount options] rootDir mountPoint\n");
    abort();
}

int main(int argc, char *argv[])
{
    int fuse_stat;
    struct os_state *os_data;

    // CORN-e-LIUS doesn't do any access checking on its own (the comment
    // blocks in fuse.h mention some of the functions that need
    // accesses checked -- but note there are other functions, like
    // chown(), that also need checking!).  Since running CORN-e-LIUS as root
    // will therefore open Metrodome-sized holes in the system
    // security, we'll check if root is trying to mount the filesystem
    // and refuse if it is.  The somewhat smaller hole of an ordinary
    // user doing it with the allow_other flag is still there because
    // I don't want to parse the options string.
    if ((getuid() == 0) || (geteuid() == 0)) {
    	fprintf(stderr, "Running CORN-e-LIUS as root opens unnacceptable security holes\n");
    	return 1;
    }

    // See which version of fuse we're running
    fprintf(stderr, "Fuse library version %d.%d\n", FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);

    // Perform some sanity checking on the command line:  make sure
    // there are enough arguments, and that neither of the last two
    // start with a hyphen (this will break if you actually have a
    // rootpoint or mountpoint whose name starts with a hyphen, but so
    // will a zillion other programs)
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
		os_usage();

    os_data = malloc(sizeof(struct os_state));

    if (os_data == NULL) {
		perror("main calloc");
		abort();
    }

    // Pull the rootdir out of the argument list and save it in my
    // internal data
    os_data->rootdir = realpath(argv[argc-2], NULL);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;

    os_data->logfile = log_open();
	os_data->fds_last_pos = 0;

	//memset(OS_DATA->file_descriptors, 0, 100);

    // turn over control to fuse
    fprintf(stderr, "about to call fuse_main\n");
    fuse_stat = fuse_main(argc, argv, &os_oper, os_data);
    fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

    return fuse_stat;
}
