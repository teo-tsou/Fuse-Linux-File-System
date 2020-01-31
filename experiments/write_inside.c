#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define BLOCK_SIZE 4096

int main(int argc, char const *argv[]){
	int i, fd, ret;

	char a[BLOCK_SIZE + 1] = {'\0'}, b[BLOCK_SIZE + 1] = {'\0'}, c[BLOCK_SIZE + 1] = {'\0'}, d[BLOCK_SIZE + 1] = {'\0'}, e[BLOCK_SIZE + 1] = {'\0'}, f[BLOCK_SIZE + 1] = {'\0'}, g[BLOCK_SIZE + 1] = {'\0'}, h[BLOCK_SIZE + 1] = {'\0'}, ii[BLOCK_SIZE + 1] = {'\0'}, j[BLOCK_SIZE + 1] = {'\0'};

	for(i = 0; i < BLOCK_SIZE; i++){
		a[i] = 'A';
		b[i] = 'B';
		c[i] = 'C';
		d[i] = 'D';
		e[i] = 'E';
		f[i] = 'F';
		g[i] = 'G';
		h[i] = 'H';
		ii[i] = 'I';
		j[i] = 'J';
	}

	fd = open("mountdir/write_inside.txt", O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);

	if(fd < 0){
		fprintf(stderr, "[ERROR] in opening file\n%s\n", strerror(errno));
		return -1;
	}

	lseek(fd, 0, SEEK_SET);

	do{
		ret = write(fd, a, BLOCK_SIZE * sizeof(char));
	}while(ret < BLOCK_SIZE);

	do{
		ret = write(fd, b, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, c, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, d, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, e, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, f, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, g, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	lseek(fd, 3 * BLOCK_SIZE, SEEK_SET);

	do{
		ret = write(fd, h, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, ii, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	do{
		ret = write(fd, j, BLOCK_SIZE * sizeof(char));
	} while (ret < BLOCK_SIZE);

	close(fd);

	return 0;
}
