all:
	gcc -g -Wall cornelius.c log.c list.c -lm \
		`pkg-config fuse --cflags --libs` \
		`pkg-config libcrypto --cflags --libs` \
		`pkg-config libssl --cflags --libs` -o cornelius


clean:
	rm -rf ./cornelius
