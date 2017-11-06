CC=gcc
CFLAGS=-I. -g
binaries=test-stitcher

build: test-stitcher

%.o: %.c
		$(CC) -c -o $@ $< $(CFLAGS)

test-stitcher: test-stitcher.o
	gcc -o test-stitcher test-stitcher.o -I.

clean:
	rm -f $(binaries) *.o
