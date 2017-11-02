CC = gcc

CFLAGS = -g -Wall -Werror -lpthread 
all: mproxy

mproxy: mproxy.o
	$(CC) $(CFLAGS) mproxy.o -o mproxy

mproxy.o:
	$(CC) $(CFLAGS) -c mproxy.c

clean:
	rm -rf *.o
	rm mproxy
