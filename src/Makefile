CC = gcc
CFLAGS = -lpthread -Wall -Os -fPIC
OBJS = md5.o log.o argparse.o radius.o

all: radiusbypass

md5.o: md5.c
	$(CC) $(CFLAGS) -c -o $@ $<

log.o: log.c
	$(CC) $(CFLAGS) -c -o $@ $<

argparse.o: argparse.c
	$(CC) $(CFLAGS) -c -o $@ $<

radius.o: radius.c
	$(CC) $(CFLAGS) -c -o $@ $<

radiusbypass: $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS)

clean:
	rm -f radiusbypass *.o
