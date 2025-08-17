CC=cc
FILES=src/main.c

all: main

main: $(FILES)
	$(CC) $(FILES) -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -std=c99 -lssl -lcrypto -o bin/main

clean:
	rm -f bin/main



.PHONY: all clean
