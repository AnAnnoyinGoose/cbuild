CC=cc
FILES=src/main.c

all: main

main: $(FILES)
	$(CC) $(FILES) -lssl -lcrypto -o bin/main

clean:
	rm -f bin/main



.PHONY: all clean
