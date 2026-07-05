CLANG ?= clang
CC ?= gcc

.PHONY: all clean

all: execwatch_kern.o loader

execwatch_kern.o: execwatch_kern.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include -I/usr/include/x86_64-linux-gnu \
		-c $< -o $@

loader: loader.c
	$(CC) -O2 -Wall -o $@ $< -lbpf

clean:
	rm -f execwatch_kern.o loader
