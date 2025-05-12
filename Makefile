BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I.

all: xdp_kern.o

xdp_kern.o: xdp_kern.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f *.o
