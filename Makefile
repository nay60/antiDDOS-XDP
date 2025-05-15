BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

BPF_SRC = xdp_kern.c
BPF_OBJ = xdp_kern.o

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)


