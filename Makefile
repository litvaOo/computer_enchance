build-c:
	clang -O3 -o sim8086 c/sim8086.c 
build-c-debug:
	clang -O2 -g -o sim8086 c/sim8086.c 
