#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	uint64_t msg = 0xaaaaaaaaaaaaaaaa;
  	fptr("%018p\n%018p\n%018p\n", *(&msg+1), *(&msg+2), *(&msg+3));
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}