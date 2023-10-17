#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdbool.h>
#include <sys/user.h>

#define BUF_SIZE 10

char buffer[BUF_SIZE+1];

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

char *int2bin(int a, char *buffer, int buf_size) {
    buffer += (buf_size - 1);

    for (int i = buf_size; i >= 0; i--) {
        *buffer-- = (a & 1) + '0';

        a >>= 1;
    }

    return buffer;
}

long char2long(char* a){
    long num = 0;
    for( int i = 0 ; i < 8 ; i++ )
        num = (num << 8) | a[i];
    return num;
}

void runUntilINT(int pid){
    int wait_status;
    if(ptrace(PTRACE_CONT, pid, 0, 0) != 0) errquit("ptrace@parent");
	if(waitpid(pid, &wait_status, 0) < 0) errquit("waitpid");
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
    memset(buffer, '0', sizeof(buffer)-1);

    
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
	    long long counter = 0LL;
	    int enter = 0x01; /* enter syscall (1) or exit from syscall (0) */
	    int wait_status;
        int intCount = 0;
	    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD); /* ptrace sig has 0x80 bit marked */
	   
        // memset
        runUntilINT(child);
	    struct user_regs_struct regs;
        struct user_regs_struct original_regs;

        for(int i = 0; i < 3; i++){ //3 step to wait for the instruction that filled in magic[] pos
            if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) != 0) errquit("ptrace@parent");
            waitpid(child, &wait_status, 0);    
        }
        if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace@parent");
        //long magic = ptrace(PTRACE_PEEKTEXT, child, regs.rax);
        long magicAddress = regs.rax;

        // before connect
        runUntilINT(child);
        
        // before reset
		runUntilINT(child);
        if(ptrace(PTRACE_GETREGS, child, 0, &original_regs) != 0) errquit("ptrace@parent");
        //long long currentAddress = original_regs.rip;
        //long long beforeEndAddress = currentAddress + 0x5e2a;
        //unsigned char jumpBackCode[] = { 0xFF, 0x25, 0xFB, 0xA1, 0xFF, 0xFF, 0x90, 0x90 };
        //unsigned long* jumpBacklCode = (unsigned long*)jumpBackCode;
        //if(ptrace(PTRACE_POKETEXT, child, beforeEndAddress, *jumpBackCode) != 0) errquit("ptrace@parent POKETEXT");


        bool finish = false;
        for(int i = 0; i < (1 << BUF_SIZE) && !finish; i ++){   
            //printf("loop %d\n",i);   
            int2bin(i,buffer,BUF_SIZE);
            if(ptrace(PTRACE_SETREGS, child, 0, &original_regs) != 0) errquit("ptrace@parent PTRACE_SETREGS");

            // before reset
            runUntilINT(child);

            long magic = char2long(buffer);
            if(ptrace(PTRACE_POKETEXT, child, magicAddress, magic) != 0) errquit("ptrace@parent PTRACE_POKETEXT");
            magic = ptrace(PTRACE_PEEKTEXT, child, magicAddress+8);
            magic = char2long(buffer+8) >> 48 | (magic & 0xffffffffff000000);
            if(ptrace(PTRACE_POKETEXT, child, magicAddress+8, magic) != 0) errquit("ptrace@parent POKETEXT");

            // before print result
            runUntilINT(child);

            if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace@parent PTRACE_GETREGS");
            long success = regs.rax;

            if (success == 0)
                break;

            // after print result
            //runUntilINT(child);

            //runUntilINT(child);
        }
    }
	return 0;
}

