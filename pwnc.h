#ifndef __PWNC__H
# define __PWNC__H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <elf.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>

#define INPUT_LIMIT 0x10000
#define RECV_LIMIT 0x10000
#define REMOTE 1
#define LOCAL 0

extern int fd[2][2]; // 프로세스 통신을 위한 fd[0] : 입력, fd[1] : 출력

typedef struct Section{
    Elf64_Half SectionCnt;
    Elf64_Half SectionStringIndex;
    char * SectionName;
    Elf64_Shdr * SectionHeader;
}Section;

typedef struct got{
    char * name;
    unsigned long long addr;
} GOT;

typedef struct sym{
    char * name;
    unsigned long long value;
}SYM;

typedef struct elfinfo{
    int fd;
    char * filename;
    Section section;
    GOT * got;
    SYM * sym;
}ELFInfo;

extern unsigned long long * p64(unsigned long long value);

extern unsigned int * p32(unsigned int value);

extern void remote(char * ip, int port);

extern int process(char * path);

extern int Recvuntil(char * str, int print);

extern char * Recv(int cnt, int print);

extern int Send(char * str);

extern int Send32(char * str);

extern int Send64(char * str);

extern int Sendline(char * str);

extern void interactive(void);


extern Section findSectionHeader(int fd);

extern Elf64_Shdr * getSectionInfo(Section section, char * name);

extern GOT * findGOTInfo(int fd, Section section);

extern unsigned long long getGOT(GOT * got, char * target);

extern SYM * findSYM(int fd, Section section);

extern unsigned long long getSYM(SYM * sym, char * target);

extern ELFInfo ELF(char * path);

extern ELFInfo getLibcELF(ELFInfo elf);

extern void hexdump(void * target, int size);

#endif
