// Copyright 2021 Sen Han <00hnes@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _POSIX_C_SOURCE 200112L

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <syscall.h>
#include <sys/ptrace.h>

char * helperPath = "/root/.tiexec/bin/tiexec-helper";

#define FATAL(...) \
    do { \
        fprintf(stderr, "tiexec: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

int interceptFlag = 0;
long interceptIPAddr = 0;

pid_t traceePid;
int rdFd = -1;
int wrFd = -1;

void dumpSyscallEnter(){
    pid_t pid = traceePid;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        FATAL("%s", strerror(errno));
    long syscall = regs.orig_rax;

    fprintf(stderr, "dump syscall call %ld(%ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, pid:%d)-> \n",
            syscall,
            (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
            (long)regs.r10, (long)regs.r8,  (long)regs.r9,
            (long)regs.rsp, (long)regs.rip, pid);
}

// ret errno
uint64_t dumpSyscallRet(){
    pid_t pid = traceePid;

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        FATAL("get regs failed: %s", strerror(errno));
    }

    fprintf(stderr, "dump syscall ret = %ld %d\n", (long)regs.rax, (int)regs.rax);
    return (uint64_t)regs.rax;
}

void myWait(){
    pid_t pid = traceePid;
    int wstatus;
    if (waitpid(pid, &wstatus, 0) == -1)
            FATAL("%s", strerror(errno));
    if (WIFEXITED(wstatus)) {
        printf("exited, status=%d\n", WEXITSTATUS(wstatus));
        exit(1);
    } else if (WIFSIGNALED(wstatus)) {
        printf("killed by signal %d\n", WTERMSIG(wstatus));
        exit(1);
    } else {}
}

void readOneByteFromPipe(){
    char pipeBuf[1];
    int nbytes = read(rdFd, pipeBuf, 1);
    if(nbytes != 1){
        if(nbytes==0){
            FATAL("readOneByteFromPipe: end of file");
        }else{
            FATAL("readOneByteFromPipe:%s", strerror(errno));
        }
    }
}

void writeOneByteToPipe(){
    char pipeBuf[1];
    int nbytes = write(wrFd, pipeBuf, 1);
    if(nbytes != 1){
        FATAL("writeOneByteToPipe: %s", strerror(errno));
    }
}

int
main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    // A is parent, B is son, i.e., the helper
    // A<-B
    // 0  1
    int linkPipe[2];

    // A->B
    // 1  0
    int linkPipeReverse[2];

    if (pipe(linkPipe)==-1)
        FATAL("%s", strerror(errno));
    if (pipe(linkPipeReverse)==-1)
        FATAL("%s", strerror(errno));

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  // child
            if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
                FATAL("PTRACE_TRACEME failed: %s", strerror(errno));
            }
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }

    // parent
    traceePid = pid;
    myWait(pid); // sync with child's successful exec syscall
    // child now is blocked at here when he want to return from kernel during exec syscall
    dumpSyscallEnter();
    dumpSyscallRet();
    // layout: size addr
    uint64_t cmdHeaderArray[2] = {0,0};
    volatile uint64_t * cmdHeader = cmdHeaderArray;

    struct user_regs_struct traceeRegsBackup;
    // start our helper
    {
        size_t maxSz = 4096;
        // tracee pid str
        char sonPidStrBuf[4096];
        char myPidStrBuf[4096];
        char sonInitialIPStrBuf[4096];
        char cmdHeaderAddrStrBuf[4096];
        if(snprintf(sonPidStrBuf , maxSz,"%d", pid) >= maxSz){ 
            FATAL("snprintf overflow"); 
        }
        if(snprintf(myPidStrBuf ,  maxSz,"%d", getpid()) >= maxSz){ 
            FATAL("snprintf overflow"); 
        }
        if(snprintf(cmdHeaderAddrStrBuf , maxSz, "%" PRIu64, (uint64_t)cmdHeader) >= maxSz){ 
            FATAL("snprintf overflow"); 
        }
        {
            if (ptrace(PTRACE_GETREGS, pid, 0, &traceeRegsBackup) == -1)
                FATAL("%s", strerror(errno));
            if(snprintf(sonInitialIPStrBuf , maxSz, "%" PRIu64, (uint64_t)traceeRegsBackup.rip) >= maxSz){
                FATAL("snprintf overflow");
            }
        }
        pid_t pidOfHelper = fork();
        switch (pidOfHelper) {
            case -1: /* error */
                FATAL("%s", strerror(errno));
            case 0:  /* child */
                // setup pipe
                pidOfHelper = getpid();
                dup2 (linkPipe[1], STDOUT_FILENO);
                close(linkPipe[0]);
                close(linkPipe[1]);
                dup2 (linkPipeReverse[0], STDIN_FILENO);
                close(linkPipeReverse[0]);
                close(linkPipeReverse[1]);
                execl(helperPath, "helper", 
                    myPidStrBuf, cmdHeaderAddrStrBuf, sonPidStrBuf, sonInitialIPStrBuf, (char *)0);
                FATAL("%s", strerror(errno));
        }
    }
    close(linkPipe[1]);
    close(linkPipeReverse[0]);
    rdFd = linkPipe[0];
    wrFd = linkPipeReverse[1];
    {
        readOneByteFromPipe();
        
        fprintf(stderr,"rcv sz:%"PRIu64"\n", cmdHeader[0]);
        if(cmdHeader[0] % 40 != 0){
            FATAL("unexpected size rcved %"PRIu64, cmdHeader[0]);
        }
        void* addr = NULL;
        if(cmdHeader[0] != 0){
            addr = malloc(cmdHeader[0]);
            if(addr==NULL){
                FATAL("malloc failed %s", strerror(errno));
            }
        }
        cmdHeader[1] = (uint64_t)addr;
        writeOneByteToPipe();
        readOneByteFromPipe();
    }
    uint64_t cmdBodySzLeft = cmdHeader[0];
    volatile uint64_t * cmdBodyPtr = (void*)(cmdHeader[1]);
    for (;;) {
        if(cmdBodySzLeft == 0){
            break;
        }
        if(cmdBodySzLeft < 40){
            FATAL("loop, unexpected size rcved %"PRIu64, cmdBodySzLeft);
        }
        // enter next syscall
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        myWait(pid);
        printf("before mangle\n");
        dumpSyscallEnter(pid);
        // mangle
        uint64_t syscallNo, arg0, arg1, arg2, arg3;
        syscallNo = cmdBodyPtr[0];
        arg0 = cmdBodyPtr[1];
        arg1 = cmdBodyPtr[2];
        arg2 = cmdBodyPtr[3];
        arg3 = cmdBodyPtr[4];
        cmdBodySzLeft=cmdBodySzLeft-40;
        cmdBodyPtr=&cmdBodyPtr[5];
        {
            struct user_regs_struct mgleRegs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &mgleRegs) == -1)
                FATAL("%s", strerror(errno));
            mgleRegs.orig_rax = syscallNo;
            mgleRegs.rdi = arg0; mgleRegs.rsi = arg1; mgleRegs.rdx = arg2;
            mgleRegs.r10 = arg3; mgleRegs.r8  =    0; mgleRegs.r9  =    0;
            if (ptrace(PTRACE_SETREGS, pid, 0, &mgleRegs) == -1)
                FATAL("mangle syscall %s", strerror(errno));
        }
        printf("after mangle\n");
        dumpSyscallEnter(pid);

        // run this syscall and suspend before return to userspace
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        myWait(pid);

        {
            uint64_t retRax = dumpSyscallRet(pid);
            int64_t i64Ret = (int64_t)retRax;
            if(i64Ret >= -4095 && i64Ret <= -1){
                FATAL("mangled syscall return failed:%s", strerror(i64Ret));
            }
            if(syscallNo == 9) {// mmap
                if(arg0 == retRax){
                    printf("mmap return an expected addr :-)\n");
                }else{
                    FATAL("mangled syscall return an unexpected addr");
                }
            }
        }
    }
    if(cmdBodySzLeft == 0){
        fprintf(stderr,"cmd finish consuming\n");
        {
            writeOneByteToPipe();
            readOneByteFromPipe();
        }
        fprintf(stderr,"resume tracee state\n");
        if (ptrace(PTRACE_SETREGS, pid, 0, &traceeRegsBackup) == -1)
            FATAL("%s", strerror(errno));
        fprintf(stderr,"end, so detaching\n");
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
                fputs(" = ?\n", stderr);
                FATAL("%s", strerror(errno));
            }
        fprintf(stderr,"done :-D\n");
        fprintf(stderr,"getchar and exit:\n");
        getchar();
    }else{
        FATAL("unexecpted end");
    }
    return 0;
}