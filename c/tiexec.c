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

#define _POSIX_C_SOURCE 200809L
#define _SVID_SOURCE

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
#include <fcntl.h>
#include <syscall.h>
#include <sys/ptrace.h>

#include "log.h"
char * glHelperPath = "/root/.tiexec/bin/tiexec-helper";
char * glLogDir = "/root/.tiexec/log/";
char * glNullStr = "(NULL)";
char * glLogFileName = NULL;
char * glHelperLogFileName = NULL;

char* ifNullConvertPointerToPrintableStr(char*p){
    if(NULL == p){
        return glNullStr;
    }else{
        return p;
    }
}

void printLogFilePathToStderr(){
    if(NULL == glLogFileName && NULL == glHelperLogFileName){
        fprintf(stderr,"tiexec: log file path not available\n");
    }else{
        fprintf(stderr,"tiexec: tracerLogFileName:%s, heplerLogFileName:%s\n", 
            ifNullConvertPointerToPrintableStr(glLogFileName), 
            ifNullConvertPointerToPrintableStr(glHelperLogFileName));
    }
}

#define FATAL(...) \
    do { \
        printLogFilePathToStderr(); \
        fprintf(stderr, "tiexec: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

#define my_log_fatal(...) \
    do { \
        printLogFilePathToStderr(); \
        log_fatal(__VA_ARGS__); \
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
        my_log_fatal("%s", strerror(errno));
    long syscall = regs.orig_rax;

    log_info("dump syscall call %ld(%ld, %ld, %ld, %ld, %ld, %ld, %ld, %ld, pid:%d)-> \n",
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
        my_log_fatal("get regs failed: %s", strerror(errno));
    }

    log_info("dump syscall ret = %ld %d\n", (long)regs.rax, (int)regs.rax);
    return (uint64_t)regs.rax;
}

void myWaitHelper(int fatalFlag){
    pid_t pid = traceePid;
    int wstatus;
    if (waitpid(pid, &wstatus, 0) == -1){
        if(fatalFlag!=0){
            my_log_fatal("%s", strerror(errno));
        }else{
            log_info("%s", strerror(errno));
        }
    }
    if (WIFEXITED(wstatus)) {
        if(fatalFlag!=0){
            my_log_fatal("exited, status=%d\n", WEXITSTATUS(wstatus));
        }else{
            log_info("exited, status=%d\n", WEXITSTATUS(wstatus));
        }
    } else if (WIFSIGNALED(wstatus)) {
        if(fatalFlag!=0){
            my_log_fatal("killed by signal %d\n", WTERMSIG(wstatus));
        }else{
            log_info("killed by signal %d\n", WTERMSIG(wstatus));
        }
    } else {}
}

void myWait(){
    myWaitHelper(1);
}

void readOneByteFromPipe(){
    char pipeBuf[1];
    int nbytes = read(rdFd, pipeBuf, 1);
    if(nbytes != 1){
        if(nbytes==0){
            my_log_fatal("readOneByteFromPipe: end of file");
        }else{
            my_log_fatal("readOneByteFromPipe:%s", strerror(errno));
        }
    }
}

void writeOneByteToPipe(){
    char pipeBuf[1];
    int nbytes = write(wrFd, pipeBuf, 1);
    if(nbytes != 1){
        my_log_fatal("writeOneByteToPipe: %s", strerror(errno));
    }
}
/*

#define my_log_fatal(...) \
    do { \
        printLogFilePathToStderr(); \
        log_fatal(__VA_ARGS__); \
        exit(EXIT_FAILURE); \
    } while (0)

void assertNoMinus1Ret(int ret){
    if(ret == -1){
        my_log_fatal("assertNoMinus1Ret: %s", strerror(errno));
    }
}

void assertNoMinus1RetToStderr(int ret){
    if(ret == -1){
        FATAL("assertNoMinus1RetToStderr: %s", strerror(errno));
    }
}
*/

#define assertNoMinus1Ret(ret) \
    do { \
        if(ret == -1){\
            my_log_fatal("assertNoMinus1Ret: %s", strerror(errno));\
        }\
    } while (0)


#define assertNoMinus1RetToStderr(ret) \
    do { \
        if(ret == -1){\
            FATAL("assertNoMinus1RetToStderr: %s", strerror(errno));\
        }\
    } while (0)

int
main(int argc, char **argv)
{
    if (argc <= 1)
        FATAL("too few arguments: %d", argc);

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

    // setup logs
    char *logFileName = NULL;
    char *helperLogFileName = NULL;
    char *logDir = glLogDir;
    int helperLogFd = -1;
    {
        pid_t tracerPid = getpid();
        int maxSz = 4096;
        char* buf = malloc(maxSz);
        if(buf==NULL){
            FATAL("malloc failed");
        }
        char* logNameSuffix = ".log";
        if(snprintf(buf , maxSz,"%stiexec-%d-XXXXXX%s", logDir, tracerPid, logNameSuffix) >= maxSz){ 
            FATAL("snprintf overflow"); 
        }
        //fprintf(stderr, "mkstemp dump: %s\n", buf);
        int logFd = mkstemps(buf, strlen(logNameSuffix));
        if(logFd == -1){
            FATAL("mkstemp: %s", strerror(errno));
        }
        logFileName = buf;
        buf = NULL;
        glLogFileName = logFileName;
        FILE *logFile = fdopen(logFd, "ab");
        if(logFile == NULL){
            FATAL("fdopen failed: %s", strerror(errno));
        }
        
        log_set_level(0);
        log_set_quiet(1);
        log_add_fp(logFile, 0);
        
        buf = malloc(maxSz);
        if(buf==NULL){
            my_log_fatal("malloc failed");
        }
        if(snprintf(buf , maxSz,"%stiexec-%d-helper-XXXXXX%s", logDir, tracerPid, logNameSuffix) >= maxSz){ 
            my_log_fatal("snprintf overflow"); 
        }
        helperLogFd = mkstemps(buf, strlen(logNameSuffix));
        if(helperLogFd == -1){
            my_log_fatal("mkstemp: %s", strerror(errno));
        }
        helperLogFileName = buf;
        buf = NULL;
        glHelperLogFileName = helperLogFileName;
        if (fcntl(helperLogFd, F_SETFD, FD_CLOEXEC) == -1) {
            my_log_fatal("fcntl FD_CLOEXEC: %s", strerror(errno));
        }
        if (fcntl(logFd, F_SETFD, FD_CLOEXEC) == -1) {
            my_log_fatal("fcntl FD_CLOEXEC: %s", strerror(errno));
        }
        log_info("tracerLogFileName:%s, heplerLogFileName:%s", logFileName, helperLogFileName);
    }

    // setup pipes
    // A is parent, B is son, i.e., the helper
    // A<-B
    // 0  1
    int linkPipe[2];
    // A->B
    // 1  0
    int linkPipeReverse[2];
    if (pipe(linkPipe)==-1)
        my_log_fatal("%s", strerror(errno));
    if (pipe(linkPipeReverse)==-1)
        my_log_fatal("%s", strerror(errno));

    // ptrace stuff
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
            my_log_fatal("snprintf overflow"); 
        }
        if(snprintf(myPidStrBuf ,  maxSz,"%d", getpid()) >= maxSz){ 
            my_log_fatal("snprintf overflow"); 
        }
        if(snprintf(cmdHeaderAddrStrBuf , maxSz, "%" PRIu64, (uint64_t)cmdHeader) >= maxSz){ 
            my_log_fatal("snprintf overflow"); 
        }
        {
            if (ptrace(PTRACE_GETREGS, pid, 0, &traceeRegsBackup) == -1)
                my_log_fatal("%s", strerror(errno));
            if(snprintf(sonInitialIPStrBuf , maxSz, "%" PRIu64, (uint64_t)traceeRegsBackup.rip) >= maxSz){
                my_log_fatal("snprintf overflow");
            }
        }
        pid_t pidOfHelper = fork();
        switch (pidOfHelper) {
            case -1: /* error */
                my_log_fatal("%s", strerror(errno));
            case 0:  /* child */
                // setup pipe
                pidOfHelper = getpid();
                assertNoMinus1RetToStderr(dup2 (linkPipe[1], STDOUT_FILENO));
                assertNoMinus1RetToStderr(close(linkPipe[0]));
                assertNoMinus1RetToStderr(close(linkPipe[1]));
                assertNoMinus1RetToStderr(dup2 (linkPipeReverse[0], STDIN_FILENO));
                assertNoMinus1RetToStderr(close(linkPipeReverse[0]));
                assertNoMinus1RetToStderr(close(linkPipeReverse[1]));
                execl(glHelperPath, "helper", helperLogFileName, logFileName,
                    myPidStrBuf, cmdHeaderAddrStrBuf, sonPidStrBuf, sonInitialIPStrBuf, (char *)0);
                FATAL("%s", strerror(errno));
        }
    }
    assertNoMinus1Ret(close(linkPipe[1]));
    assertNoMinus1Ret(close(linkPipeReverse[0]));
    rdFd = linkPipe[0];
    wrFd = linkPipeReverse[1];
    {
        readOneByteFromPipe();
        
        log_info("rcv sz:%"PRIu64"\n", cmdHeader[0]);
        if(cmdHeader[0] % 40 != 0){
            my_log_fatal("unexpected size rcved %"PRIu64, cmdHeader[0]);
        }
        void* addr = NULL;
        if(cmdHeader[0] != 0){
            addr = malloc(cmdHeader[0]);
            if(addr==NULL){
                my_log_fatal("malloc failed %s", strerror(errno));
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
            my_log_fatal("loop, unexpected size rcved %"PRIu64, cmdBodySzLeft);
        }
        // enter next syscall
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            my_log_fatal("%s", strerror(errno));
        myWait(pid);
        log_info("before mangle\n");
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
                my_log_fatal("%s", strerror(errno));
            mgleRegs.orig_rax = syscallNo;
            mgleRegs.rdi = arg0; mgleRegs.rsi = arg1; mgleRegs.rdx = arg2;
            mgleRegs.r10 = arg3; mgleRegs.r8  =    0; mgleRegs.r9  =    0;
            if (ptrace(PTRACE_SETREGS, pid, 0, &mgleRegs) == -1)
                my_log_fatal("mangle syscall %s", strerror(errno));
        }
        log_info("after mangle\n");
        dumpSyscallEnter(pid);

        // run this syscall and suspend before return to userspace
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            my_log_fatal("%s", strerror(errno));
        myWait(pid);

        {
            uint64_t retRax = dumpSyscallRet(pid);
            int64_t i64Ret = (int64_t)retRax;
            if(i64Ret >= -4095 && i64Ret <= -1){
                my_log_fatal("mangled syscall return failed:%s", strerror(i64Ret));
            }
            if(syscallNo == 9) {// mmap
                if(arg0 == retRax){
                    log_info("mmap return an expected addr :-)\n");
                }else{
                    my_log_fatal("mangled syscall return an unexpected addr");
                }
            }
        }
    }
    if(cmdBodySzLeft == 0){
        log_info("cmd finish consuming\n");
        {
            writeOneByteToPipe();
            readOneByteFromPipe();
        }
        log_info("resume tracee state\n");
        if (ptrace(PTRACE_SETREGS, pid, 0, &traceeRegsBackup) == -1)
            my_log_fatal("%s", strerror(errno));
        log_info("end, so detaching\n");
        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
            my_log_fatal("failed to detach: %s", strerror(errno));
        }
        log_info("done :-D\n");
        log_info("getchar and exit:\n");
        myWaitHelper(0);
        return 0;
    }else{
        my_log_fatal("unexecpted end");
    }
    return 0;
}