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

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
)

const (
	MAP_HUGE_SHIFT = 26
	MAP_HUGE_2MB   = (21 << MAP_HUGE_SHIFT)
	MAP_HUGE_1GB   = (30 << MAP_HUGE_SHIFT)
)

var glOnlyExecReMmap = true

var glLogFileName string
var glTracerLogFileName string

func AssertNoErr(err error) {
	if err == nil {
	} else {
		MyPanicln(err)
	}
}

func Assert(b bool) {
	if b {
	} else {
		MyPanicln(b)
	}
}

func MyPrintf(format string, a ...interface{}) {
	//fmt.Fprintf(os.Stderr, format, a...)
	logrus.Infof(format, a...)
}

func MyPrintln(a ...interface{}) {
	//fmt.Fprintln(os.Stderr, a...)
	logrus.Infoln(a...)
}

func MyPanicf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "tracerLogFileName:%s, heplerLogFileName:%s", glTracerLogFileName, glLogFileName)
	fmt.Fprintf(os.Stderr, format, a...)
	debug.PrintStack()
	logrus.Panicf(format, a...)
}

func MyPanicln(a ...interface{}) {
	fmt.Fprintf(os.Stderr, "tracerLogFileName:%s, heplerLogFileName:%s", glTracerLogFileName, glLogFileName)
	fmt.Fprintln(os.Stderr, a...)
	debug.PrintStack()
	logrus.Panicln(a...)
}

/*
inject_hardcode:
	while(1) exit_group(1)

objdump -M intel:
0000000000000000 <inject_hardcode>:
   0:   48 c7 c0 e7 00 00 00    mov    rax,0xe7
   7:   48 c7 c7 01 00 00 00    mov    rdi,0x1
   e:   0f 05                   syscall
  10:   eb ee                   jmp    0 <inject_hardcode>
*/
var injectLoopExitGroupCodeHexStr = " " + //<inject_hardcode>:
	"48 c7 c0 e7 00 00 00" + // mov    rax,0xe7
	"48 c7 c7 01 00 00 00" + // mov    rdi,0x1
	"0f 05" + //                syscall
	"eb ee" //                  jmp    0 <inject_hardcode> // jmp rel8(-18)

var injectLoopCPUCodeHexStr = "eb fe" // cpu loop

var injectSyscallHexStr = "0f 05" // syscall

func transformToCode(hexStr string) []byte {
	s := strings.ReplaceAll(hexStr, " ", "")
	//fmt.Println(s)
	bs, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	//fmt.Printf("%x", bs)
	return bs
}

func getLoopExitGroupCodeBs() []byte {
	return transformToCode(injectLoopExitGroupCodeHexStr)
}

func getLoopCPUCodeBs() []byte {
	return transformToCode(injectLoopCPUCodeHexStr)
}

func getSyscallCodeBs() []byte {
	return transformToCode(injectSyscallHexStr)
}

type ProcMemHack struct {
	pid  int
	path string
	f    *os.File
}

func MustOpenProcMemHack(pid int) *ProcMemHack {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	p := &ProcMemHack{
		path: path,
		pid:  pid,
	}
	var err error
	p.f, err = os.OpenFile(path, os.O_RDWR, 0600)
	AssertNoErr(err)
	return p
}

func (p *ProcMemHack) GetPid() int {
	return p.pid
}

func (p *ProcMemHack) GetProcNumaMapsPath() string {
	return fmt.Sprintf("/proc/%d/numa_maps", p.GetPid())
}

func (p *ProcMemHack) GetProcMapsPath() string {
	return fmt.Sprintf("/proc/%d/maps", p.GetPid())
}

func (p *ProcMemHack) MustWriteAt(bs []byte, offset int64) {
	ct, err := p.f.WriteAt(bs, offset)
	AssertNoErr(err)
	Assert(ct == len(bs))
}

func (p *ProcMemHack) MustReadAt(bs []byte, offset int64) {
	ct, err := p.f.ReadAt(bs, offset)
	AssertNoErr(err)
	Assert(ct == len(bs))
}

type ProcMapsUnit struct {
	StartAddr uint64
	EndAddr   uint64
	Size      uint64
	PermStr   string
	PathName  string
}

type ProcMapsUnits []*ProcMapsUnit

func (u *ProcMapsUnit) IsExec() bool {
	return u.isPerm('x')
}

// perm r|w|x
func (u *ProcMapsUnit) isPerm(perm rune) bool {

	Assert(len(u.PermStr) == 4)
	for _, c := range u.PermStr {
		Assert(c == 'r' || c == 'w' || c == 'x' || c == 'p' || c == '-')
		if c == perm {
			return true
		}
	}
	return false
}

// protection of the mapping
func (u *ProcMapsUnit) GetProt() int {
	var prot int
	if u.isPerm('x') {
		prot |= syscall.PROT_EXEC
	}
	if u.isPerm('w') {
		prot |= syscall.PROT_WRITE
	}
	if u.isPerm('r') {
		prot |= syscall.PROT_READ
	}
	return prot
}

func (u *ProcMapsUnit) IsContainAddr(addr uint64) bool {
	Assert(u.EndAddr > u.StartAddr)
	if addr >= u.StartAddr && addr < u.EndAddr {
		return true
	}
	return false
}

func eatAllHeadingAndTrailingSpaces(str string) string {
	return strings.TrimSpace(str)
}

func dumpProcNumaMapsFileToTmpFile(procNumaMapsPath string) (tmpFilePath string) {
	return dupFileToANewTmpFile(procNumaMapsPath)
}

func dumpProcMapsFileToTmpFile(procMapsPath string) (tmpFilePath string) {
	return dupFileToANewTmpFile(procMapsPath)
}

func dupFileToANewTmpFile(oldFilePath string) (tmpFilePath string) {
	tmpPrefix := strings.Replace(fmt.Sprintf("%s.tmp", oldFilePath), "/", "_", -1)
	MyPrintf("dupFileToANewTmpFile: tmpPrefix:%s\n", tmpPrefix)
	tmpFile, err := ioutil.TempFile("", tmpPrefix)
	AssertNoErr(err)
	defer tmpFile.Close()
	tmpFilePath = tmpFile.Name()
	bs, err := ioutil.ReadFile(oldFilePath) // just pass the file name
	AssertNoErr(err)
	AssertNoErr(ioutil.WriteFile(tmpFilePath, bs, 0600))
	MyPrintf("dupFileToANewTmpFile: %s\n", tmpFilePath)
	return
}

func parseProcMapsFile(path string) []*ProcMapsUnit {
	var list []*ProcMapsUnit
	file, err := os.Open(path)
	AssertNoErr(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	{
		const maxCapacity = 1024 * 1024 // your required line length
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)
	}

	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		var u ProcMapsUnit
		//00607000-00608000 rw-p 00007000 fd:00 17193274                           /usr/bin/sleep
		str := scanner.Text()
		//fmt.Println(str)
		testHitCt := 0
		for _, pattern := range []string{"\\s+\\[heap\\]\\s*$", "\\s+\\[vdso\\]\\s*$",
			"\\s+\\[stack\\]\\s*$", "\\s+\\[vsyscall\\]\\s*$"} {

			re, err := regexp.Compile(pattern)
			AssertNoErr(err)
			testStr := re.FindString(str)
			if len(testStr) > 0 {
				testHitCt++
			}
		}
		Assert(testHitCt == 0 || testHitCt == 1)
		if testHitCt > 0 {
			continue
		}
		re, err := regexp.Compile("^[0-9a-f]+")
		AssertNoErr(err)
		startAddrStr := re.FindString(str)
		str = str[len(startAddrStr):]
		//
		Assert(str[0] == '-')
		str = str[1:]
		//
		re, err = regexp.Compile("^[0-9a-f]+")
		AssertNoErr(err)
		endAddrStr := re.FindString(str)
		str = str[len(endAddrStr):]
		str = eatAllHeadingAndTrailingSpaces(str)
		//
		pattern := "^[^\\s]+"
		//fmt.Println("pattern", pattern)
		re, err = regexp.Compile(pattern)
		AssertNoErr(err)
		permStr := re.FindString(str)
		Assert(len(permStr) == 4)
		//str = str[len(permStr):]
		//str = eatAllHeadingAndTrailingSpaces(str)
		//
		u.StartAddr, err = strconv.ParseUint(startAddrStr, 16, 64)
		AssertNoErr(err)
		u.EndAddr, err = strconv.ParseUint(endAddrStr, 16, 64)
		AssertNoErr(err)
		u.PermStr = permStr
		Assert(u.EndAddr > u.StartAddr)
		u.Size = u.EndAddr - u.StartAddr
		//
		list = append(list, &u)
	}

	AssertNoErr(scanner.Err())
	return list
}

type MemSpan struct {
	StartAddr uint64
	Len       uint64
}

// try to get as much 2M pages as possible
func selfAdaptMmapPagesFixedCalc(addr, len uint64) []*MemSpan {
	if len <= 0 {
		var spans []*MemSpan
		spans = append(spans, &MemSpan{
			addr, len,
		})
		return spans
	}
	var firstBeBottom, lastLeCeil uint64
	var mod uint64
	var X = uint64(2 * 1024 * 1024)
	mod = addr % X
	firstBeBottom = addr
	if mod > 0 {
		firstBeBottom = addr + X - mod
	}
	mod = (addr + len) % X
	lastLeCeil = (addr + len) - mod
	//
	if lastLeCeil > firstBeBottom {
		MyPrintf("%x %x\n", addr, firstBeBottom-addr)
		MyPrintf("%x %x\n", firstBeBottom, lastLeCeil-firstBeBottom)
		MyPrintf("%x %x\n", lastLeCeil, addr+len-lastLeCeil)
		var spans []*MemSpan
		spans = append(spans, &MemSpan{
			addr, firstBeBottom - addr,
		})
		spans = append(spans, &MemSpan{
			firstBeBottom, lastLeCeil - firstBeBottom,
		})
		spans = append(spans, &MemSpan{
			lastLeCeil, addr + len - lastLeCeil,
		})
		return spans
	} else {
		MyPrintf("%x %x\n", addr, len)
		var spans []*MemSpan
		spans = append(spans, &MemSpan{
			addr, len,
		})
		return spans
	}
}

type CmdBodyUnit struct {
	op    string // mmap/munmap
	addr  uint64
	len   uint64
	prot  uint64
	flags uint64
}

func marshalCmdBodyUnits(units []*CmdBodyUnit) []byte {
	bs := make([]byte, 5*8*len(units))
	origBs := bs
	for _, u := range units {
		Assert(len(bs) >= 5*8)
		var syscallNo uint64
		if u.op == "mmap" {
			syscallNo = 9
		} else if u.op == "munmap" {
			syscallNo = 11
		} else {
			panic("unexpected")
		}
		writeU64ToBs(bs, syscallNo)
		bs = bs[8:]
		writeU64ToBs(bs, u.addr)
		bs = bs[8:]
		writeU64ToBs(bs, u.len)
		bs = bs[8:]
		writeU64ToBs(bs, u.prot)
		bs = bs[8:]
		writeU64ToBs(bs, u.flags)
		bs = bs[8:]
	}
	return origBs
}

type Helper struct {
	tracerProMem *ProcMemHack
	// mem layout: cmdBodySize, cmdBodyAddr uint64
	tracerCmdHeaderAddr uint64
	tracerCmdBodySize   uint64
	tracerCmdBodyAddr   uint64

	traceeProMem *ProcMemHack
	// inital instruction pointer value after syscall `exec`` was returned from kernel
	traceeInitialIP uint64

	pipeFileWrite *os.File
	pipeFileRead  *os.File

	traceeMapUnits     []*ProcMapsUnit
	snapshotUnits      []*SnapshotUnit
	cmdBodyUnits       []*CmdBodyUnit
	marshaledCmdBodyBs []byte
	injectCodeBs       []byte
}

func (h *Helper) addCmdBodyUnit(u *CmdBodyUnit) {
	h.cmdBodyUnits = append(h.cmdBodyUnits, u)
}

type SnapshotUnit struct {
	addr      uint64
	size      uint64
	backupMem []byte
}

func (h *Helper) addSnapshotUnit(addr, size uint64) {
	var u SnapshotUnit
	u.addr = addr
	u.size = size
	Assert(size > 0)
	u.backupMem = make([]byte, size)
	offset := int64(u.addr)
	Assert(offset >= 0)
	h.traceeProMem.MustReadAt(u.backupMem, offset)
	h.snapshotUnits = append(h.snapshotUnits, &u)
}

func (h *Helper) restoreFromSnapshotUnits(checkFlag bool) {
	if len(h.marshaledCmdBodyBs) > 0 {
		for _, u := range h.snapshotUnits {
			offset := int64(u.addr)
			Assert(offset >= 0)
			h.traceeProMem.MustWriteAt(u.backupMem, offset)
			if checkFlag {
				bs := make([]byte, len(u.backupMem))
				h.traceeProMem.MustReadAt(bs, offset)
				Assert(len(bs) == len(u.backupMem))
				for i, v := range bs {
					Assert(v == u.backupMem[i])
				}
				MyPrintln("restoreFromSnapshotUnits check passed")
			}
		}
	} else {
		MyPrintln("restoreFromSnapshotUnits: nop since len(h.marshaledCmdBodyBs) == 0")
		Assert(len(h.snapshotUnits) == 1)
	}
	h.snapshotUnits = nil
}

func NewHelper(tracerPid, traceePid int, traceeInitialIP, tracerCmdHeaderAddr uint64, pipeFileWrite, pipeFileRead *os.File) *Helper {
	h := &Helper{
		tracerProMem:        MustOpenProcMemHack(tracerPid),
		tracerCmdHeaderAddr: tracerCmdHeaderAddr,
		traceeProMem:        MustOpenProcMemHack(traceePid),
		traceeInitialIP:     traceeInitialIP,
		pipeFileWrite:       pipeFileWrite,
		pipeFileRead:        pipeFileRead,
		injectCodeBs:        getLoopExitGroupCodeBs(),
	}
	return h
}

func (h *Helper) tryToExclueTheMapUintsWhichContainInitialIP() {
	idx := 0
	ct := 0
	for i, u := range h.traceeMapUnits {
		if u.IsContainAddr(uint64(h.traceeInitialIP)) {
			Assert(u.IsExec())
			idx = i
			ct++
		}
	}
	Assert(ct == 1)
	delUnit := h.traceeMapUnits[idx]
	oldSlice := h.traceeMapUnits
	h.traceeMapUnits = append(oldSlice[:idx], oldSlice[idx+1:]...)
	maxAddrNeed := h.traceeInitialIP + uint64(len(h.injectCodeBs)) - 1
	Assert(delUnit.IsContainAddr(maxAddrNeed))
	h.addSnapshotUnit(delUnit.StartAddr, delUnit.Size)
}

func (h *Helper) dumpTraceeMapUnits() {
	dumpProcMapsFileToTmpFile(h.traceeProMem.GetProcMapsPath())
	dumpProcNumaMapsFileToTmpFile(h.traceeProMem.GetProcNumaMapsPath())
	MyPrintln("dumpTraceeMapUnits-->>")
	for _, u := range h.traceeMapUnits {
		MyPrintln(u.StartAddr, u.EndAddr, u.Size, u.PermStr, u.PathName)
	}
	MyPrintln("<<--dumpTraceeMapUnits")
}

func (h *Helper) AnalyzeAndSnapshot() {
	h.traceeMapUnits = parseProcMapsFile(h.traceeProMem.GetProcMapsPath())
	h.dumpTraceeMapUnits()
	defer h.dumpTraceeMapUnits()
	h.tryToExclueTheMapUintsWhichContainInitialIP()
	for _, u := range h.traceeMapUnits {
		Assert(u.Size > 0)
		checkOkFlag := true
		if glOnlyExecReMmap {
			checkOkFlag = false
			if u.IsExec() {
				checkOkFlag = true
			}
		}
		if checkOkFlag { //u.IsExec() {
			Assert(false == u.IsContainAddr(h.traceeInitialIP))
			spans := selfAdaptMmapPagesFixedCalc(u.StartAddr, u.Size)
			Assert(len(spans) == 3 || len(spans) == 1)
			if len(spans) == 3 {
				Assert(spans[1].Len > 0)
				h.addSnapshotUnit(u.StartAddr, u.Size)
				{
					var cmdBodyU CmdBodyUnit
					cmdBodyU.op = "munmap"
					cmdBodyU.addr = u.StartAddr
					cmdBodyU.len = u.Size
					h.addCmdBodyUnit(&cmdBodyU)
				}
				for spanIdx, span := range spans {
					hugePageFlag := false
					if spanIdx == 1 {
						hugePageFlag = true
						Assert(span.Len > 0 && span.Len%(1024*1024*2) == 0 && span.StartAddr%(1024*1024*2) == 0)
					}
					if span.Len > 0 {
						var cmdBodyU CmdBodyUnit
						cmdBodyU.op = "mmap"
						cmdBodyU.addr = span.StartAddr
						cmdBodyU.len = span.Len
						cmdBodyU.prot = uint64(u.GetProt())
						flags := syscall.MAP_FIXED | syscall.MAP_PRIVATE | syscall.MAP_ANON
						if hugePageFlag {
							flags |= syscall.MAP_HUGETLB
							flags |= MAP_HUGE_2MB //syscall.MAP_HUGE_2MB
						}
						cmdBodyU.flags = uint64(flags)
						h.addCmdBodyUnit(&cmdBodyU)
					}
				}
			}
		}
	}
}

var nativeEndian binary.ByteOrder

func initEndian() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		MyPrintln("binary.LittleEndian")
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		MyPrintln("binary.BigEndian")
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func writeU64ToBs(bs []byte, u64 uint64) {
	nativeEndian.PutUint64(bs, u64)
}

func readU64FromBs(bs []byte) uint64 {
	return nativeEndian.Uint64(bs)
}

func (h *Helper) WriteOneByteToPipe(r byte) {
	bs := make([]byte, 1)
	bs[0] = r
	n, err := h.pipeFileWrite.Write(bs)
	AssertNoErr(err)
	Assert(n == 1)
}

func (h *Helper) ReadOneByteFromPipe() byte {
	bs := make([]byte, 1)
	n, err := h.pipeFileRead.Read(bs)
	AssertNoErr(err)
	Assert(n == 1)
	return bs[0]
}

func (h *Helper) marshalCmdBodyUnits() {
	h.marshaledCmdBodyBs = marshalCmdBodyUnits(h.cmdBodyUnits)
}
func (h *Helper) GetCmdBodyAddrFromTracer() {
	if len(h.cmdBodyUnits) == 0 {
		MyPrintln("GetCmdBodyAddrFromTracer: len(h.cmdBodyUnits) == 0")
		//return
	}
	h.marshalCmdBodyUnits()
	needSize := uint64(len(h.marshaledCmdBodyBs))
	bs := make([]byte, 8)
	writeU64ToBs(bs, needSize)
	h.tracerCmdBodySize = needSize
	offset := int64(h.tracerCmdHeaderAddr)
	Assert(offset >= 0)
	h.tracerProMem.MustWriteAt(bs, offset)
	h.WriteOneByteToPipe(0)
	h.ReadOneByteFromPipe()
	offset = int64(h.tracerCmdHeaderAddr + 8)
	Assert(offset >= 0)
	h.tracerProMem.MustReadAt(bs, offset)
	h.tracerCmdBodyAddr = readU64FromBs(bs)
}

func (h *Helper) SetupCmdBodyForTracer() {
	if len(h.marshaledCmdBodyBs) > 0 {
		h.tracerProMem.MustWriteAt(h.marshaledCmdBodyBs, int64(h.tracerCmdBodyAddr))
	}
}

func (h *Helper) InjectHackCodeIntoTracee() {
	if len(h.marshaledCmdBodyBs) > 0 {
		offset := int64(h.traceeInitialIP)
		Assert(offset >= 0)
		h.traceeProMem.MustWriteAt(h.injectCodeBs, offset)
	} else {
		MyPrintln("InjectHackCodeIntoTracee: nop since len(h.marshaledCmdBodyBs) == 0")
	}
}

func (h *Helper) RunHackCodeInTracee() {
	h.WriteOneByteToPipe('r')
	h.ReadOneByteFromPipe()
}

func (h *Helper) RestoreEverything() {
	h.restoreFromSnapshotUnits(true)
	h.dumpTraceeMapUnits()
	h.WriteOneByteToPipe('f')
}

func (h *Helper) Exit() {
}

func main() {
	if len(os.Args) < 7 {
		MyPrintln("more args need")
		os.Exit(1)
	}

	var logFileName, tracerLogFileName, tracerPidStr, cmdHeaderAddrStr, traceePidStr, ipOffsetStr string
	logFileName = os.Args[1]
	tracerLogFileName = os.Args[2]
	tracerPidStr = os.Args[3]
	cmdHeaderAddrStr = os.Args[4]
	traceePidStr = os.Args[5]
	ipOffsetStr = os.Args[6]
	tracerPid, err := strconv.ParseUint(tracerPidStr, 10, 64)
	AssertNoErr(err)
	cmdHeaderAddr, err := strconv.ParseUint(cmdHeaderAddrStr, 10, 64)
	AssertNoErr(err)
	traceePid, err := strconv.ParseUint(traceePidStr, 10, 64)
	AssertNoErr(err)
	traceeInitialIP, err := strconv.ParseUint(ipOffsetStr, 10, 64)
	AssertNoErr(err)
	glLogFileName = logFileName
	glTracerLogFileName = tracerLogFileName
	{
		f, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			MyPrintf("%s,%s,%d,%d,%d,%d\n", logFileName, tracerLogFileName, tracerPid, cmdHeaderAddr, traceePid, traceeInitialIP)
			MyPanicf("failed to open log file %s, err:%s", logFileName, err)
		}
		logrus.SetOutput(f)
		MyPrintf("%s,%s,%d,%d,%d,%d\n", logFileName, tracerLogFileName, tracerPid, cmdHeaderAddr, traceePid, traceeInitialIP)
		logrus.Infof("tracerLogFileName:%s, heplerLogFileName:%s", tracerLogFileName, logFileName)
	}
	initEndian()
	h := NewHelper(int(tracerPid), int(traceePid), traceeInitialIP, cmdHeaderAddr, os.Stdout, os.Stdin)
	h.AnalyzeAndSnapshot()
	h.GetCmdBodyAddrFromTracer()
	h.SetupCmdBodyForTracer()
	h.InjectHackCodeIntoTracee()
	h.RunHackCodeInTracee()
	h.RestoreEverything()
	h.Exit()
}

func oldMain() {
	//os.Exit(0)
	_ = injectLoopExitGroupCodeHexStr
	fmt.Println("hi")
	var pidStr, offsetStr string
	if len(os.Args) > 2 {
		pidStr = os.Args[1]
		offsetStr = os.Args[2]
	} else {
		panic("want arg and offset")
	}
	pid, err := strconv.ParseUint(pidStr, 10, 64)
	AssertNoErr(err)
	offset, err := strconv.ParseUint(offsetStr, 10, 64)
	fmt.Println("pid ", pid)
	fmt.Printf("offset: %x", offset)
	{
		fp := getLoopCPUCodeBs
		p := MustOpenProcMemHack(int(pid))
		bs := fp()
		offset := int64(offset)
		p.MustReadAt(bs, offset)
		fmt.Println("get ", hex.EncodeToString(bs))
		//return
		bs = fp()
		fmt.Println("write ", hex.EncodeToString(bs))
		p.MustWriteAt(bs, offset)
		p.MustReadAt(bs, offset)
		fmt.Println("get ", hex.EncodeToString(bs))
	}
}

func misc() {
	path := "/proc/48565/mem"
	offset := int64(140737351893280)
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	AssertNoErr(err)
	newOff, err := f.Seek(offset, 0)
	AssertNoErr(err)
	Assert(newOff == offset)
	bs := make([]byte, 1)
	ct, err := f.Read(bs)
	Assert(err == nil && ct == 1)
	fmt.Printf("%x %d\n", bs[0], bs[0])
	bs[0] = 0xcc
	newOff, err = f.Seek(offset, 0)
	AssertNoErr(err)
	Assert(newOff == offset)
	ct, err = f.Write(bs)
	fmt.Println(err)
	Assert(err == nil && ct == 1)
	//AssertNoErr(f.Sync())
	newOff, err = f.Seek(offset, 0)
	AssertNoErr(err)
	Assert(newOff == offset)

	ct, err = f.Read(bs)
	Assert(err == nil && ct == 1)
	fmt.Printf("%x %d\n", bs[0], bs[0])
}
