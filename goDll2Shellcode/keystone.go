package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MODE_32 = 4
	MODE_64 = 8

	ARCH_X86 = 4
)

func GenerateShellcode(asm string) ([]byte, error) {
	fmt.Println("----> Generating Shellcode from ASM <----")

	fmt.Println("[+] Loading keystone.dll")
	hModule, err := windows.LoadLibrary("keystone.dll")
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to load Libray\n")
	}
	fmt.Println("[+] Getting function addresses")
	ks_open_proc, err := windows.GetProcAddress(hModule, "ks_open")
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to get address for ks_open\n")
	}
	ks_asm_proc, err := windows.GetProcAddress(hModule, "ks_asm")
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to get address for ks_asm\n")

	}

	fmt.Println("[+] Running ks_open_proc")
	var ksSession uintptr
	r1, _, err := syscall.SyscallN(ks_open_proc, uintptr(ARCH_X86), uintptr(MODE_64), uintptr(unsafe.Pointer(&ksSession)))
	if r1 != 0 {
		return []byte{}, err
	}
	var bytearray, size, count uintptr

	ptr, err := syscall.BytePtrFromString(asm)
	if err != nil {
		return []byte{}, fmt.Errorf("Failed to get byte ptr from string\n")
	}
	fmt.Println("[+] Running ks_asm_proc")
	r1, _, err = syscall.SyscallN(ks_asm_proc,
		ksSession,
		uintptr(unsafe.Pointer(ptr)),
		0,
		uintptr(unsafe.Pointer(&bytearray)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&count)),
	)
	if r1 != 0 {
		return []byte{}, err
	}
	fmt.Println("[+] Copying bytes from memory to byte slice")
	//fmt.Printf("Successfully generated shellcode of size %d at address 0x%x\n", size, bytearray)
	bytes := make([]byte, size)
	copy(bytes, (*[1 << 30]byte)(unsafe.Pointer(bytearray))[:size])
	//fmt.Println(bytes)
	return bytes, nil
}
