#pragma once

#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <intrin.h>

#define _TARGET 0xaf63fe4c86022652
#define _CrTh 0x15dd5b2c59a5081a


typedef struct {
	PVOID DllBase;
}TARGETDLL, *PTARGETDLL;

typedef struct {
	DWORD64 HashCode;
	DWORD64 Address;
}FUNCNODE, *PFUNCNODE;

//typedef struct {
//	FUNCNODE CrTh;
//	FUNCNODE 
//}WHATIWANT, *PWHATIWANT;


class HalosGate {

public:
	HalosGate() {
#ifdef _WIN64
		this->_peb = (PPEB)__readgsqword(0x60);
		this->_ldr = (PPEB_LDR_DATA)this->_peb->Ldr;
		this->_module_entry = (LIST_ENTRY)this->_ldr->InMemoryOrderModuleList;
		this->findTarget();
#else
		this->_peb = (PPEB)__readfsdword(0x30);
#endif
	}

	inline PPEB getPEB() {
		return this->_peb;
	}

	inline PPEB_LDR_DATA getLDR() {
		return this->_ldr;
	}

	inline LIST_ENTRY getModuleEntry() {
		return this->_module_entry;
	}

	void traversalModule() {
		PLDR_DATA_TABLE_ENTRY pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)this->_module_entry.Flink-0x10);
		while (pModule->DllBase) {
			printf("Module Base: %p\n", pModule->DllBase);
			printf("Module Name: %ws\n", pModule->FullDllName.Buffer);
			pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pModule->InMemoryOrderLinks.Flink-0x10);
		}
	}

	//Crash? Maybe!
	DWORD64 Hash(UNICODE_STRING ModuleName) {
		PBYTE pString = (PBYTE)ModuleName.Buffer;
		DWORD64 result = 0;
		std::hash<std::string> hash_str;
		result = hash_str((char*)pString);
		return result;
	}

	DWORD64 Hash(PBYTE FunctionName) {
		DWORD64 result = 0;
		std::hash<std::string> hash_str;
		result = hash_str((char*)FunctionName);
		return result;
	}

	void findTarget() {
		PLDR_DATA_TABLE_ENTRY pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)this->_module_entry.Flink - 0x10);
		this->_p_target = (PTARGETDLL)malloc(sizeof(TARGETDLL));
		while (pModule->DllBase) {
			if (Hash(pModule->FullDllName) == _TARGET) {
#ifdef _PRINT
				printf("Module Base: %p\n", pModule->DllBase);
				printf("Module Name: %ws\n", pModule->FullDllName.Buffer);
#endif
				this->_p_target->DllBase = pModule->DllBase;
				break;
			}
			pModule = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pModule->InMemoryOrderLinks.Flink - 0x10);
		}
	}

	void traversalExports() {
		PBYTE pImageBase = (PBYTE)this->_p_target->DllBase;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
		PIMAGE_OPTIONAL_HEADER pOption = (PIMAGE_OPTIONAL_HEADER)(pImageBase +
			pDos->e_lfanew +
			sizeof(DWORD) +
			sizeof(IMAGE_FILE_HEADER));
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pImageBase + 
			pOption->DataDirectory[0].VirtualAddress);
		PDWORD pAddressOfNames = (PDWORD)(pImageBase + pExport->AddressOfNames);
		PDWORD pAddressOfFunctions = (PDWORD)(pImageBase + pExport->AddressOfFunctions);
		PWORD pAddressOfOrdianls = (PWORD)(pImageBase + pExport->AddressOfNameOrdinals);
		for (int i = 0; i < pExport->NumberOfNames; i++) {
			PBYTE pFuncName = pImageBase + pAddressOfNames[i];
			PBYTE pFuncAddr = pImageBase + pAddressOfFunctions[pAddressOfOrdianls[i]];
			printf("Function Name: %s\n", pFuncName);
			printf("Hash Code: %llx\n", this->Hash(pFuncName));
			printf("Hooked? %s\n", this->detectHook(pFuncAddr)?"yes":"no");
			printf("Function Addr: %llx\n", pFuncAddr);
		}
	}

	//maybe hooked somewhere else, you can add more pattern to help it 
	BOOL detectHook(PBYTE pFuncAddr) {
		if (*pFuncAddr != 0x4c || *(pFuncAddr + 1) != 0x8b 
			|| *(pFuncAddr + 2) != 0xd1
			|| *(pFuncAddr + 3) != 0xb8) {
			return true;
		}
		return false;
	}

	WORD findSysCall(DWORD64 HashCode, DWORD depth) {
		PBYTE pImageBase = (PBYTE)this->_p_target->DllBase;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
		PIMAGE_OPTIONAL_HEADER pOption = (PIMAGE_OPTIONAL_HEADER)(pImageBase +
			pDos->e_lfanew +
			sizeof(DWORD) +
			sizeof(IMAGE_FILE_HEADER));
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pImageBase +
			pOption->DataDirectory[0].VirtualAddress);
		PDWORD pAddressOfNames = (PDWORD)(pImageBase + pExport->AddressOfNames);
		PDWORD pAddressOfFunctions = (PDWORD)(pImageBase + pExport->AddressOfFunctions);
		PWORD pAddressOfOrdianls = (PWORD)(pImageBase + pExport->AddressOfNameOrdinals);
		WORD syscllNum = 0;
		for (int i = 0; i < pExport->NumberOfNames; i++) {
			PBYTE pFuncName = pImageBase + pAddressOfNames[i];
			PBYTE pFuncAddr = pImageBase + pAddressOfFunctions[pAddressOfOrdianls[i]];
			if (this->Hash(pFuncName) == HashCode) {
				if (detectHook(pFuncAddr)) {
					for (int i = 1; i < depth; i++) {
						if (!this->detectHook(pFuncAddr - 0x20 * i)) {
						
							BYTE high = *((PBYTE)pFuncAddr + 5);
							BYTE low = *((PBYTE)pFuncAddr + 4);
							syscllNum = (high << 8) | low + i;
							break;
						}
						if (!this->detectHook(pFuncAddr + 0x20 * i)) {
						
							BYTE high = *((PBYTE)pFuncAddr + 5);
							BYTE low = *((PBYTE)pFuncAddr + 4);
							syscllNum = (high << 8) | low - i;
							break;
						}
					}
				}
				else {
					
					BYTE high = *((PBYTE)pFuncAddr + 5);
					BYTE low = *((PBYTE)pFuncAddr + 4);
					syscllNum = (high << 8) | low;
					printf("Syscall Number is: %d\n", syscllNum);
				}
				break;
			}
		}
		return syscllNum;
	}
	

private:
	PPEB _peb;
	PPEB_LDR_DATA _ldr;
	LIST_ENTRY _module_entry;
	PTARGETDLL _p_target;
};