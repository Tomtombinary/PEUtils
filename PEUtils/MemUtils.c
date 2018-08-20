/**
 * \file MemUtils.c
 * \brief Defines function described in file MemUtils.h
 * \author Tomtombinary
 * \version 1.0
 * \date 18 août 2018
 */

#include "stdafx.h"
#include "MemUtils.h"

BOOL MemIsNull(LPVOID Buffer, DWORD SizeInBytes) 
{
	PBYTE BytesBuff = (PBYTE)Buffer;
	while (*BytesBuff == '\0' && SizeInBytes > 0)
	{
		BytesBuff++;
		SizeInBytes--;
	}
	return SizeInBytes == 0;
}

BOOL PEBUtils_EnumModules(EnumModulesCallback Callback,PVOID UserArgs)
{
	PPEB Peb;
	NTSTATUS Status;
	PROCESS_BASIC_INFORMATION ProcBasicInfo;
	ULONG ReturnLength;
	BOOL bEnumTerminated = TRUE;

	Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &ProcBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if(NT_SUCCESS(Status))
	{ 
		Peb = ProcBasicInfo.PebBaseAddress;
		PLIST_ENTRY FirstEntry = &(Peb->Ldr->InMemoryOrderModuleList);
		PLIST_ENTRY CurrentEntry = FirstEntry->Flink;
		do
		{
			PLDR_DATA_TABLE_ENTRY pDllEntry = (PLDR_DATA_TABLE_ENTRY)((DWORD)CurrentEntry - (DWORD)offsetof(LDR_DATA_TABLE_ENTRY,InMemoryOrderLinks));
			if (!Callback(pDllEntry,UserArgs))
			{
				bEnumTerminated = FALSE;
				break;
			}
			CurrentEntry = CurrentEntry->Flink;
		} while (CurrentEntry != FirstEntry);
	}
	return bEnumTerminated;
}