/**
 * \file PEUtils.c
 * \brief Defines function described in file PEUtils.h 
 * \author Tomtombinary
 * \version 1.0
 * \date 18 août 2018
 */

#include "stdafx.h"
#include "PEUtils.h"
#include "MemUtils.h"

PIMAGE_NT_HEADERS32 PE32_GetNtHeaders(HMODULE hMod)
{
	PIMAGE_NT_HEADERS32 lpNtHeaders32 = NULL;
	PIMAGE_DOS_HEADER lpDOSHeader = (PIMAGE_DOS_HEADER)hMod;
	
	/* check if dos header is valid */
	if (lpDOSHeader->e_magic == 0x5a4d)
	{
		lpNtHeaders32 = (PIMAGE_NT_HEADERS32)((DWORD)lpDOSHeader + (DWORD)lpDOSHeader->e_lfanew);
		/* check if nt header is valid */
		if (lpNtHeaders32->Signature != 0x00004550)
			lpNtHeaders32 = NULL;
		/* check if nt header is a 32 bits nt header */
		else if (lpNtHeaders32->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
			lpNtHeaders32 = NULL;
	}
	return lpNtHeaders32;
}

BOOL PE32_EnumSections(HMODULE hMod, EnumSectionsCallback pFuncCallback, LPVOID lpUserArgs)
{
	SECTION_ENTRY entry;
	BOOL bEnumTerminated = TRUE;
	
	PIMAGE_NT_HEADERS32 lpNtHeaders = PE32_GetNtHeaders(hMod);
	if (lpNtHeaders == NULL)
		return FALSE;

	DWORD lpOptionalHeader = (DWORD)&lpNtHeaders->OptionalHeader;
	DWORD SizeOfOptionalHeader = lpNtHeaders->FileHeader.SizeOfOptionalHeader;

	PIMAGE_SECTION_HEADER lpSectionHeader = (PIMAGE_SECTION_HEADER)(lpOptionalHeader + SizeOfOptionalHeader);
	DWORD nSections = lpNtHeaders->FileHeader.NumberOfSections;
	for (unsigned int i = 0; i < nSections; i++)
	{
		entry.header = lpSectionHeader;
		entry.SectionData = (PBYTE)((DWORD)hMod + lpSectionHeader->VirtualAddress);
		entry.SectionLimit = (DWORD)hMod + lpSectionHeader->VirtualAddress + lpSectionHeader->Misc.VirtualSize;
		if (pFuncCallback(&entry, lpUserArgs))
			lpSectionHeader += 1; 
		else
		{
			bEnumTerminated = FALSE;
			break;
		}
	}
	return bEnumTerminated;
}


BOOL PE32_EnumExports(HMODULE hMod, EnumExportsCallback pCallback, LPVOID UserArgs)
{
	EXPORT_ENTRY entry;
	BOOL bEnumTerminated = TRUE;
	PIMAGE_NT_HEADERS32 lpImageNtHeaders32 = PE32_GetNtHeaders(hMod);
	if (lpImageNtHeaders32 == NULL)
		return FALSE;
	
	PIMAGE_EXPORT_DIRECTORY lpImageExportDirectory = NULL;
	DWORD ImageExportDirectoryRVA = lpImageNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PDWORD lpAddressOfFunctions = NULL;
	PDWORD lpAddressOfNames = NULL;
	PWORD lpAddressOfNamesOrdinals = NULL;

	if (ImageExportDirectoryRVA != 0)
	{
		lpImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hMod + ImageExportDirectoryRVA);
		lpAddressOfFunctions = (PDWORD)((DWORD)hMod + lpImageExportDirectory->AddressOfFunctions);
		lpAddressOfNames = (PDWORD)((DWORD)hMod + lpImageExportDirectory->AddressOfNames);
		lpAddressOfNamesOrdinals = (PWORD)((DWORD)hMod + lpImageExportDirectory->AddressOfNameOrdinals);

		for (unsigned int i = 0; i < lpImageExportDirectory->NumberOfNames; i++)
		{
			entry.Ordinal = lpAddressOfNamesOrdinals[i];
			entry.RVAName = lpAddressOfNames[i];
			entry.RVAAddress = lpAddressOfFunctions[entry.Ordinal];
			entry.Name =  (LPCSTR)((DWORD)hMod + lpAddressOfNames[i]);
			entry.pFunction = (PVOID)((DWORD)hMod + lpAddressOfFunctions[entry.Ordinal]);

			if (!pCallback(&entry, UserArgs))
			{
				bEnumTerminated = FALSE;
				break;
			}
		}
	}
	else
		fprintf(stderr, "no image export directory\n");
	return bEnumTerminated;
}

BOOL PE32_EnumImports(HMODULE hMod, EnumImportsCallback pCallback, LPVOID UserArgs)
{
	IMPORT_ENTRY ImportEntry;
	LPVOID Limit = 0;
	BOOL bEnumTerminated = TRUE;
	PIMAGE_IMPORT_DESCRIPTOR lpCurrentImportDesc = NULL;
	PIMAGE_NT_HEADERS32 lpNtHeaders = PE32_GetNtHeaders(hMod);
	PDWORD HintNameRVAArray = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
	PIMAGE_THUNK_DATA32 ThunkArray = NULL;
	if (lpNtHeaders == NULL)
		return FALSE;
	
	DWORD FirstImageImportDescRVA = lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		
	if (FirstImageImportDescRVA != 0)
	{
		lpCurrentImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hMod + FirstImageImportDescRVA);
		Limit = (LPVOID)(lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + (DWORD)lpCurrentImportDesc);
		
		while ((LPVOID)lpCurrentImportDesc < Limit)
		{
			if (MemIsNull(lpCurrentImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
				break;

			ImportEntry.pImportDesc = lpCurrentImportDesc;

			LPCSTR Name = (LPCSTR)(lpCurrentImportDesc->Name + (PBYTE)hMod);

			HintNameRVAArray = (PDWORD)((DWORD)hMod + lpCurrentImportDesc->OriginalFirstThunk);
			ThunkArray = (PIMAGE_THUNK_DATA32)((DWORD)hMod + lpCurrentImportDesc->FirstThunk);
			
			while (*HintNameRVAArray != 0)
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)hMod + *(HintNameRVAArray));
				ImportEntry.pImportByName = pImportByName;
				ImportEntry.Thunk =  *(ThunkArray);

				if (!pCallback(&ImportEntry, UserArgs))
				{
					bEnumTerminated = FALSE;
					return bEnumTerminated;
				}
				HintNameRVAArray += 1;
				ThunkArray += 1;
			}
			lpCurrentImportDesc += 1; // sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
	}
	else
		fprintf(stderr, "no image import directory\n");
	return bEnumTerminated;
}

BOOL PE32_IsRVAPointToSection(PSECTION_ENTRY entry, LPVOID lpUserArgs)
{
	BOOL bContinue = TRUE;
	PFILE_OFFSET_RVA frva = (PFILE_OFFSET_RVA)lpUserArgs;

	if (frva->dwRVA >= entry->header->VirtualAddress && frva->dwRVA < entry->header->VirtualAddress + entry->header->Misc.VirtualSize)
	{
		frva->dwFileOffset = entry->header->PointerToRawData + (frva->dwRVA - entry->header->VirtualAddress);
		bContinue = FALSE;
	}

	return bContinue;
}


DWORD PE32_RVAToFileOffset(HMODULE hMod, DWORD dwRVA)
{
	FILE_OFFSET_RVA FileOffsetRVA;
	FileOffsetRVA.dwRVA = dwRVA;
	FileOffsetRVA.dwFileOffset = 0;

	PE32_EnumSections(hMod, PE32_IsRVAPointToSection, &FileOffsetRVA);
	return FileOffsetRVA.dwFileOffset;
}