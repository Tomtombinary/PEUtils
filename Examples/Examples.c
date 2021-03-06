/**
 * \file Examples.c
 * \brief Console example program
 * \author Tomtombinary
 * \version 1.0
 * \date 20 août 2018
 * Program enumerates:
 *    - loaded modules in current EXE
 *    - sections in current EXE
 *    - exported functions in current EXE
 *    - imported functions in current EXE
 */

#include <Windows.h>
#include <stdio.h>
#include "PEUtils.h"
#include "MemUtils.h"

BOOL CallbackPrintSections(PSECTION_ENTRY section,PVOID UserArgs)
{
	printf("%s:\n", section->header->Name);
	printf("\t- VirtualSize : %x\n", section->header->Misc.VirtualSize);
	printf("\t- VirtualAddress: %x\n", section->header->VirtualAddress);
	printf("\t- Memory Zone : %p - %x\n",section->SectionData,section->SectionLimit);
	return TRUE;
}

BOOL CallbackPrintExports(PEXPORT_ENTRY Entry, PVOID UserArgs)
{
	printf("Name: %s\n", Entry->Name);
	printf("\t- Ordinal: %d\n",Entry->Ordinal);
	printf("\t- RVAName: %x\n", Entry->RVAName);
	printf("\t- RVAFunction: %x\n", Entry->RVAFunction);
	printf("\t- Function: %p\n", Entry->pFunction);
	return TRUE;
}

BOOL CallbackPrintImports(PIMPORT_ENTRY Entry, PVOID UserArgs)
{
	printf("%s:\n", Entry->pImportByName->Name);
	printf("\t- Hint : %d\n", Entry->pImportByName->Hint);
	printf("\t- Address : %x\n", Entry->Thunk.u1.Function);
	return TRUE;
}

BOOL CallbackPrintModules(PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry, PVOID UserArgs)
{
	wprintf(L"%ws:\n",pLdrDataTableEntry->FullDllName.Buffer);
	printf("\t-DllBase: %p\n", pLdrDataTableEntry->DllBase);
	return TRUE;
}

BOOL CallbackPrintReloc(PRELOC_ENTRY Entry, PVOID UserArgs)
{
	printf("\t- Type:%d, Offset:0x%08.8x,VA:0x%08.8x\n",Entry->Type,Entry->Offset,Entry->RelocationVA);
	return TRUE;
}

__declspec(dllexport) VOID ExportedFunc()
{
	printf("This function is exported\n");
}

int main(int argc,char** argv)
{
	HMODULE Current = GetModuleHandle(NULL);

	printf("Enumerates modules:\n");
	PEBUtils_EnumModules(CallbackPrintModules, NULL);

	printf("Enumerates sections:\n");
	PE32_EnumSections(Current, CallbackPrintSections, NULL);
	
	printf("Enumerates exports:\n");
	PE32_EnumExports(Current, CallbackPrintExports, NULL);
	
	printf("Enumerates imports:\n");
	PE32_EnumImports(Current, CallbackPrintImports, NULL);

	printf("Enumerates relocations:\n");
	PE32_EnumRelocations(Current,CallbackPrintReloc,NULL);

	return 0;
}
