/**
 * \file PEUtils.h
 * \brief Utility functions to walk through a PE in memory
 * \author Tomtombinary
 * \version 1.0
 * \date 18 août 2018
 */

#pragma once
#include "stdafx.h"


#define DUMP_FIELD(FieldName,Struct) \
	printf("%s: %x\n",#FieldName,Struct->FieldName)

/**
 * \brief each sections found in PE Header is represented by this structure
 * SectionData points to section in memory
 * SectionLimit points to the section end in memory
 */
typedef struct _SECTION_ENTRY
{
	PIMAGE_SECTION_HEADER header;
	PBYTE SectionData;
	DWORD SectionLimit;
}SECTION_ENTRY,*PSECTION_ENTRY;

/**
 * \struct EXPORT_ENTRY
 * \brief each export found in export table is represented by this structure 
 */
typedef struct _EXPORT_ENTRY
{
	WORD Ordinal;
	DWORD RVAAddress;
	DWORD RVAName;
	LPCSTR Name;
	PVOID pFunction;
}EXPORT_ENTRY,*PEXPORT_ENTRY;

/**
 * \struct IMPORT_ENTRY
 * \brief each import found in import table is represented by this structure
 * Thunk conatains the address of imported function.
 * pImportDesc describe the Dll associated with the import.
 */
typedef struct _IMPORT_ENTRY
{
	IMAGE_THUNK_DATA32 Thunk;
	PIMAGE_IMPORT_BY_NAME pImportByName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
}IMPORT_ENTRY,*PIMPORT_ENTRY;

/**
 * Callback function type for PE32_EnumSections
 */
typedef BOOL(*EnumSectionsCallback)(PSECTION_ENTRY lpSectionEntry, LPVOID UserArgs);
/**
 * Callback function type for PE32_EnumExportsCallback 
 */
typedef BOOL(*EnumExportsCallback)(PEXPORT_ENTRY lpExportEntry, LPVOID UserArgs);
/**
 * Callback function type for PE32_EnumImportsCallback
 */
typedef BOOL(*EnumImportsCallback)(PIMPORT_ENTRY lpImportEntry, LPVOID UserArgs);

/**
 * \fn PIMAGE_NT_HEADERS32 PE32_GetNtHeaders(HMODULE hMod);
 * \brief obtains address of PE Header in memory from a DOS Header
 * \param hMod: module image base
 * \return the PE Header address. NULL if PE Header has invalid signature or is not a 32 bits header
 */
PIMAGE_NT_HEADERS32 PE32_GetNtHeaders(HMODULE hMod);

/**
 * \fn BOOL PE32_EnumExports(HMODULE hMod, EnumExportsCallback pFuncCallback, LPVOID UserArgs);
 * \brief enumerate exports from a given module image base
 * \param hMod: module image base
 * \param pFuncCallback: callback function called for each exports
 * \param UserArgs: [optional] extras arguments for callback function 
 * \return TRUE if all exports have been enumerated
 */
BOOL PE32_EnumExports(HMODULE hMod, EnumExportsCallback pFuncCallback, LPVOID UserArgs);

/**
 * \fn BOOL PE32_EnumImports(HMODULE hMod, EnumImportsCallback pFunCallback, LPVOID UserArgs);
 * \brief enumerate exports from a given module image base
 * \param hMod: module image base
 * \param pFuncCallback: callback function called for each imports
 * \param UserArgs: [optional] extras arguments for callback function
 * \return TRUE if all imports have been enumerated
 */
BOOL PE32_EnumImports(HMODULE hMod, EnumImportsCallback pFunCallback, LPVOID UserArgs);

/**
 * \fn BOOL PE32_EnumSections(HMODULE hMod, EnumSectionsCallback pFuncCallback, LPVOID lpUserArgs);
 * \brief enumerate sections from a given module image base
 * \param hMod: module image base
 * \param pFuncCallback: callback function called for each sections
 * \param UserArgs: [optional] extras arguments for callback function
 * \return TRUE if all sections have been enumerated
 */
BOOL PE32_EnumSections(HMODULE hMod, EnumSectionsCallback pFuncCallback, LPVOID lpUserArgs);