/**
 * \file PEUtils.h
 * \brief Utility functions to browse a PE in memory
 * \author Tomtombinary
 * \version 1.0
 * \date 18 août 2018
 */

#pragma once
#include "stdafx.h"


#define DUMP_FIELD(FieldName,Struct) \
	printf("%s: %x\n",#FieldName,Struct->FieldName)

/** 
 * \brief each relocation in PE header is represented by this structure
 * BaseRelocationBlock: pointer to associated IMAGE_BASE_RELOCATION header
 * Type: type  of relocation (HIGHLOW, ...)
 * Offset: Offset to page VA
 * RelocationVA: Where the base relocation is to be applied
 */
typedef struct _RELOC_ENTRY
{
	PIMAGE_BASE_RELOCATION BaseRelocationBlock;
	BYTE Type;
	WORD Offset;
	DWORD RelocationVA;
}RELOC_ENTRY,*PRELOC_ENTRY;

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
 * \struct _FILE_OFFSET_RVA
 * \brief Utility structure to convert a RVA to a file offset
 * This structure is used internaly by PE32_RVAToFileOffset
 */
typedef struct _FILE_OFFSET_RVA
{
	DWORD dwRVA;
	DWORD dwFileOffset;
}FILE_OFFSET_RVA, *PFILE_OFFSET_RVA;


/**
 * \struct _SEARCH_RELOC
 * \brief Utility structure to search a relocation by RVA
 * This structure is useful for PE32_SearchRelocation
 */
typedef struct _SEARCH_RELOC
{
	DWORD RVA;
	BYTE Type;
	WORD Offset;
	DWORD RelocationVA;
	IMAGE_BASE_RELOCATION BaseRelocationBlock;
}RELOC_SEARCH,*PRELOC_SEARCH;

/**
 * Callback function type for PE32_EnumSections
 */
typedef BOOL(*EnumSectionsCallback)(PSECTION_ENTRY lpSectionEntry, LPVOID UserArgs);
/**
 * Callback function type for PE32_EnumExports 
 */
typedef BOOL(*EnumExportsCallback)(PEXPORT_ENTRY lpExportEntry, LPVOID UserArgs);
/**
 * Callback function type for PE32_EnumImports
 */
typedef BOOL(*EnumImportsCallback)(PIMPORT_ENTRY lpImportEntry, LPVOID UserArgs);

/**
 * Callback function type for PE32_EnumRelocations
 */
typedef BOOL(*EnumRelocationsCallback)(PRELOC_ENTRY lpRelocEntry, LPVOID UserArgs);

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

/**
 * \fn PE32_EnumRelocations(HMODULE hMod, EnumRelocationsCallback pFuncCallback, LPVOID lpUserArgs);
 * \brief enumerate relocations from a given module image base
 * \param hMod: module image base
 * \param pFuncCallback: callback function called for each relocations base
 * \param UserArgs: [optional] extras arguments for callback function
 * \return TRUE if all relocations have been enumerated
 */
BOOL PE32_EnumRelocations(HMODULE hMod, EnumRelocationsCallback pFuncCallback, LPVOID lpUserArgs);

/**
 * \fn DWORD PE32_RVAToFileOffset(HMODULE hMod, DWORD dwRVA);
 * \brief convert a relative virtual address to a file offset
 * \param hMod: module image base
 * \param dwRVA: relative virtual address from module image base
 * \return module file offset
 */
DWORD PE32_RVAToFileOffset(HMODULE hMod, DWORD dwRVA);

/**
 * \fn BOOL PE32_IsRVAPointToSection(PSECTION_ENTRY entry, LPVOID lpUserArgs);
 * \brief Callback for PE32_EnumSection to check if a relative virtual address is in a section
 * \param entry section description (returned by PE32_EnumSection)
 * \param lpUserArgs structure to store the file offset
 * \return TRUE to continue to iterate over sections table
 */
BOOL PE32_IsRVAPointToSection(PSECTION_ENTRY entry, LPVOID lpUserArgs);


/**
 * \fn BOOL PE32_CallbackSearchRelocationByRVA(PRELOC_ENTRY Reloc, PRELOC_SEARCH UserArgs);
 * \brief Callback for search a relocation entry by his RVA
 * \param Reloc relocation entry (from PE32_EnumRelocations)
 * \return TRUE to continue to iterate over relocations table
 */
BOOL PE32_CallbackSearchRelocationByRVA(PRELOC_ENTRY Reloc, PRELOC_SEARCH UserArgs);

/** 
 * \fn BOOL PE32_SearchRelocation(HMODULE hMod, PRELOC_SEARCH SearchArgs);
 * \brief Search a relocation by it's RVA
 * \param hMod module image base
 * \param SearchArgs 
 *   - [in] search argument (rva field must be initialized)
 *   - [out] search result
 * \return FALSE if relocation couldn't be found
 */
BOOL PE32_SearchRelocation(HMODULE hMod, PRELOC_SEARCH SearchArgs);