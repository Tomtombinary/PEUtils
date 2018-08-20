/**
 * \file MemUtils.h
 * \brief Utility functions to walk through PEB
 * \author Tomtombinary
 * \version 1.0
 * \date 18 août 2018
 */

#pragma once
#include "stdafx.h"
#include <winternl.h>


/**
 * callback prototype for PEBUtils_EnumModules
 */
typedef BOOL(*EnumModulesCallback)(PLDR_DATA_TABLE_ENTRY pLdrDataEntry,LPVOID UserArgs);

/**
 * \fn BOOL PEBUtils_EnumModules(PPEB Peb, EnumModulesCallback Callback, PVOID UserArgs);
 * \brief Enumerate modules in current process
 * \param Callback : callback called for each modules found. Callback must return TRUE to continue enumeration
 * \param UserArgs: [optional] extras arguments for callback function. 
 * \return TRUE if all modules have been enumerated
 */
BOOL PEBUtils_EnumModules(EnumModulesCallback Callback, PVOID UserArgs);

/**
 * \fn BOOL MemIsNull(LPVOID Buffer, DWORD SizeInBytes);
 * \brief Check if a memory zone is null
 * \param Buffer: pointer to a buffer
 * \param SizeInBytes: buffer size in bytes
 * \return TRUE if memory is filled with zeros
 */
BOOL MemIsNull(LPVOID Buffer, DWORD SizeInBytes);
