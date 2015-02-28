// DebugInfo.cpp : Defines the entry point for the console application.
// Original work:
// DebugDir.cpp : Defines the entry point for the console application.
////////////////////////////////////////////////////////////////////////
// work by Oleg Starodumov (http://www.debuginfo.com) in his example code titled "DebugDir example".
//
// Background:
// The build tool that is delivered with the DDK manages to build all  of my .sys files, 
//in such a way that they contain the full path to the debug
// symbols. For example, if you open your compiled (release mode / free build)
// driver with a tool like BinText, one of the text strings present in  the
// binary may be  "C:\my_company\my_project_name\obj_fre_x86\my_driv er_name.pdb"
//
// You might not want to be leaking sensitive information into every  driver you
// build. I looked into various ways to try to not have this happen. 
//
// Some suggested that I use the rebase.exe tool (provided in the  Microsoft
// SDK, etc) to "strip debug information." The truth is, this tool used  to work
// for that purpose back when they used an older (pre-Visual Studio  6-era)
// compiler that compiled in the debug information differently. I tried  it
// though, and it had no effect on this PDB pathname string. 
//
// BinPlace tool (a Microsoft DDK tool): again, I could find no way to  use this
// tool for this purpose, although it was a promising option for a  little while.
//
// Build utility macros in the SOURCES file: also a dead end, as macros  like
// USE_PDB are now obsolete and are ignored. 
//
// Compiler and linker options: I was not able to find anything here,  but one
// thing I didn't try is to tell the compiler to use old-style debug  info (for
// an explanation go here  http://www.debuginfo.com/articles/gendebuginfo.html),
// and then try to strip it out later with the rebase tool. This might  work if
// you want to go that route.
//
// Final decision: I decided to write a tool that would strip this text string
// from the compiled binary. I run it after my build process completes  (add it
// into your makefile or make it part of the build process in Visual Studio if
// you want). The PDB pathname string is located in a predictable location that
// you can programatically locate by walking the PE headers of the executable.
// For more information, there is a great article at 
// http://www.debuginfo.com/articles/debuginfomatch.html
// and source code I used at 
// http://www.debuginfo.com/examples/debugdir.html // 
//
// Vaibhav Gaikwad - additions
// 1. Added default debug path printing
// 2. Added 'clean' argument to clean whole path from debug dir
// 3. Addded 'clean-path' argument to clean just the full path info. and retain file name of PDB
// 4. Optimizations over printing to console + usage description
// 5. File exists check added
#include <windows.h>
#include <tchar.h>
#include <imagehlp.h>
#include <crtdbg.h>
#include <stdio.h>
#include <limits.h>
#include <string>

using namespace std;
// MakePtr is a macro that allows you to easily add to values (including
 // pointers) together without dealing with C's pointer arithmetic. It
 // essentially treats the last two parameters as DWORDs. The first
 // parameter is used to typecast the result to the appropriate pointer type.
 #define MakePtr(cast, ptr, addValue) (cast)((DWORD)(ptr) + (DWORD)(addValue))
 

///////////////////////////////////////////////////////////////////////////////
 // CodeView debug information structures
 //
 #define CV_SIGNATURE_NB10 '01BN' //This is little endian byte order,
 #define CV_SIGNATURE_RSDS 'SDSR' //because we'll read them in as DWORDs.
 
// CodeView header
 struct CV_HEADER
 {
	 DWORD CvSignature; // NBxx
	 LONG Offset; // Always 0 for NB10
 };
 
// CodeView NB10 debug information
 // (used when debug information is stored in a PDB 2.00 file)
 struct CV_INFO_PDB20
 {
	 CV_HEADER Header;
	 DWORD Signature; // seconds since 01.01.1970
	 DWORD Age; // an always-incrementing value
	 BYTE PdbFileName[1]; // zero terminated string with the name of the PDB file
 };
 
// CodeView RSDS debug information
 // (used when debug information is stored in a PDB 7.00 file)
 struct CV_INFO_PDB70
 {
	 DWORD CvSignature;
	 GUID Signature; // unique identifier
	 DWORD Age; // an always-incrementing value
	 BYTE PdbFileName[1]; // zero terminated string with the name of the PDB file
 };
 

 LPCTSTR ProcessCmdLine(int argc, TCHAR* argv[]);
 bool CheckDosHeader(PIMAGE_DOS_HEADER pDosHeader);
 bool CheckNtHeaders(PIMAGE_NT_HEADERS pNtHeaders);
 bool CheckSectionHeaders(PIMAGE_NT_HEADERS pNtHeaders);
 bool CheckDebugDirectory(PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize);
 bool IsPE32Plus(PIMAGE_OPTIONAL_HEADER pOptionalHeader, bool& bPE32Plus);
 bool GetDebugDirectoryRVA(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD& DebugDirRva, DWORD& DebugDirSize);
 bool GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset);
 void CleanDebugDirectoryEntries(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize, bool clean, bool cleanPath);
 void CleanDebugDirectoryEntry(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, bool clean, bool cleanPath);
 void CleanCodeViewDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize, bool clean, bool cleanPath);
 char* GetFileName(char* filepath);
 void Print(char* message);
 void Print(std::string message);
char* GuidToString(GUID guid);
///////////////////////////////////////////////////////////////////////////////
//
// Process command line and display usage information, if necessary
//
// Return value: If command line parameters are correct, the function
// returns a pointer to the file name specified by the user.
// If command line parameters are incorrect, the function returns  null.
//
 LPCTSTR ProcessCmdLine(int argc, TCHAR* argv[])
 {
	 if(argc < 2)
	 {
		_tprintf(_T("Usage: %s FileName(.dll|.exe) [clean|clean-path] \n clean: clears whole pdb path information \n clean-path: clears the pdb path and retains the filename."), argv[0]);
		return 0;
	 }	 
	 return argv[1];
 }

 //VG: 
  LPCTSTR GetCmd(int argc, TCHAR* argv[])
 {
	 if(argc < 2)
	 {
		_tprintf(_T("Usage: %s FileName(.dll|.exe) [clean|clean-path] \n clean: clears whole pdb path information \n clean-path: clears the pdb path and retains the filename."), argv[0]);
		return 0;
	 }
	 if(argc == 3)
	 {
		return argv[2];
	 }else	
	 {
		return NULL;
	 }
	 
 }

///////////////////////////////////////////////////////////////////////////////
// main
//
 int _tmain(int argc, TCHAR* argv[])
 {
	 bool clean = false;
	 bool cleanPath = false;
	 LPCTSTR cleanCmd = _T("clean");
	 LPCTSTR cleanPathCmd = _T("clean-path");	 
	// Process the command line and obtain the file name
	LPCTSTR FileName = ProcessCmdLine(argc, argv);
	if(FileName == 0)
		return 0;
	
	DWORD fileWord = GetFileAttributes(FileName);
	if(fileWord == 0)
	{
		_tprintf(_T("Error: Cannot open the file. Error code: %u \n"), GetLastError());
		return 0;
	}
	LPCTSTR option = GetCmd(argc, argv);
	if(option != NULL)
	{
		int cmp = lstrcmp(option,cleanCmd);
		int cmp1 = lstrcmp(option,cleanPathCmd);
		if(cmp == 0)
		{
			clean = true;
		}
		else if(cmp1 == 0)
		{
			cleanPath = true;
		}
	}
	
 
	// Process the file
	HANDLE hFile = NULL;
	HANDLE hFileMap = NULL;
	LPVOID lpFileMem = 0;
	unsigned long ulFileSize = 0;
 	//Recalculate the checksum for the file now:
	DWORD dwCurrentChecksum;
	DWORD dwNewChecksum;
	// Look up the debug directory:
	DWORD DebugDirRva = 0;
	DWORD DebugDirSize = 0;
	
	do
	 {
		 // Open the file and map it into memory:
		 hFile = CreateFile(FileName, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		 if((hFile == INVALID_HANDLE_VALUE) || (hFile == NULL))
		 {
			 _tprintf(_T("Error: Cannot open the file. Error code: %u \n"), GetLastError());
			 break;
		 }
		ulFileSize = GetFileSize(hFile,NULL);
 
		hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
		if(hFileMap == NULL)
		{
			_tprintf(_T("Error: Cannot open the file mapping object. Error code: %u \n"), GetLastError());
			break;
		}
 
		lpFileMem = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);
		if(lpFileMem == 0)
		{
			_tprintf(_T("Error: Cannot map the file. Error code: %u \n"),
			GetLastError());
			break;
		}
 
		// Is it a valid PE executable?
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileMem;
		if(!CheckDosHeader(pDosHeader))
		{
			_tprintf(_T("Error: File is not a PE executable.\n"));
			break;
		}
 
		PIMAGE_NT_HEADERS pNtHeaders = MakePtr(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
		if(!CheckNtHeaders(pNtHeaders))
		{
			_tprintf(_T("Error: File is not a PE executable.\n"));
			break;
		}
 
		if(!CheckSectionHeaders(pNtHeaders))
		{
			_tprintf(_T("Error: File is not a PE executable.\n"));
			break;
		}
 
		
		if(!GetDebugDirectoryRVA(&pNtHeaders->OptionalHeader, DebugDirRva, DebugDirSize))
		{
			_tprintf(_T("Error: File is not a PE executable.\n"));
			break;
		}
 
		if((DebugDirRva == 0) || (DebugDirSize == 0))
		{
			_tprintf(_T("Debug directory not found.\n"));
			break;
		}
 
		DWORD DebugDirOffset = 0;
		if(!GetFileOffsetFromRVA(pNtHeaders, DebugDirRva, DebugDirOffset))
		{
			_tprintf(_T("Debug directory not found.\n"));
			break;
		}
 
		PIMAGE_DEBUG_DIRECTORY pDebugDir = MakePtr(PIMAGE_DEBUG_DIRECTORY, lpFileMem, DebugDirOffset);
		if(!CheckDebugDirectory(pDebugDir, DebugDirSize))
		{
			_tprintf( _T("Error: Debug directory is not valid.\n") );
			break;
		}
 
		// Sanitize information in every entry in the debug directory:
		CleanDebugDirectoryEntries((LPBYTE)lpFileMem, pDebugDir, DebugDirSize, clean, cleanPath);
 
		if(clean || cleanPath)
		{
			if(!CheckSumMappedFile(lpFileMem, ulFileSize, &dwCurrentChecksum, &dwNewChecksum))
			{
				_tprintf(_T("Error: Cannot recalculate checksum for mapped file. Error code: %u \n"), GetLastError()); _ASSERT(0); 
			}
			pNtHeaders->OptionalHeader.CheckSum = dwNewChecksum;
		}
		
	}
	while(0); //do-while(0) with a "break" just a way to avoid using "goto"
 
	// Cleanup:
	if(lpFileMem != 0)
	{ 
		//Write out the memory-mapped file's buffer back to its file:
		if(FlushViewOfFile(lpFileMem,0) == 0)
		{
		_tprintf(_T("Error: Cannot write memory-mapped file back to disk. Error code: %u \n"), GetLastError());
		_ASSERT(0);
		}
 
		if(!UnmapViewOfFile(lpFileMem))
		{
			_tprintf(_T("Error: Cannot unmap the file. Error code: %u \n"), GetLastError());
			_ASSERT(0);
		}	
	}
 
	if(hFileMap != NULL)
	{
		if(!CloseHandle(hFileMap))
		{
			_tprintf(_T("Error: Cannot close the file mapping object. Error	code: %u \n"), GetLastError());
			_ASSERT(0);
		}
	}
 
	if((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
	{
		if(!CloseHandle(hFile))
		{
			_tprintf(_T("Error: Cannot close the file. Error code: %u \n"),	GetLastError());
			_ASSERT(0);
		}
	}
 
// Complete
 return 0;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Check IMAGE_DOS_HEADER and determine whether the file is a PE executable
// (according to the header contents)
//
// Return value: "true" if the header is valid and the file is a PE executable,
// "false" otherwise
//
 bool CheckDosHeader(PIMAGE_DOS_HEADER pDosHeader)
 {
 // Check whether the header is valid and belongs to a PE executable
	 if(pDosHeader == 0)
	 {
		 _ASSERT(0);
		 return false;
	 }
 
	if(IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)))
	{
		// Invalid header
		return false; 
	} 
	if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		// Not a PE executable
		return false;
	}
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Check IMAGE_NT_HEADERS and determine whether the file is a PE executable
// (according to the headers' contents)
//
// Return value: "true" if the headers are valid and the file is a PE executable,
// "false" otherwise
//
 bool CheckNtHeaders(PIMAGE_NT_HEADERS pNtHeaders)
 {
	 // Check the signature
	 if(pNtHeaders == 0)
	 {
		 _ASSERT(0);
		 return false; 
	 }
	 if(IsBadReadPtr(pNtHeaders, sizeof(pNtHeaders->Signature)))
	 {
		 // Invalid header
		 return false; 
	 }
	 if(pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	 {
		 // Not a PE executable
		 return false;
	 }
	 // Check the file header
	 if(IsBadReadPtr(&pNtHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER)))
	 {
		 // Invalid header
		 return false; 
	 } 
	 if(IsBadReadPtr(&pNtHeaders->OptionalHeader, pNtHeaders->FileHeader.SizeOfOptionalHeader))
	 {
		 // Invalid size of the optional header
		 return false;
	 }
 
	// Determine the format of the header
	// If true, PE32+, otherwise PE32
	bool bPE32Plus = false; 
	if(!IsPE32Plus(&pNtHeaders->OptionalHeader, bPE32Plus))
	{
		// Probably invalid IMAGE_OPTIONAL_HEADER.Magic
		return false;
	}
 
	// Complete
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Lookup the section headers and check whether they are valid
//
// Return value: "true" if the headers are valid, "false" otherwise
//
 bool CheckSectionHeaders(PIMAGE_NT_HEADERS pNtHeaders)
 {
	 if(pNtHeaders == 0)
	 {
		_ASSERT(0);
		return false;
	 }
 
	PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders); 
	if(IsBadReadPtr(pSectionHeaders, pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)))
	{
		// Invalid header
		return false;
	}
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Checks whether the debug directory is valid
//
// Return value: "true" if the debug directory is valid, "false" if it  is not
//
 bool CheckDebugDirectory(PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize)
 {
	 if((pDebugDir == 0) || (DebugDirSize == 0))
	 {
		 _ASSERT(0);
		 return false;
	 }
 
	if(IsBadReadPtr(pDebugDir, DebugDirSize))
	{
		// Invalid debug directory
		return false;
	}
 
	if(DebugDirSize < sizeof(IMAGE_DEBUG_DIRECTORY))
	{
		// Invalid size of the debug directory
		return false;
	}
 
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Check whether the specified IMAGE_OPTIONAL_HEADER belongs to
// a PE32 or PE32+ file format
//
// Return value: "true" if succeeded (bPE32Plus contains "true" if the file
// format is PE32+, and "false" if the file format is PE32),
// "false" if failed
//
 bool IsPE32Plus(PIMAGE_OPTIONAL_HEADER pOptionalHeader, bool& bPE32Plus)
 {
	 // Note: The function does not check the header for validity.
	 // It assumes that the caller has performed all the necessary checks.
	 // IMAGE_OPTIONAL_HEADER.Magic field contains the value that allows
	 // to distinguish between PE32 and PE32+ formats 
	if(pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		// PE32
		bPE32Plus = false; 
	}
	else if(pOptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// PE32+
		bPE32Plus = true;
	} 
	else 
	{
		// Unknown value -> Report an error
		bPE32Plus = false;
		return false;
	}
 
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// Returns (in [out] parameters) the RVA and size of the debug directory,
// using the information in
// IMAGE_OPTIONAL_HEADER.DebugDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
//
// Return value: "true" if succeeded, "false" if failed
//
 bool GetDebugDirectoryRVA(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD& DebugDirRva, DWORD& DebugDirSize)
 {
	// Check parameters
	 if(pOptionalHeader == 0)
	 {
		 _ASSERT(0);
		 return false;
	 }
 
	// Determine the format of the PE executable
	 bool bPE32Plus = false;
	 if(!IsPE32Plus(pOptionalHeader, bPE32Plus))
	 {
		 // Probably invalid IMAGE_OPTIONAL_HEADER.Magic
		 return false;
	 }
 
	// Obtain the debug directory RVA and size
	 if(bPE32Plus)
	 {
		 PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)pOptionalHeader; 
		 DebugDirRva = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		 DebugDirSize = pOptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	 }
	 else
	 {
		 PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)pOptionalHeader; 
		 DebugDirRva = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		 DebugDirSize = pOptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	 }
	 
	 if((DebugDirRva == 0) && (DebugDirSize == 0)) 
	 {
		 // No debug directory in the executable -> no debug information
		 return true;
	 }
	else if((DebugDirRva == 0) || (DebugDirSize == 0))
	{
		// Inconsistent data in the data directory
		return false;
	}
 
	// Complete
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
//
// The function walks through the section headers, finds out the section
// the given RVA belongs to, and uses the section header to determine
// the file offset that corresponds to the given RVA
//
// Return value: "true" if succeeded, "false" if failed
//
 bool GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset)
 {
	 // Check parameters
	 if(pNtHeaders == 0)
	 {
		 _ASSERT(0);
		 return false;
	 }
 
	// Look up the section the RVA belongs to:
	bool bFound = false;
 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders); 
	for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) 
	{
		DWORD SectionSize = pSectionHeader->Misc.VirtualSize;
		
		if(SectionSize == 0) // compensate for Watcom linker strangeness, according to Matt Pietrek
			pSectionHeader->SizeOfRawData; 
		if((Rva >= pSectionHeader->VirtualAddress) && (Rva < pSectionHeader->VirtualAddress + SectionSize))
		{
			// Yes, the RVA belongs to this section
			bFound = true;
			break;
		}
	}
	
	if(!bFound)
	{
		// Section not found
		return false;
	}
	
	// Look up the file offset using the section header
	INT Diff = (INT)(pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData);
	
	FileOffset = Rva - Diff;
	// Complete
	return true;
 }
 

///////////////////////////////////////////////////////////////////////////////
 //
 // Walk through each entry in the debug directory and clean out the PDB
 // string info it may contain.
 //
 void CleanDebugDirectoryEntries(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, DWORD DebugDirSize, bool clean, bool cleanPath)
 {
	 // Check parameters
	 if(!CheckDebugDirectory(pDebugDir, DebugDirSize))
	 {
		_ASSERT(0);
		return;
	 }
 
	if(pImageBase == 0)
	 {
		_ASSERT(0);
		return;
	 }
 
	// Determine the number of entries in the debug directory
	 int NumEntries = DebugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY);
 
	if(NumEntries == 0)
	 {
		_ASSERT(0);
		return;
	 }
 
	// Find information about every entry
	 for(int i = 1; i <= NumEntries; i++, pDebugDir++)
	 {
		CleanDebugDirectoryEntry(pImageBase, pDebugDir, clean, cleanPath);
	 }
 }
 

///////////////////////////////////////////////////////////////////////////////
 //
 // Find the PDB string info in the debug directory entry and delete it.
 //
 void CleanDebugDirectoryEntry(LPBYTE pImageBase, PIMAGE_DEBUG_DIRECTORY pDebugDir, bool clean, bool cleanPath)
 {
	 // Check parameters:
	 if(pDebugDir == 0)
	 {
		_ASSERT(0);
		return;
	 }
 
	if(pImageBase == 0)
	 {
		_ASSERT(0);
		return; 
	} 
	LPBYTE pDebugInfo = pImageBase + pDebugDir->PointerToRawData; 
	if(pDebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW) 
	{
		CleanCodeViewDebugInfo(pDebugInfo, pDebugDir->SizeOfData, clean, cleanPath);
	}
 }
 

///////////////////////////////////////////////////////////////////////////////
 //
 // Find the PDB string info in the CodeView debug information block and  delete
 // it.
 //
 void CleanCodeViewDebugInfo(LPBYTE pDebugInfo, DWORD DebugInfoSize, bool clean, bool cleanPath)
 {
	 // Check parameters
	 if((pDebugInfo == 0) || (DebugInfoSize == 0))
		return;
 
	if(IsBadReadPtr(pDebugInfo, DebugInfoSize))
		return;
 
	if(DebugInfoSize < sizeof(DWORD)) // size of the signature
		return;
 
	DWORD CvSignature = *(DWORD*)pDebugInfo;
 
	// Determine the format of the information:
	 if(CvSignature == CV_SIGNATURE_NB10)
	 {
		 // NB10 signature indicates format PDB 2.00
		 CV_INFO_PDB20* pCvInfo = (CV_INFO_PDB20*)pDebugInfo;
 
		if(IsBadReadPtr(pCvInfo, sizeof(CV_INFO_PDB20))) return; 
		if(IsBadStringPtrA((CHAR*)pCvInfo->PdbFileName, UINT_MAX))
		 return;
 
		//Overwrite the entire string with zeroes:
		 char* szPdbFileName = (char*)(pCvInfo->PdbFileName);
		 char* pdbFile = GetFileName(szPdbFileName);
		  int cmp = strcmp(szPdbFileName, pdbFile);
		 if(!clean && !cleanPath)
		 {
			//list and return
			// _tprintf(_T("Debug file: %s \n"), szPdbFileName);
			 char buffer [33];
			  std::string str;
			  str.append("Debug file ID: ").append(itoa(pCvInfo->Signature,buffer,10)).append("\n");
			 str.append("Debug file Path: ").append(szPdbFileName);
			 Print(str);
			 return;
		 }
		 if(cmp == 0 && cleanPath)
			 return;
		  //_tprintf(_T("Debug file: %s \n"), szPdbFileName);
		  char buffer [33];
			  std::string str;
			  str.append("Debug file ID: ").append(itoa(pCvInfo->Signature,buffer,10)).append("\n");
			 str.append("Debug file Path: ").append(szPdbFileName);
			 Print(str);
		 if(clean)
		 {
			int iLength = strlen(szPdbFileName);
			for(int i=0; i < iLength; i++) 
			{
				pCvInfo->PdbFileName[i] = 0x00;
			}
		 }
		 else if(cleanPath)
		 {
			int iLength = strlen(pdbFile);
			int j = 0;
			for(int i=0; i < iLength; i++) 
			{
				j = i;
				pCvInfo->PdbFileName[i] = pdbFile[i];
			}
			pCvInfo->PdbFileName[j+1] = '\0'; // null termination
		 }
	 }
	 else if(CvSignature == CV_SIGNATURE_RSDS)
	 {
		 // RSDS signature indicates format PDB 7.00
		 CV_INFO_PDB70* pCvInfo = (CV_INFO_PDB70*)pDebugInfo;
 
		if(IsBadReadPtr(pCvInfo, sizeof(CV_INFO_PDB70))) return; 
		if(IsBadStringPtrA((CHAR*)pCvInfo->PdbFileName, UINT_MAX))
		 return;
 
		//Overwrite the entire string with zeroes:
		 char* szPdbFileName = (char*)(pCvInfo->PdbFileName);
		 char* pdbFile = GetFileName(szPdbFileName);
		 int cmp = strcmp(szPdbFileName, pdbFile);
		 if(!clean && !cleanPath)
		 {
			//list and return
			// _tprintf(_T("Debug file: %s \n"), szPdbFileName);
			 std::string str;
			 str.append("Debug file ID: ").append(GuidToString(pCvInfo->Signature)).append("\n");			 
			 str.append("Debug file Path: ").append(szPdbFileName);
			 Print(str);
			 return;
		 }
		 if(cmp == 0 && cleanPath)
		 {
			 std::string str;
			 str.append("Debug file ID: ").append(GuidToString(pCvInfo->Signature)).append("\n");			 
			 str.append("Debug file Path: ").append(szPdbFileName);
			 Print(str);
			 return;
		 }
		  //_tprintf(_T("Debug file: %s \n"), szPdbFileName);		
		 
		 if(clean)
		 {
			int iLength = strlen(szPdbFileName);
			for(int i=0; i < iLength; i++) 
			{
				pCvInfo->PdbFileName[i] = 0x00;
			}
			 std::string str;
			 str.append("Replaced Debug file Path to: ").append((char*)pCvInfo->PdbFileName);
			 Print(str);
		 }
		 else if(cleanPath)
		 {
			int iLength = strlen(pdbFile);
			int j = 0;
			for(int i=0; i < iLength; i++) 
			{
				j = i;
				pCvInfo->PdbFileName[i] = pdbFile[i];
			}
			pCvInfo->PdbFileName[j+1] = '\0'; // null termination
			std::string str;
			str.append("Replaced Debug file Path to: ").append((char*)pCvInfo->PdbFileName);
			Print(str);
		 }
	 }
 }

 void Print(std::string message)
 {
	printf("%s \n",message.c_str());
 }

 void Print(char* message)
 {
	printf("%s \n", message);
 }

 ///////////////////////////////////////////////////////////////////////////////
 //
 // Gets file name from the full path
 //
 char* GetFileName(char* filepath)
 {
	//
	 if(filepath == NULL)
		 return NULL;
	char* f = filepath; //"E:\\vgaikwad\\petrel\\trunk\\code\\Backend\\obj\\Debug\\Generic.Backend.pdb";
	char sep = '\\';
	int h = -1, idx = -1, h1;
	for(h = 0; h< strlen(f); h++)
	{
		if(f[h] == sep)
		{
		   idx = h;
		}
	}
	
	if(idx > -1)
	{
		char* f1= new char[(strlen(f) - idx) ];
		h1 = 0;
		for(h = idx + 1; h< strlen(f); h++, h1++)
		{
			f1[h1] = f[h];
		}
		f1[h1] = '\0'; //null termination
		return f1;	
	}
	else
	{
		return filepath;
	}
	
 }

 char* GuidToString(GUID guid)
  {
	  /*
	OLECHAR* bstrGuid; 
	guid.
	StringFromCLSID(guid, &bstrGuid); 
	CoTaskMemFree(bstrGuid);
	char chars[20];
	wcstombs((CHAR*)&chars, bstrGuid,sizeof(chars));
	return chars; */
	  static char buf[64] = {0};
	  _snprintf(buf,sizeof(buf),"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", 
		  guid.Data1, 
		  guid.Data2, 
		  guid.Data3,
		  guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
	  return buf;
  }
