#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

class DmpParser {
private:
	DWORD m_dwTimeStamp;
	DWORD m_dwSizeofImage;
	DWORD m_dwChecksum;
public:
	int CheckPEFileFormat(TCHAR *lpExePath);
	int CheckDumpFileFormat(TCHAR *lpDumpFilePath);
};
#pragma pack(1)
typedef struct {
	DWORD magic;      //0x00
	DWORD unKnown1;   //0x04
	DWORD unKnown2;   //0x08
	DWORD m_dwStruct2Offset;   //0x0C
}HEADER_DUMP;
typedef struct {
	DWORD m_dwIndex;
	DWORD unKnown1;
	DWORD m_dwStruct3Offset;
}DMP_STRUCT2;
typedef struct {
	BYTE m_szUnknow1[0x08];
	DWORD m_dwSizeofImage; //0x08
	DWORD m_dwChecksum;    //0x0c
	DWORD m_dwTimeStamp;   //0x10
	BYTE m_szUnknow2[0x58];
}DMP_STRUCT4;
typedef struct {
	DWORD m_dwTableCount;
	DMP_STRUCT4 m_szTable[];
}DMP_STRUCT3;

#pragma pack()

int DmpParser::CheckPEFileFormat(TCHAR *lpExePath)
{
	int ret = 1;
	IMAGE_DOS_HEADER *lpDosHeader = NULL;
	LPVOID lpFileMap = NULL;
	HANDLE hMap = INVALID_HANDLE_VALUE;
	HANDLE hFile = CreateFile(lpExePath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto FINAL_RET;
	}
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == INVALID_HANDLE_VALUE)
	{
		goto CLOSEFILE_RET;
	}
	lpFileMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (lpFileMap == NULL)
	{
		goto CLOSEMAPPING_RET;
	}

	ret = 2;
	try {
		lpDosHeader = (PIMAGE_DOS_HEADER)lpFileMap;
		if (lpDosHeader->e_magic == 0x5A4D)
		{
			PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)((char *)lpFileMap + lpDosHeader->e_lfanew);
			if (lpNtHeader->Signature == 0x4550)
			{
				if (lpNtHeader->OptionalHeader.Magic == 0x10B || lpNtHeader->OptionalHeader.Magic == 0x20B)
				{
					m_dwTimeStamp = lpNtHeader->FileHeader.TimeDateStamp;
					m_dwSizeofImage = lpNtHeader->OptionalHeader.SizeOfImage;
					m_dwChecksum = lpNtHeader->OptionalHeader.CheckSum;
					ret = 0;
				}
			}
		}
	}
	catch (...) {
		ret = 2;
	}
	

	UnmapViewOfFile(lpFileMap);

CLOSEMAPPING_RET:
	CloseHandle(hMap);

CLOSEFILE_RET:
	CloseHandle(hFile);

FINAL_RET:
	return ret;
}

int DmpParser::CheckDumpFileFormat(TCHAR *lpDumpFilePath)
{
	int ret = 1;
	HANDLE hMap = INVALID_HANDLE_VALUE;
	LPVOID lpFileMap = NULL;
	HEADER_DUMP *header = NULL;
	BYTE *lpBase = NULL;
	HANDLE hFile = CreateFile(lpDumpFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto FINAL_RET;
	}
	hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hMap == INVALID_HANDLE_VALUE)
	{
		goto CLOSEFILE_RET;
	}
	lpFileMap = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
	if (lpFileMap == NULL)
	{
		goto CLOSEMAPPING_RET;
	}

	ret = 2;
	try {
		header = (HEADER_DUMP *)lpFileMap;
		lpBase = (BYTE *)lpFileMap;
		if (header->magic == 0x504D444D)
		{
			ret = 3;
			DMP_STRUCT2 * lpDmpStruct2 = (DMP_STRUCT2 *)(lpBase + header->m_dwStruct2Offset);
		
			for (DWORD i = 0; i < header->unKnown2; i++, lpDmpStruct2++)
			{
				if (lpDmpStruct2->m_dwIndex == 4)
				{
					DWORD dwOffset = lpDmpStruct2->m_dwStruct3Offset;
					DMP_STRUCT3 *lpDmpStruct3 = (DMP_STRUCT3 *)(lpBase + dwOffset);
					for (DWORD j = 0; j < lpDmpStruct3->m_dwTableCount; j++)
					{
	//					BYTE *lpEax =(BYTE *) (lpDmpStruct3 + 4 + j * 0x6c);
	//					DWORD dwEBX = *(DWORD *)(lpEax + 0x10);
						DMP_STRUCT4 *lpStruct4 = lpDmpStruct3->m_szTable + j;
						if (lpStruct4->m_dwTimeStamp == m_dwTimeStamp)
						{
	//						*(DWORD *)(lpEax + 0x08) = m_dwSizeofImage;
	//						*(DWORD *)(lpEax + 0x0c) = m_dwChecksum;
							lpStruct4->m_dwSizeofImage = m_dwSizeofImage;
							lpStruct4->m_dwChecksum = m_dwChecksum;
							ret = 0;
						}
					}
				}

			}
		}

		if (ret == 0)
		{
			FlushViewOfFile(lpFileMap, 0);
		}
	}
	catch (...) {
		ret = 2;
	}
	UnmapViewOfFile(lpFileMap);
CLOSEMAPPING_RET:
	CloseHandle(hMap);
	 
CLOSEFILE_RET:
	CloseHandle(hFile);

FINAL_RET:
	return ret;
}

int wmain(int argc, TCHAR *argv[])
{
	DmpParser dump;
	wprintf(L"MiniDump Fixer v 1.0 Copyright 2003-2015 VMProtect Software\n");
	if (argc < 3) {
		wprintf(L"Usage: %s dmp_file exe_file\n", PathFindFileName(argv[0]));
		return 1;
	}

	if (wcslen(argv[1]) == 0)
	{
		wprintf(L"Crash dump file does not specified.");
		return 1;
	}

	if (wcslen(argv[2]) == 0)
	{
		wprintf(L"Executable file does not specified.");
		return 1;
	}
	int ret = dump.CheckPEFileFormat(argv[2]);
	switch (ret) {
	case 1:
		wprintf(L"Can not open \"%s\".", argv[2]);
		return 1;
	case 2:
		wprintf(L"File \"%s\" has an incorrect format.", argv[2]);
		return 1;
	}

	ret = dump.CheckDumpFileFormat(argv[1]);
	switch (ret) {
	case 1:
		wprintf(L"Can not open \"%s\".", argv[1]);
		return 1;
	case 2:
		wprintf(L"File \"%s\" has an incorrect format.", argv[2]);
		return 1;
	case 3:
		wprintf(L"Module \"%s\" not found in the DMP file.", PathFindFileName(argv[2]));
		return 1;
	}
	wprintf(L"DMP file sucessfully updated.");
	return 0;
}