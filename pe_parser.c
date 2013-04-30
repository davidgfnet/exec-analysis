
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pe_headers.h"

int isPE(unsigned char * pBuffer) {
	return (pBuffer[0] == 0x4d && pBuffer[1] == 0x5a);
}

void * getTextSection(unsigned char * pBuffer, unsigned int * osize) {

	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((char*)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((char*)pNT + sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader);

	int i;
	for (i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
		char * praw = (char*)(pBuffer + pSections[i].PointerToRawData);
		int size = pSections[i].SizeOfRawData;
		
		if (memcmp(pSections[i].Name,".text\0\0\0",8) == 0) {
			void * me = malloc(size);
			memcpy(me,praw,size);
			*osize = size;
			return me;
		}
	}
	return 0;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD_PTR vaddr, PIMAGE_NT_HEADERS pNTHeader) {
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	WORD nSection = 0;

	for(nSection = 0; nSection < pNTHeader->FileHeader.NumberOfSections; nSection++, section++ ) {
		DWORD size = section->Misc.VirtualSize;
		if (size == 0) size = section->SizeOfRawData;

		if ( ((ULONG)vaddr >= section->VirtualAddress) && ((ULONG)vaddr < (section->VirtualAddress + size)) )
			return section;
	}

	return 0;
}

// Matt Pietrek's function
LPVOID GetRawPointerFromVirtualAddr(DWORD_PTR vaddr, PIMAGE_NT_HEADERS pNTHeader, PBYTE imageBase) {

	PIMAGE_SECTION_HEADER section = GetEnclosingSectionHeader(vaddr, pNTHeader);
	if(!section) return 0;

	LONG_PTR delta = (LONG_PTR)( section->VirtualAddress - section->PointerToRawData );
	return (LPVOID)( (ULONG)imageBase + (ULONG)vaddr - (ULONG)delta );
}

void getIAT(unsigned char * pBuffer) {
	PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)((char*)pBuffer + ((PIMAGE_DOS_HEADER)pBuffer)->e_lfanew);
	PIMAGE_SECTION_HEADER pSections = (PIMAGE_SECTION_HEADER)((char*)pNT + sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) + pNT->FileHeader.SizeOfOptionalHeader);

	PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)GetRawPointerFromVirtualAddr(
			(DWORD_PTR)pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
			pNT, (PBYTE)pBuffer);
	LONG size = (pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

	char* lpModuleName = 0;
	while((lpModuleName = (char*)GetRawPointerFromVirtualAddr((DWORD_PTR)pImgImpDesc->Name, pNT, pBuffer))) {
		PIMAGE_THUNK_DATA itd = (PIMAGE_THUNK_DATA)GetRawPointerFromVirtualAddr((DWORD_PTR)pImgImpDesc->FirstThunk, pNT, pBuffer);

		while(itd->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iibn = (PIMAGE_IMPORT_BY_NAME)GetRawPointerFromVirtualAddr((DWORD_PTR)itd->u1.AddressOfData, pNT, pBuffer);
			char * fname = (char*)iibn->Name;
			printf("%s %s\n",lpModuleName,fname);
			itd++;
		}
		pImgImpDesc++;
	}
}

