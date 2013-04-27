
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


