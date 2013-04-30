
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int isPE(unsigned char * pBuffer);
void * getTextSection(unsigned char * pBuffer, unsigned int * osize);

int main(int argc, char ** argv) {

	if (argc < 3) {
		fprintf(stderr,"Usage: %s executable [options]\n\nOptions:\n\n",argv[0]);
		fprintf(stderr," * dumptext Dumps the text section of the executable to stdout\n");
		fprintf(stderr," * opcodes  Prints opcode histogram\n");
		fprintf(stderr," * printp   Prints the instructions line by line\n");
		exit(0);
	}

	FILE * fd = fopen(argv[1],"rb");
	if (fd == 0) {
		fprintf(stderr,"Could not open %s!\n",argv[1]);
		exit(1);
	}
	fseek(fd,0,SEEK_END);
	int size = ftell(fd);
	fseek(fd,0,SEEK_SET);
	void * bin = malloc(size);
	fread(bin,1,size,fd);
	fclose(fd);
	
	unsigned char * textdata = 0;
	unsigned int textsize = 0;
	if (isPE(bin)) {
		textdata = getTextSection(bin,&textsize);
	}
	if (textdata == 0) {
		fprintf(stderr,"Could not find .text section within the executable!\n");
		exit(1);
	}
	
	// Get opcode statistics
	int i,j;
	if (strcmp(argv[2],"dumptext") == 0) {
		fwrite(textdata,1,size,stdout);
	}
	if (strcmp(argv[2],"opcodes") == 0) {
		unsigned int histo[4096][2];
		memset(histo,~0,sizeof(histo));
		
		int of = 0;
		int icount = 0;
		while (of < textsize) {
			unsigned char opcode;
			int is = disasm(&textdata[of],&opcode);
			if (is == 0) {
				// Try to parse next byte...
				of++;
				continue;
			}
			
			icount++;
			j = -1;
			for (i = 0; i < sizeof(histo)/sizeof(histo[0]); i++) {
				if (histo[i][0] == opcode) {
					histo[i][1]++;
					break;
				}
				else if (histo[i][0] == ~0 && j < 0)
					j = i;
			}
			if (i >= sizeof(histo)/sizeof(histo[0]) && j >= 0) {
				histo[j][0] = opcode;
				histo[j][1] = 1;
			}
			
			if (0) {
				for (i = 0; i < is; i++)
					printf("%x ",textdata[of+i]);
				printf("\n");
			}
			of += is;
		}
		
		j = 1;
		while (j) {
			j = 0;
			for (i = 1; i < sizeof(histo)/sizeof(histo[0]); i++) {
				if (histo[i-1][1] < histo[i][1]) {
					unsigned int e[2];
					memcpy(e,histo[i-1],sizeof(int)*2);
					memcpy(histo[i-1],histo[i],sizeof(int)*2);
					memcpy(histo[i],e,sizeof(int)*2);
					j = 1;
				}
			}
		}
		for (i = 0; i < sizeof(histo)/sizeof(histo[0]); i++) {
			if (histo[i][0] != ~0) {
				printf("%10d %2x %3.2f \%\n",histo[i][1],histo[i][0],(float)histo[i][1]/icount*100);
			}
		}
	}
	if (strcmp(argv[2],"printiat") == 0) {
		getIAT(bin);
	}
	
	return 0;
}



