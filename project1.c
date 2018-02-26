//project1.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/*
I edited the sample.bin file for multiple different types of malicious input.
Unreconized tags, sample inputs that were longer than expected,
different sized html tables, off-by-one errors and so on.  
I think I've (hopefully) secured most of the bugs.
*/

//close gracefully and wrap up the html
void end(FILE *fptr, FILE *opt) {
	fprintf(opt, "</tr> </body> </html>");
	fclose(fptr);
	fclose(opt);
	exit(0);
}

//reverses the string... but not by 2's (or bytes), instead flips it so only slightly effective
//I should fix this to read little endian format easier... but hey, it works
char *strrev(char *str) {
	int i = strlen(str) - 1, j = 0;
    char ch;
    while (i > j) {
        ch = str[i];
        str[i] = str[j];
        str[j] = ch;
        i--;
        j++;
    }
    return str;
}

/*
anytime we read from the file, a malicious input could attempt to
read past the memory allocated for the file.  This function checks 
that it stays in bounds.

i.e. This function is called everytime before fread()

n is the current location+location being read <= IMPORTANT
*/
int check_EOF(int n, int file_size, FILE *fptr, FILE *opt) {
	if (n>file_size) {
		printf("Reached end of file, exiting.\n");
		end(fptr, opt);
	}
	return(1);
}


unsigned int get_data(int bytes, FILE *fptr) {
	int buff[bytes+1];
	//EOF possible (checked before the get_data function call)
	fread(&buff, bytes, 1, fptr);
	char hexstring[bytes+1]; //make sure allocate enough size
	snprintf(hexstring, (bytes*2)+1, "%02x", *buff);
	/*
	the bytes will always be between 1-4 so snprintf is not REALLY needed,
	but I did so just in case.
	*/
	
	while (strlen(hexstring) < bytes*2) {
				char new[9] = "0";
				strcat(new, hexstring);
				strcpy(hexstring, new);
			}
	strrev(hexstring);
	
	if (bytes == 4) {
		char tempstr[9];
			strncpy(tempstr, hexstring, 8);
			
		//little endian... messy way to do it
		hexstring[0] = tempstr[1];
		hexstring[1] = tempstr[0];
		hexstring[2] = tempstr[3];
		hexstring[3] = tempstr[2];
		hexstring[4] = tempstr[5];
		hexstring[5] = tempstr[4];
		hexstring[6] = tempstr[7];
		hexstring[7] = tempstr[6];
	} else if (bytes == 2) {
		char tempstr[9];
		strncpy(tempstr, hexstring, 4);
			
		//little endian... messy way to do it
		hexstring[0] = tempstr[1];
		hexstring[1] = tempstr[0];
		hexstring[2] = tempstr[3];
		hexstring[3] = tempstr[2];
	} else {
		strrev(hexstring);
	}
	
	
	//printf("hexstring: %s\t\n", hexstring);
	
	int num = strtol(hexstring, NULL, 16);

	return(num);
}


int
main(int argc, char *argv[]) {
	//initialize output
	FILE *opt;
	opt = fopen("opt.html", "w");
	fprintf(opt, "<!DOCTYPE html> <html> <body> <table border =\"1\"> <tr>");

	
	/*
	I put 5 minutes into trying to make it detect if the file was binary before testing
	with non-binary files and it still exits gracefully after not detecting a tag.
	May still be a vulnerability with "rb" not working; does have some exception handling.
	*/
	//initialize input
	FILE *fptr;
	fptr = fopen(argv[1], "rb");
	if (fptr == NULL) {
		printf("Cannot open file (format: ./Project1 sample.bin)	\n");
		end(fptr, opt);
    }
		
	//find how many bytes in the file
	int fsize;
	fseek(fptr, 0L, SEEK_END);
	fsize = ftell(fptr);
	//printf("File size = %d\n\n", fsize);	//checked correct, 22x16-3 = 349 bytes of sample.bin file
	rewind(fptr); //and go back to beginning of the file
	
	//initialize variables
	int n = 0; //counter of byte location in file
	int buffer[5]; //max size used is 4
	char test[16];
	char test2[2];
	long data;
	char hexstring[9];
	unsigned int number;
	
	//loop, start reading the file
	while (n < fsize+1) {
		//printf("fsize: %d,\tn: %d\n", fsize, n);
		/*
		This loop reads each tag.  If the tag is not 0-5, detects a wrong input and gracefully exits.
		*/
		check_EOF(n+1, fsize, fptr, opt);
		fread(&buffer, 1, 1, fptr);
		//printf("x: %x\t d: %u\t\n", *buffer, *buffer);
		
		//read the tags
		if (*buffer == 16777216) {
			//Read next four bytes, intepret as length bytes of data
			//EOF possible
			check_EOF(n+4, fsize, fptr, opt);
			fread(&buffer, 4, 1, fptr);
			n = n + 4;
			
			//EOF possible
			
			sprintf(hexstring, "%02x", *buffer);
			
			while (strlen(hexstring) < 8) {
				char new[9] = "0";
				strcat(new, hexstring);
				strcpy(hexstring, new);
			}
			
			strrev(hexstring);
			
			char tempstr[9]; //reads next 8 bytes
			strncpy(tempstr, hexstring, 8);
			
			//little endian... messy way to do it
			hexstring[0] = tempstr[1];
			hexstring[1] = tempstr[0];
			hexstring[2] = tempstr[3];
			hexstring[3] = tempstr[2];
			hexstring[4] = tempstr[5];
			hexstring[5] = tempstr[4];
			hexstring[6] = tempstr[7];
			hexstring[7] = tempstr[6];

			//hexstring to int
			number = strtol(hexstring, NULL, 16);
			
			if (number == 0) {
					if (errno == EINVAL) {
						printf("Conversion error occured: %d\t", errno);
						end(fptr, opt);	}
			}
			
			check_EOF(n+number, fsize, fptr, opt); //always before fread()
			char data1[number];
			fread(&data1, number, 1, fptr);
			fprintf(opt, "<th>%s</th>", data1);
			n = n + number;
		}
		
		
		else if (*buffer == 33554432) {
			check_EOF(n+4, fsize, fptr, opt); //always before fread() - fread called in get_data()
			data = get_data(4, fptr);
			fprintf(opt, "<th>%ld</th>", data);
			n = n+4;
		}
		else if (*buffer == 50331648) {
			check_EOF(n+2, fsize, fptr, opt); //always before fread() - fread called in get_data()
			data = get_data(2, fptr);
			fprintf(opt, "<th>%ld</th>", data);
			n = n+2;
		}
		else if (*buffer == 67108864) {
			check_EOF(n+1, fsize, fptr, opt); //always before fread() - fread called in get_data()
			data = get_data(1, fptr);
			fprintf(opt, "<th>%ld</th>", data);
			n = n+1;
		}
		else if (*buffer == 83886080) {
			fprintf(opt, "</tr> <tr> ");
			n++;
		}
		else if (*buffer == 0) {
			printf("It worked! '00' reached :D\n");
			end(fptr, opt);
		}
		else {
			printf("Unreconized Tag: %x\t Closing...\n", *buffer);
			end(fptr, opt);
		}
	}
	
	end(fptr, opt);
	return(0);
}
	