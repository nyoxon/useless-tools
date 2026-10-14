/*
super simple and minimal utf8 decoder

uselessness = 5/10

usage: utfdump [ARGS] STRING

example of usage:

$ utfdump -n 4 string
(s) U+0073  (t) U+0074  (r) U+0072  (i) U+0069  
(n) U+006E  (g) U+0067


use the program with the -h option to see all possible args
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

static int NUMBER_COLUMNS = 6;

static void print_usage(const char* prog_name) {
	fprintf(stderr, "usage: %s [ARGS] STRING\n", prog_name);
}

static void print_help() {
	printf("-h -> print help\n");
	printf("-s -> only print the decoded codepoints\n");
	printf("-d -> print the decoded codepoints as decimal\n");
	printf("-n N -> format the output using lines of N columns\n");
}

enum {
	UTF_SUCCESS = 0,
	UTF_EXIT_SUCCESS,
	UTF_EXIT_ERROR
};

enum {
	OPT_SUPRESS		   = 1 << 0,
	OPT_DECIMAL 	   = 1 << 1,
	OPT_NUMBER_COLUMNS = 1 << 2,
};

static int parse_args(int argc, char** argv, int* flags) {
	int opt;
	
	while ((opt = getopt(argc, argv, "dshn:")) != -1) {
		switch(opt) {
			case 'd':
				*flags |= OPT_DECIMAL;
				break;
			
			case 's':
				*flags |= OPT_SUPRESS;
				break;
			
			case 'n':
				*flags |= OPT_NUMBER_COLUMNS;
				NUMBER_COLUMNS = atoi(optarg);
				
				if (NUMBER_COLUMNS <= 0) {
					fprintf(
						stderr, 
						"invalid number of columns: %s\n",
						optarg
					);
					
					return UTF_EXIT_ERROR;
				}
				
				break;
			
			case 'h':
				print_help();
				return UTF_EXIT_SUCCESS;
			
			case '?':
				return UTF_EXIT_ERROR;
		}
	}
		
	return UTF_SUCCESS;
}

int utf8_decode(const unsigned char** str, uint32_t* codepoint) {
	const unsigned char* s = *str;
	uint32_t cp;
	size_t len;
	
	if (s[0] == '\0') {
		return 0;
	}
	
	if (s[0] < 0x80) {
		cp = s[0];
		len = 1;
	}
	
	else if (s[0] >= 0xC2 && s[0] <= 0xDF) {
		cp = s[0] & 0x1F;
		len = 2;
	}
	
	else if (s[0] >= 0xE0 && s[0] <= 0xEF) {
		cp = s[0] & 0x0F;
		len = 3;
	}
	
	else if (s[0] >= 0xF0 && s[0] <= 0xF4) {
		cp = s[0] & 0x07;
		len = 4;
	}
	
	else {
		return -1;
	}
	
	for (size_t i = 1; i < len; i++) {
		if (s[i] == '\0' || (s[i] & 0xC0) != 0x80) {
			return -1;
		}
		
		cp = (cp << 6) | (s[i] & 0x3F);
	}
	
	if ((len == 2 && cp < 0x80) ||
		(len == 3 && cp < 0x800) ||
		(len == 4 && cp < 0x10000) ||
		(cp >= 0xD800 && cp <= 0xDFFF) ||
		cp > 0x10FFFF)
	{
		return -1;
	}
	
	*str += len;
	*codepoint = cp;
	
	return 1;
}

void print_codepoint(uint32_t cp) {
	if (cp <= 0x7F) {
		putchar(cp);
	} 
	
	else if (cp <= 0x7FF) {
		putchar(0xC0 | (cp >> 6));
		putchar(0x80 | (cp & 0x3F));
	} 
	
	else if (cp <= 0xFFFF) {
		putchar(0xE0 | (cp >> 12));
		putchar(0x80 | ((cp >> 6) & 0x3F));
		putchar(0x80 | (cp & 0x3F));
	} 

	else if (cp <= 0x10FFFF) {
		putchar(0xF0 | (cp >> 18));
		putchar(0x80 | ((cp >> 12) & 0x3F));
		putchar(0x80 | ((cp >> 6) & 0x3F));
		putchar(0x80 | (cp & 0x3F));
	}
}

static int print_encode(const unsigned char* str, int opt) {
	size_t len = strlen((const char*) str);
	uint32_t cp;
	int ret;
	size_t count = 0;
	size_t printed = 0;
	
	while ((ret = utf8_decode(&str, &cp)) == 1) {
		if (count == 0 && printed > 0) {
			putchar('\n');
		}
		
		if (!(opt & OPT_SUPRESS)) {
			putchar('(');
			print_codepoint(cp);
			putchar(')');
			putchar(' ');
		}
		
		if (opt & OPT_DECIMAL) {
			printf("%u", (unsigned int) cp);
		}
		
		else {
			printf("U+%04X", (unsigned int) cp);
		}
		
		count++;
		printed++;
		
		if (count == NUMBER_COLUMNS) {
			count = 0;
		}
		
		else if (count < NUMBER_COLUMNS) {
			printf("  ");
		}
	}
	
	if (ret < 0) {
		fprintf(stderr, "invalid UTF-8\n");
		return UTF_EXIT_ERROR;
	}
	
	putchar('\n');
	
	return UTF_SUCCESS;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		return UTF_EXIT_ERROR;
	}
	
	int flags, parse_result;
	
	flags = 0;
	
	if ((parse_result = parse_args(argc, argv, &flags)) != UTF_SUCCESS) {
		if (parse_result == UTF_EXIT_SUCCESS) {
			return UTF_SUCCESS;
		}
		
		return parse_result;
	}
	
	if (optind >= argc) {
		fprintf(stderr, "missing string argument\n");
		return UTF_EXIT_ERROR;
	}
		
	const unsigned char* str = (const unsigned char*) argv[optind];
	
	print_encode(str, flags);
	
	return 0;
}