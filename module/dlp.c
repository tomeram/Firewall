#include "dlp.h"

#define REGEX_NUM 7

char *regex_str[REGEX_NUM] = {
	// include statement
	"(#include [\"<].*[\">])",
	// main function statement
	"((int)|(void))\\s+(main)\\s*\\(.*\\)\\s*\\{((\\s|.)*)\\}",
	// if statement
	"(if)\\s*\\(.*?\\)\\s*((\\{(\\s*.*?\\;\\s*)*\\})|(.*?\\;))",
	// for loop
	"(for)\\s*\\(([^\\;]*?\\;){2}([^\\;]*?)\\)\\s*(\\{(\\s|.)*\\}|[^\\;]*\\;|((if|while|for|switch)((\\s|.)*?)\\{((\\s|.)*?)\\}))",
	// while loop
	"(while)\\s*\\([^\\;]*?\\)\\s*(\\{(\\s|.)*\\}|[^\\;]*\\;|((if|while|for|switch)((\\s|.)*?)\\{((\\s|.)*?)\\}))",
	// variable declaration
	"([A-Z|a-z][a-z0-9_]*(\\s*\\*\\s|\\s\\*\\s*|\\s+)[A-Z|a-z][a-z0-9_]*\\s*)(\\[[0-9]*\\])*\\s*(\\=(\\s|.)*)?\\;",
	// function decleration
	"([A-Z|a-z][a-z0-9_]*(\\s*\\*\\s|\\s\\*\\s*|\\s+)[A-Z|a-z][a-z0-9_]*\\s*)\\s*\\((((((const)\\s+)?[A-Z|a-z][a-z0-9_]*(\\s*\\*\\s|\\s\\*\\s*|\\s+)[A-Z|a-z][a-z0-9_]*\\s*)(\\[[0-9]*\\])*\\s*)(\\,\\s*(((const)\\s+)?([A-Z|a-z][a-z0-9_]*(\\s*\\*\\s|\\s\\*\\s*|\\s+)[A-Z|a-z][a-z0-9_]*\\s*)(\\[[0-9]*\\])*\\s*)))?\\)"
};

char *str = "Include the next question: who are you working for (if you’re even working for someone)";

regex_t regex;
int reti;

int check_for_code(const char *str) {
	int i;

	for (i = 0; i < REGEX_NUM; i++) {
		/* Compile Regex */
		reti = regcomp(&regex, regex_str[i], REG_EXTENDED);

		/* Exec Regex */
		reti = regexec(&regex, str, 0, NULL, 0);

		if (!reti) {
			
		}

		/* Free compiled regular expression if you want to use the regex_t again */
		regfree(&regex);
	}

	return 0;
}