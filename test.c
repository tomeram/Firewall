#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

char *regex_str = "((int)|(void))\\s+(main)\\s*\\(.*\\)\\s*\\{((\\s|.)*)\\}";
char *str = "int main() {\n\tint a = 5;\n}";

regex_t regex;
int reti;

int main() {
	/* Compile Regex */
	reti = regcomp(&regex, regex_str, REG_EXTENDED);

	if (reti) {
		printf("Could not compile regex.\n");
		exit(1);
	}

	/* Exec Regex */
	reti = regexec(&regex, str, 0, NULL, 0);

	if (!reti) {
		printf("Match\n");
	} else if (reti == REG_NOMATCH) {
		printf("No Match\n");
	} else {
	    regerror(reti, &regex, str, sizeof(str));
	    printf("Regex match failed: %s\n", str);
	    exit(1);
	}

	/* Free compiled regular expression if you want to use the regex_t again */
	regfree(&regex);

	return 0;
}
