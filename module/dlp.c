#include "dlp.h"

/** Checks for whitespaces and skips them **/
int skip_whitespaces(const char *data, int pos, int len) {
	int count = 0;
	char curr;

	while (pos < len) {
		curr = *(data + pos);

		if (isspace(curr)) {
			count++;
			pos++; 
		} else {
			break;
		}
	}

	return count;
}

int skip_to_char(const char *data, int *pos, int len, char target_char) {
	char curr;

	while (*pos < len) {
		curr = *(data + *pos);

		if (curr == target_char) {
			return 1;
		} else {
			(*pos)++;
		}
	}

	return 0;
}

int skip_to_closingbracket(const char *data, int pos, int len, char target) {
	int reg = 0, sq = 0, curl = 0;
	char curr = *(data + pos);

	while (pos < len) {
		if (curr == target && target != '_') {
			if (!reg && !sq && !curl) {
				return pos;
			}
		}


		switch(curr) {
			case '(':
				reg++;
				break;
			case ')':
				reg--;
				break;
			case '[':
				sq++;
				break;
			case ']':
				sq--;
				break;
			case '{':
				curl++;
				break;
			case '}':
				curl--;
				break;
			default:
				break;
		}

		if (reg < 0 || sq < 0 || curl < 0) {
			return -1;
		}

		pos++;
	}

	if (!reg && !sq && !curl && target == '_') {
		return pos;
	}

	return -1;
}

int has_include(const char *data) {
	if (strstr(data, "#include") != NULL) {
		return 1;
	}

	return 0;
}

int has_main(const char *data, int *pos, int len) {
	char *main_pos = strstr(data, "main");
	char curr;
	int tmp;

	if (main_pos == NULL) {
		return 0;
	}

	do {
		(*pos) = main_pos - data;

		if (isspace(*(main_pos - 1))) {
			break;
		} else {
			*pos += 4;
			main_pos = strstr(data + *pos, "main");
		}
	} while ((*pos) < len && main_pos != NULL);

	// Go back to type
	while(*pos > 0) {
		curr = *(data + *pos - 1);

		if (isspace(curr)) {
			(*pos)--;
		} else {
			break;
		}
	}

	if (*pos < 3) {
		return 0;
	}

	if (!strnicmp((data + (*pos - 3)), "int", 3) || !strnicmp((data + (*pos - 4)), "void", 4)) {
		main_pos += 4;
		main_pos += skip_whitespaces(data, main_pos - data, len);

		if (*main_pos == '(') {
			main_pos++;
			tmp = skip_to_closingbracket(data, main_pos - data, len, ')');

			if (tmp > 0) {
				main_pos = (data + tmp) + 1;
				main_pos += skip_whitespaces(data, main_pos - data, len);

				printk(KERN_INFO "here: %s\n", main_pos);

				if (*main_pos == '{') {
					main_pos++;
					tmp = skip_to_closingbracket(data, main_pos - data, len, '}');

					if (tmp < 0) {
						return 0;
					} else {
						return 1;
					}
				}
			}
		}
	}

	return 0;
}

/** Returns 1 if code found and 1 otherwise **/
int check_for_code(const char *data) {
	int len = strlen(data);
	int pos = 0;


	printk(KERN_INFO "In DLP\n");

	if (len == 0) {
		// Empty message, Not code.
		return 0;
	} else if (skip_to_closingbracket(data, 0, len, '_') < 0) {
		printk(KERN_INFO "Wrong number/order of brackets in file. Not code.\n");
	 	return 0;
	} else if (has_include(data)) {
		return 1;
	} else if (has_main(data, &pos, len)) {
		return 1;
	}
	// else if (has_if(data, len)) {
	// 	return 1;
	// }

	return 0;
}