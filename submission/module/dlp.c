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
	char curr;

	while (pos < len) {
		curr = *(data + pos);
		
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
	const char *main_pos = strstr(data, "main");
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

int has_if(const char *data, int len) {
	int tmp;
	const char *if_pos = strstr(data, "if");

	if (if_pos == NULL) {
		return 0;
	}

	while (if_pos != NULL) {
		if (if_pos > data) {
			if (!isspace(*(if_pos - 1))) {
				if_pos = strstr(data, "if");
				continue;
			}
		}

		if (!isspace(*(if_pos + 2)) && *(if_pos + 2) != '(') {
			if_pos = strstr(data, "if");
			continue;
		}

		break;
	}

	if (if_pos == NULL) {
		return 0;
	}
			
	if_pos += 2;
	if_pos += skip_whitespaces(if_pos, 0, len);
	
	if (*if_pos != '(') {
		return 0;
	}

	if_pos++;
	tmp = skip_to_closingbracket(data, if_pos - data + 1, len, ')');

	if (tmp < 0) {
		return 0;
	}

	if_pos = (data + tmp) + 1;;
	if_pos += skip_whitespaces(if_pos, 0, len);

	if (*if_pos == '{') {
		if_pos++;
		tmp = skip_to_closingbracket(data, if_pos - data, len, '}');

		if (tmp >= 0) {
			printk(KERN_INFO "DLP: Found 'if' statement, Blocking message.");
			return 1;
		}
	}

	while (if_pos - data < len) {
		if (*if_pos == ';') {
			printk(KERN_INFO "DLP: Found 'if' statement, Blocking message.");
			return 1;
		} else {
			if_pos++;
		}
	}

	return 0;
}

const char *loop_start(const char *data, const char *loop_type, int len) {
	int loop_len = strlen(loop_type);
	const char *res = strstr(data, loop_type);

	while (res != NULL) {
		if (res > data) {
			if (!isspace(*(res - 1))) {
				res = strstr(data, loop_type);
				continue;
			}
		}

		res += loop_len;
		res += skip_whitespaces(res, 0, len);

		if (*(res) == '(') {
			break;
		}

		res = strstr(data, loop_type);
	}

	return res;
}

int has_for(const char *data, int len) {
	const char *loop_pos;
	int tmp;
	int count = 0;

	loop_pos = loop_start(data, "for", len);

	if (loop_pos == NULL) {
		return 0;
	}

	while (loop_pos - data < len) {
		if (*loop_pos == ';') {
			if (count < 2) {
				count++;
			} else {
				// Too many ';'
				return 0;
			}
		} else if (count == 2 && *loop_pos == ')') {
			loop_pos++;
			break;
		}

		loop_pos++;
	}


	loop_pos += skip_whitespaces(loop_pos, 0, len);

	if (*loop_pos == '{') {
		loop_pos++;
		tmp = skip_to_closingbracket(data, loop_pos - data, len, '}');

		if (tmp >= 0) {
			printk(KERN_INFO "DLP: Found 'for' loop, Blocking message.");
			return 1;
		} else {
			return 0;
		}
	}

	while (loop_pos - data < len) {
		if (*loop_pos == ';') {
			printk(KERN_INFO "DLP: Found 'for' loop, Blocking message.");
			return 1;
		} else {
			loop_pos++;
		}
	}

	return 0;
}

int has_while(const char *data, int len) {
	const char *loop_pos;
	int tmp;

	loop_pos = loop_start(data, "while", len);

	if (loop_pos == NULL) {
		return 0;
	}

	loop_pos++;
	tmp = skip_to_closingbracket(data, loop_pos - data, len, ')');

	if (tmp < 0) {
		return 0;
	}

	loop_pos = data + tmp + 1;
	loop_pos += skip_whitespaces(loop_pos, 0, len);

	if (*loop_pos == '{') {
		loop_pos++;
		tmp = skip_to_closingbracket(data, loop_pos - data, len, '}');

		if (tmp >= 0) {
			printk(KERN_INFO "DLP: Found 'while' loop, Blocking message.");
			return 1;
		} else {
			return 0;
		}
	}

	while (loop_pos - data < len) {
		if (*loop_pos == ';') {
			printk(KERN_INFO "DLP: Found 'while' loop, Blocking message.");
			return 1;
		} else {
			loop_pos++;
		}
	}

	return 0;
}

/** Returns 1 if code found and 1 otherwise **/
int check_for_code(const char *data) {
	int len = strlen(data);
	int pos = 0;

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
	} else if (has_if(data, len)) {
		return 1;
	} else if (has_for(data, len)) {
		return 1;
	} else if (has_while(data, len)) {
		return 1;
	}

	return 0;
}