#include "sysax.h"

int check_sysax_attack(const char *data) {
	char *location, *param_end;

	if (strstr(data, "pid=mk_folder2_name1.htm")) {
		// Create folder attempt -> check if legitimate
		location = strstr(data, "name=\"e2\"");

		printk(KERN_INFO "found pid\n");

		if (location != NULL) {
			// Found vulnerable parameter, check if attacked
			param_end = strstr(location, "--");
			printk(KERN_INFO "found e2 param\n");

			if (param_end - location > XP_FOLDER_NAME_LEN) {
				return 1;
			}
		}
	}

	return 0;
}