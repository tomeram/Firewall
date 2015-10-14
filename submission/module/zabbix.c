#include "zabbix.h"

int check_zabbix_injection(const char *data) {
	if (strstr(data, "zabbix.sessions")) {
		return 1;
	}

	return 0;
}