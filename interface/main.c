#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int main(int argc, char const *argv[]) {
	char buf[100] = {0,};
	int fd;
	int len, i;

	if (argc < 2) {
		printf("Error: Wrong number of arguments recieced. (2)\n");
	}

	/****** Show Rule Table ******/
	if (strcmp(argv[1], "show_rule_table") == 0) {
		fd = open("/sys/class/fw/fw_rules/fw_rules", O_RDONLY);

		if (fd < 0) {
			perror("open(rules)");
		}

		read(fd, buf, 100);

		len = atoi(buf);

		close(fd);

		for (i = 0; i < len; i++) {
			bzero(buf, 100);
			fd = open("/dev/fw_rules", O_RDONLY);

			if (fd < 0) {
				perror("open(rules)");
			}

			read(fd, buf, 100);

			printf("%s", buf);

			close(fd);
		}

		return 0;
	}

	/****** Show Rule Table ******/
	if (strcmp(argv[1], "show_connection_table") == 0) {
		fd = open("/sys/class/fw/conn_tab/conn_tab", O_RDONLY);

		if (fd < 0) {
			perror("open(conn_tab)");
		}

		read(fd, buf, 100);

		len = atoi(buf);

		close(fd);

		for (i = 0; i < len; i++) {
			bzero(buf, 100);
			fd = open("/dev/conn_tab", O_RDONLY);

			if (fd < 0) {
				perror("open(conn_tab)");
			}

			read(fd, buf, 100);

			printf("%s", buf);

			close(fd);
		}

		return 0;
	}

	/****** Clear Rule Talbe ******/
	if (strcmp(argv[1], "clear_rule_table") == 0) {
		char msg[22] = "clear_rule_table00000";

		fd = open("/dev/fw_rules", O_WRONLY);

		if (fd < 0) {
			perror("open(rules)");
		}

		write(fd, msg, strlen(msg));

		close(fd);

		return 0;
	}

	/****** Show Log ******/
	if (strcmp(argv[1], "show_log") == 0) {

		fd = open("/sys/class/fw/fw_log/log_size/log_size", O_RDONLY);

		if (fd < 0) {
			perror("open(log)");
		}

		read(fd, buf, 100);

		len = atoi(buf);

		close(fd);


		for (i = 0; i < len; i++) {
			bzero(buf, 100);
			fd = open("/dev/fw_log", O_RDONLY);

			if (fd < 0) {
				perror("open(log)");
			}

			read(fd, buf, 0);

			printf("%s", buf);

			close(fd);
		}
		
		return 0;
	}


	/****** Clear Log ******/
	if (strcmp(argv[1], "clear_log") == 0) {
		fd = open("/dev/fw_log", O_WRONLY);

		if (fd < 0) {
			perror("open(log)");
		}

		write(fd, "1", strlen("1"));

		close(fd);

		return 0;
	}


	if (argc < 3) {
		printf("Error: Wrong number of arguments recieced. (3)\n");
	}

	/****** FireWall Activation ******/
	if (strcmp(argv[1], "firewall_activation") == 0) {
		fd = open("/sys/class/fw/fw_rules/active/active", O_WRONLY);

		if (fd < 0) {
			perror("open(active)");
		}

		if (strcmp(argv[2], "1") == 0) {
			// Activete Firewall
			write(fd, "1", 1);
		} else if (strcmp(argv[2], "0") == 0) {
			// Shutdown Firewall
			write(fd, "0", 1);
		} else {
			printf("Wrong parameter recieved for - firewall_activation. Expecting 1/0\n");
		}

		close(fd);

		return 0;
	}

	/****** Load Rule Table ******/
	if (strcmp(argv[1], "load_rule_table_from_file") == 0) {
		fd = open("/dev/fw_rules", O_WRONLY);

		if (fd < 0) {
			perror("open(rules)");
		}

		FILE *input_file = fopen(argv[2], "r");

		if (input_file == NULL) {
			perror("Error opening rule file\n");
			close(fd);

			return -1;
		}

		char rule[100] = {0,};

		while (fgets(rule, 100, input_file) != NULL) {

			strstr(rule, "/")[0] = ' ';
			strstr(rule, "/")[0] = ' ';

			write(fd, rule, strlen(rule));
		}
		fclose(input_file);
		close(fd);

		return 0;
	}

	return 0;
}