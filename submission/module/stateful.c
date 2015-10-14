#include "stateful.h"

/** Globals **/
int num_of_dynamic_rules 			= 0;
dynamic_rule_link *dynamic_table 	= NULL;


/** Function **/
void clear_dynamic_rules(void) {
	dynamic_rule_link *next;

	if (num_of_dynamic_rules == 0) {
		printk(KERN_INFO "Dynamic Rule Table empty.\n");
		return;
	}

	while (dynamic_table != NULL) {
		next = dynamic_table->next;
		kfree(dynamic_table);
		dynamic_table = next;
		num_of_dynamic_rules--;
	}

	if (num_of_dynamic_rules != 0) {
		printk(KERN_INFO "Error: not all dynamic rules freed! %d\n", num_of_dynamic_rules);
	} else {
		printk(KERN_INFO "Memory successfully freed! :)\n");
	}
}

dynamic_rule_link *create_dynamic_rule(rule_t input) {
	// Create rule, and add to table
	dynamic_rule_link 	* new_link = kmalloc(sizeof(dynamic_rule_link), GFP_ATOMIC);
	dynamic_rule		* rule = NULL;
	struct timeval 		s_time;
	unsigned long		curr_time;

	do_gettimeofday(&s_time);
	curr_time = (u32)s_time.tv_sec;

	if (new_link == NULL) {
		printk(KERN_INFO "Error in kmalloc: could not allocate a dynamic rule.\n");
		return NULL;
	}

	new_link->next = dynamic_table; // Add to dynamic table
	dynamic_table = new_link;

	rule = &new_link->rule;

	rule->src_ip	= input.src_ip;
	rule->dst_ip	= input.dst_ip;
	rule->src_port	= input.src_port;
	rule->dst_port	= input.dst_port;
	rule->timestamp = curr_time;

	if (ntohs(input.dst_port) == 21) {
		rule->protocol 	= FTP;
		rule->ftp_state = FTP_HANDSHAKE;
	} else if (ntohs(input.dst_port) == 80) {
		rule->protocol 		= HTTP;
		rule->http_state 	= HTTP_HANDSHAKE;
	} else if (ntohs(input.dst_port) == 25) {
		rule->protocol 		= SMTP;
		rule->smtp_state 	= SMTP_INIT;
	} else {
		rule->protocol = OTHER_TCP;
	}

	num_of_dynamic_rules++;

	return new_link;
}

int update_ftp_rule(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph, rule_t s_rule) {
	char 				* data 	= (char *)((int)tcph + (int)(tcph->doff * 4));
	dynamic_rule 		* rule 	= &curr->rule;
	dynamic_rule_link 	* new_link = NULL;
	int	ip_1, ip_2, ip_3, ip_4, port_1, port_2;
	int update_timestamp = 1;

	struct timeval 		s_time;
	unsigned long 		curr_time;

	do_gettimeofday(&s_time);
	curr_time = (u32)s_time.tv_sec;

	switch(rule->ftp_state) {
		case FTP_HANDSHAKE:
			if (!strnicmp(data, "230", 3)) {
				printk(KERN_INFO "FTP: Server accepted connection.\n");
				rule->ftp_state = FTP_CONNECTED;
			} else {
				printk(KERN_INFO "FTP: Awaiting server connection approval.\n");
			}
			break;
		case FTP_CONNECTED:
			if (!strnicmp(data, "PORT", 4)) {
				printk(KERN_INFO "FTP: Switching to data transfer mode.\n");

				// Create new rule
				new_link = create_dynamic_rule(s_rule);

				// Make sure directions are right
				new_link->rule.src_ip = curr->rule.src_ip;
				new_link->rule.src_port = curr->rule.src_port;
				new_link->rule.dst_ip = curr->rule.dst_ip;
				new_link->rule.dst_port = curr->rule.dst_port;

				// Getting the new IP and port
				sscanf(data, "PORT %d,%d,%d,%d,%d,%d", &ip_1, &ip_2, &ip_3, &ip_4, &port_1, &port_2);
				new_link->rule.src_ip 	= ntohl((ip_1<<24) + (ip_2<<16) + (ip_3<<8) + ip_4);
				new_link->rule.src_port = htons((port_1 * 256) + port_2);
				new_link->rule.dst_port = htons(20);

				new_link->rule.protocol		= FTP;
				new_link->rule.ftp_state 	= FTP_TRANSFER;
			} else if (!strnicmp(data, "QUIT", 4)) {
				printk(KERN_INFO "FTP: Closing connection.\n");
				rule->ftp_state = FTP_END;
			}
			break;
		case FTP_TRANSFER:
			printk(KERN_INFO "FTP: Transfering\n");
			if (tcph->fin) {
				rule->ftp_state = FTP_END;
			}
			break;
		case FTP_END:
			if (!(tcph->ack || tcph->fin)) {
				return 0;
			}

			update_timestamp = 0;
			break;
	}

	if (update_timestamp) {
		rule->timestamp = curr_time;
	}

	return 1;
}

int update_smtp_rule(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph, rule_t s_rule) {
	char *data = (char *)((int)tcph + (int)(tcph->doff * 4));
	dynamic_rule *rule = &curr->rule;

	// Update rule timestamp
	struct timeval 		s_time;

	do_gettimeofday(&s_time);
	rule->timestamp = (u32)s_time.tv_sec;

	if (rule->smtp_state == SMTP_INIT) {
		if (!strnicmp(data, "DATA", 4) || !strnicmp(data, "data", 4)) {
			// DATA transminssion will begin in next transmission
			rule->smtp_state = SMTP_DATA;

			printk(KERN_INFO "SMTP: Movin to data stage.\n");
		}
	} else if (rule->smtp_state == SMTP_DATA) {
		if (check_for_code(data)) {
			printk("DLP: Code detected, communication blocked.");

			// Delete rule from table
			if (prev != NULL) {
				prev->next = curr->next;
				kfree(curr);
				curr = prev->next;
			} else {
				// This is the first rule in the list.
				dynamic_table = curr->next;
				kfree(curr);
				curr = dynamic_table;
			}

			return -1;
		}
	}
	
	return 1;
}

int update_http_rule(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph, rule_t s_rule) {
	char 				* data 			= (char *)((int)tcph + (int)(tcph->doff * 4));
	dynamic_rule 		* rule 			= &curr->rule;
	dynamic_rule_link 	* new_link 		= NULL;
	char 				* location		= NULL;
	char 				* location_end	= NULL;
	char				new_ip[256]		= {0,};
	int					redirect 		= 0;
	int	ip_1, ip_2, ip_3, ip_4;
	int update_timestamp = 1;

	struct timeval 		s_time;
	unsigned long 		curr_time;

	do_gettimeofday(&s_time);
	curr_time = (u32)s_time.tv_sec;

	switch(rule->http_state) {
		case HTTP_HANDSHAKE:
			if (!strnicmp(data, "GET", 3) || !strnicmp(data, "POST", 4)) {
				rule->http_state = HTTP_REQUEST;

				// Check attacks
				if (check_zabbix_injection(data)) {
					printk(KERN_INFO "Zabbix injection found: drop packet");
					return -1;
				} else if (check_sysax_attack(data)) {
					printk(KERN_INFO "Sysax create folder attack found: drop packet");
					return -1;
				}
			}
			break;
		case HTTP_REQUEST:
			// Check attacks
			if (check_zabbix_injection(data)) {
				printk(KERN_INFO "Zabbix injection found: drop packet");
				return -1;
			} else if (check_sysax_attack(data)) {
				printk(KERN_INFO "Sysax create folder attack found: drop packet");
				return -1;
			} else if (!strnicmp(data, "HTTP/1.1", 8)) {
				if (!strnicmp(data, "HTTP/1.1 30", 11)) {
					redirect = 1;
				}
				rule->http_state = HTTP_RESPONSE;
			} else if (!strnicmp(data, "HTTP/1.0", 8)) {
				if (!strnicmp(data, "HTTP/1.0 30", 11)) {
					redirect = 1;
				}
				rule->http_state = HTTP_RESPONSE;
			}
			break;
		case HTTP_RESPONSE:
			update_timestamp = 0;
			break;
	}

	if (redirect) {
		printk(KERN_INFO "Found redirect");
		location = strstr(data, "\x0d\x0aLocation: ");
		if (location != NULL) {
			if (!strnicmp(location, "\x0d\x0aLocation: http://", strlen("\x0d\x0aLocation: http://"))) {
				location += strlen("\x0d\x0aLocation: http://");
			} else {
				location += strlen("\x0d\x0aLocation: ");
			}

			location_end = strstr(location, "\x0d\x0a");

			if (strstr(location, "/") < location_end) {
				// Remove path in IP i.e: 10.0.1.1/index.html
				location_end = strstr(location, "/");
			}

			memcpy(new_ip, location, (location_end - location));
			sscanf(new_ip, "%d.%d.%d.%d", &ip_1, &ip_2, &ip_3, &ip_4);

			new_link = create_dynamic_rule(s_rule);

			// Make sure directions are right
			new_link->rule.src_ip = curr->rule.src_ip;
			new_link->rule.src_port = curr->rule.src_port;
			new_link->rule.dst_ip = curr->rule.dst_ip;
			new_link->rule.dst_port = curr->rule.dst_port;

			new_link->rule.dst_ip = ntohl((ip_1<<24) + (ip_2<<16) + (ip_3<<8) + ip_4);
			new_link->rule.protocol		= HTTP;
			new_link->rule.http_state 	= HTTP_HANDSHAKE;
		}
	}

	if (update_timestamp) {
		rule->timestamp = curr_time;
	}

	return 1;
}

int update_connection_state(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph, rule_t s_rule) {
	if (curr->rule.protocol == FTP) {
		return update_ftp_rule(curr, prev, tcph, s_rule);
	} else if (curr->rule.protocol == HTTP) {
		return update_http_rule(curr, prev, tcph, s_rule);
	} else if (curr->rule.protocol == SMTP) {
		return update_smtp_rule(curr, prev, tcph, s_rule);
	} else {
		return 1;
	}
}

int check_dynamic_action(rule_t input, struct tcphdr *tcph) {
	struct timeval 		s_time; // To check if the entry is still relevant
	unsigned long 		curr_time;
	dynamic_rule_link 	* curr 		= dynamic_table;
	dynamic_rule_link 	* prev		= NULL;
	dynamic_rule		* rule		= NULL;

	do_gettimeofday(&s_time);
	curr_time = (u32)s_time.tv_sec;

	// Check if there is a rule for this connection
	while(curr != NULL) {
		rule = &curr->rule;

		// Check rule timeout
		//TODO: fix time
		if (curr_time - rule->timestamp > 25) {
			printk(KERN_INFO "Rule Expired. Remove from table.\n");
			// Rule default timeout -> remove and skip
			if (prev != NULL) {
				prev->next = curr->next;
				kfree(curr);
				curr = prev->next;
			} else {
				// This is the first rule in the list.
				dynamic_table = curr->next;
				kfree(curr);
				curr = dynamic_table;
			}

			num_of_dynamic_rules--;
			continue;
		}

		// Check if this is a matching rule
		if ((rule->src_ip == input.src_ip && rule->src_port == input.src_port 
					&& rule->dst_ip == input.dst_ip && rule->dst_port == input.dst_port) ||
			(rule->src_ip == input.dst_ip && rule->src_port == input.dst_port 
					&& rule->dst_ip == input.src_ip && rule->dst_port == input.src_port)) {
			
			// printk(KERN_INFO "Found matching dynamic_rule.\n");
			return update_connection_state(curr, prev, tcph, input);
		}

		prev = curr;
		curr = curr->next;
	}

	// No rule found, check if the connection is new, and create a rule accordingly
	printk(KERN_INFO "No rule found in dynamic table.\n");
	return 0;
}
