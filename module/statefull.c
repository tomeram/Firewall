#include "statefull.h"

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

void create_dynamic_rule(rule_t input, struct tcphdr *tcph) {
	// TODO: should I create rule for both directions?
	// Create rule, and add to table
	dynamic_rule_link 	* new_link = kmalloc(sizeof(dynamic_rule_link), GFP_ATOMIC);
	dynamic_rule		* rule = NULL;
	struct timeval 		s_time;
	unsigned long		curr_time;

	do_gettimeofday(&s_time);
	curr_time = (u32)s_time.tv_sec;

	if (new_link == NULL) {
		printk(KERN_INFO "Error in kmalloc: could not allocate a dynamic rule.\n");
		return;
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
	} else {
		rule->protocol = OTHER_TCP;
	}

	num_of_dynamic_rules++;
	printk(KERN_INFO "Size of of dynamic table: %d", num_of_dynamic_rules);
}

void update_ftp_rule(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph) {
	// TODO: ftp
	char 			* data = (char *)((int)tcph + (int)(tcph->doff * 4));
	dynamic_rule 	* rule = &curr->rule;

	printk(KERN_INFO "data: %s\n", data);

	switch(rule->ftp_state) {
		case FTP_HANDSHAKE:
			printk(KERN_INFO "FTP_HANDSHAKE\n");
			break;
	}

}

void update_connection_state(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph) {
	if (curr->rule.protocol == FTP) {
		update_connection_state(curr, prev, tcph);
	}
	// TODO: http, other
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
		if (curr_time - rule->timestamp > 25) {
			printk(KERN_INFO "Rule Expired.\n");
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

			printk(KERN_INFO "Size of of dynamic table: %d\n", num_of_dynamic_rules);
			continue;
		}


		// TODO: Am I supposed check in the other direction too?
		if ((rule->src_ip == input.src_ip && rule->src_port == input.src_port 
					&& rule->dst_ip == input.dst_ip && rule->dst_port == input.dst_port) ||
			(rule->src_ip == input.dst_ip && rule->src_port == input.dst_port 
					&& rule->dst_ip == input.src_ip && rule->dst_port == input.src_port)) {
			printk(KERN_INFO "Found matching dynamic_rule.\n");
			// TODO update state
			rule->timestamp = curr_time;
			update_connection_state(curr, prev, tcph);

			return 1;
		}

		prev = curr;
		curr = curr->next;
	}

	// No rule found, check if the connection is new, and create a rule accordingly
	printk(KERN_INFO "No rule found in dynamic table - Packet dropped.\n");
	return 0;
}
