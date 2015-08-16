#include "stateless.h"

/** Globals **/
int 		num_of_rules 	= 0;
rule_link 	* list 			= NULL;
rule_link 	* last 			= NULL;

/** Function **/
void clear_rules(void) {
	rule_link *next;

	if (num_of_rules == 0) {
		printk(KERN_INFO "Rule Table empty.\n");
		return;
	}

	while (list != NULL) {
		next = list->next;
		kfree(list);
		list = next;

		num_of_rules--;
	}

	if (num_of_rules != 0) {
		printk(KERN_INFO "Error: not all rules freed! %d\n", num_of_rules);
	} else {
		printk(KERN_INFO "Memory successfully freed! :)\n");
	}
}

int check_static_action(rule_t input, int hooknum) {
	rule_link *curr_l = list;
	rule_t curr;
	__be32 mask;
	int i = 0;

	// Search for matching rule
	while(curr_l != NULL) {
		i++;
		curr = curr_l->rule;
		// Check Direction
		if (curr.direction != DIRECTION_ANY && curr.direction != input.direction) {
			curr_l = curr_l->next;
			continue;
		}

		// Check src_ip
		if (curr.src_ip != 0) { // Ok of rule IP is any
			mask = (0xFFFFFFFF << (32 - curr.src_prefix_size)) & 0xFFFFFFFF;

			if ((curr.src_ip & mask) != (input.src_ip & mask)) {
				// Rule does not match
				curr_l = curr_l->next;
				continue;
			}
		}

		if (curr.dst_ip != 0) { // Ok of rule IP is any
			mask = (0xFFFFFFFF << (32 - curr.dst_prefix_size)) & 0xFFFFFFFF;

			if ((curr.dst_ip & mask) != (input.dst_ip & mask)) {
				// Rule does not match
				curr_l = curr_l->next;
				continue;
			}
		}
		
		// Check Protocol
		if (curr.protocol != PROT_OTHER && curr.protocol != PROT_ANY) { // Continue if rule protocol is any
			if (input.protocol == curr.protocol) {
				// Check TCP
				if (curr.protocol == PROT_TCP) {
					// Check ACK
					if (curr.ack != ACK_ANY && curr.ack == input.ack) {
						// Check Ports
						if ((curr.src_port == 0) || (curr.src_port != 0 && curr.src_port == input.src_port) || (curr.src_port == 1023 && input.src_port > 1023)) {
							if ((curr.dst_port == 0) || (curr.dst_port != 0 && curr.dst_port == input.dst_port) || (curr.dst_port == 1023 && input.dst_port > 1023)) {
								// Found Matching rule. Wire to log and execute action.
								log_entry(&input, &curr, i, hooknum, curr.action);
								printk(KERN_INFO "TCP Rule: %s, action %d", curr.rule_name, curr.action);
								return curr.action;
							}
						}
					}
				}

				// Check UDP
				if (curr.protocol == PROT_UDP) {
					// Check Ports
					if ((curr.src_port == 0) || (curr.src_port != 0 && curr.src_port == input.src_port) || (curr.src_port == 1023 && input.src_port > 1023)) {
						if ((curr.dst_port == 0) || (curr.dst_port != 0 && curr.dst_port == input.dst_port) || (curr.dst_port == 1023 && input.dst_port > 1023)) {
							// Found Matching rule. Wire to log and execute action.
							log_entry(&input, &curr, i, hooknum, curr.action);
							printk(KERN_INFO "UDP Rule: %s, action %d", curr.rule_name, curr.action);
							return curr.action;
						}
					}
				}
				// Check ICMP
				if (curr.protocol == PROT_ICMP) {
					// Found Matching rule. Wire to log and execute action.
					log_entry(&input, &curr, i, hooknum, curr.action);
					printk(KERN_INFO "ICMP Rule: %s, action %d", curr.rule_name, curr.action);
					return curr.action;
				}
			}
			
			curr_l = curr_l->next;
			continue;
		}

		// Found Matching rule. Wire to log and execute action.
		log_entry(&input, &curr, i, hooknum, curr.action);
		printk(KERN_INFO "OTHER/ANY Rule: %s, action %d", curr.rule_name, curr.action);
		return curr.action;
	}

	// No Rule found
	log_entry(&input, NULL, REASON_NO_MATCHING_RULE, hooknum, 1);
	printk(KERN_INFO "No Rule Found\n");
	return 1;
}