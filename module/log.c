#include "log.h"

/** Globals **/
int log_size_num 	= 0;
log_link *log_l 	= NULL;

/** Functions **/

void clear_log(void) {
	log_link *next;

	while (log_l != NULL) {
		next = log_l->next;
		kfree(log_l);
		log_l = next;

		log_size_num--;
	}

	if (log_size_num != 0) {
		printk(KERN_INFO "Error: not all rules freed! %d\n", num_of_rules);
	} else {
		printk(KERN_INFO "Memory successfully freed! :)\n");
	}
}

void log_entry(rule_t *input, rule_t *rule, reason_t reason, int hooknum, int action) {
	log_link 	* curr 		= log_l;
	log_link 	* new_link;
	log_row_t 	* new;
	struct timeval s_time;

	new_link = kmalloc(sizeof(log_link), GFP_ATOMIC);

	if (new_link == NULL) {
		printk(KERN_INFO "Error in kmalloc for log\n");
		return;
	}

	new = &new_link->entry;

	do_gettimeofday(&s_time);
	new->timestamp = (u32)s_time.tv_sec;
	new->protocol = input->protocol;
	new->reason = reason;
	new->action = action;

	new->hooknum = hooknum;
	new->src_ip = input->src_ip;
	new->dst_ip = input->dst_ip;
	new->src_port = input->src_port;
	new->dst_port = input->dst_port;
	new->count = 1;

	while (curr != NULL) {
		// Check if there is alredy a log entry
		if (curr->entry.reason == reason &&
			curr->entry.protocol == new->protocol &&
			curr->entry.src_ip == new->src_ip &&
			curr->entry.dst_ip == new->dst_ip &&
			curr->entry.src_port == new->src_port &&
			curr->entry.dst_port == new->dst_port &&
			curr->entry.action == new->action) {
			
			curr->entry.timestamp = (u32)s_time.tv_sec;
			curr->entry.count++;
			kfree(new_link);
			return;
		}

		curr = curr->next;
		continue;
	}

	new_link->next = log_l;
	log_l = new_link;

	log_size_num++;
}