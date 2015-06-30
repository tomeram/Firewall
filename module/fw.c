/*** Main FW File ***/
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomer Amir");

/****** Global Vars ******/
int firewall_active = 0;
int num_of_rules 	= 0;
int log_size_num 	= 0;
int num_of_dynamic_rules = 0;

rule_link *list = NULL;
rule_link *last = NULL;

dynamic_rule_link *dynamic_table = NULL;

log_link *log_l = NULL;

/* For Hook */
static struct nf_hook_ops nfho_hook;

/* Globals for the devices */
int major_rules;
int major_rules_active;

int major_log;
int major_log_size;

struct class *m_c_fw;

struct device * dev_rules;
struct device * dev_rules_active;
struct device * dev_log;
struct device * dev_log_size;

dev_t m_dev_rules;
dev_t m_dev_rules_active;

dev_t m_dev_log;
dev_t m_dev_log_size;


/****** Helper Functions ******/
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
	log_link *curr = log_l;
	log_link *new_link;
	log_row_t *new;
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

	printk("here");

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

int get_packet(struct sk_buff *skb, const struct net_device *in, int hooknum) {
	rule_t input;
	struct iphdr    * iph;
	struct tcphdr   * tcph;
	struct udphdr   * udph;


	input.src_ip 	= *((unsigned int *)(skb->data + 12));
	input.dst_ip 	= *((unsigned int *)(skb->data + 16));
	input.protocol 	= *((__u8 *) (skb->data + 9));

	input.src_port = 0;
	input.dst_port = 0;
	input.ack = ACK_ANY;

	// Check that the packet came from the right network device
	if (in->name != NULL) {
		if (strcmp(in->name, IN_NET_DEVICE_NAME) == 0) {
			input.direction = DIRECTION_IN;
		} else if (strcmp(in->name, OUT_NET_DEVICE_NAME) == 0) {
			input.direction = DIRECTION_OUT;
		}
	} else {
		// Allow other traffic
		return 1;
	}

	iph 	= ip_hdr(skb);
	tcph 	= (struct tcphdr *)((__u32 *)iph + iph->ihl);
	udph 	= (struct udphdr *)((__u32 *)iph + iph->ihl);

	// If the firewall is inactive, let all packets pass
	if (firewall_active == 0) {
		log_entry(&input, NULL, REASON_FW_INACTIVE, hooknum, 1);
		return 1;
	}

	if (input.protocol == PROT_ICMP) {
		input.src_port = PORT_ANY;
		input.dst_port = PORT_ANY;
	} else if (input.protocol == PROT_UDP) {
		input.src_port = udph->source;
		input.dst_port = udph->dest;
	} else if (input.protocol == PROT_TCP) {
		input.src_port = tcph->source;
		input.dst_port = tcph->dest;
		input.ack = tcph->ack ? ACK_YES : ACK_NO;

		// Handle X_MAS
		if (tcph->fin && tcph->urg && tcph->psh) {
			log_entry(&input, NULL, REASON_XMAS_PACKET, hooknum, 0);
			return 0;
		}
	}

	if (input.protocol != PROT_TCP || 
		(input.protocol == PROT_TCP && !tcph->ack)) {
		// No need to do the dynamic test, since the static rules come first
		if(check_static_action(input, hooknum)) {
			if (input.protocol == PROT_TCP) {
				create_dynamic_rule(input, tcph);
			}

			return 1;
		} else {
			return 0;
		}
	}

	// Check dynamic rule table
	return check_dynamic_action(input, tcph);
}

/* Hook Function */
static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	return get_packet(skb, in, hooknum);
}


/* fw_rules functions */
static ssize_t rules_show_func(struct device *dev, struct device_attribute *attr, char *buf) {
	return snprintf(buf, PAGE_SIZE, "%d", num_of_rules);
}

static ssize_t rules_store_func(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	return 1;
}

static DEVICE_ATTR(fw_rules, 0666, rules_show_func, rules_store_func);


/* active functions */
static ssize_t active_show_func(struct device *dev, struct device_attribute *attr, char *buf) {
	return 0;
}

static ssize_t active_store_func(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	if (buf[0] == '1') {
		firewall_active = 1;
		printk(KERN_INFO "Firewall activated\n");
	} else {
		firewall_active = 0;
		printk(KERN_INFO "Firewall shutdown\n");
	}

	return 1;
}

static DEVICE_ATTR(active, 0666, active_show_func, active_store_func);



/* fw_log functions */
static ssize_t log_show_func(struct device *dev, struct device_attribute *attr, char *buf) {
	return 0;
}

static ssize_t log_store_func(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	return 1;
}

static DEVICE_ATTR(fw_log, 0444, log_show_func, log_store_func);


static int device_open(struct inode *inode, struct file *file) {
	return 0;
}

log_link *curr_log_entry = NULL;

static ssize_t read_log(struct file *file, char __user * buffer, size_t length, loff_t * offset) {
    char buf[100] = {0,};
    

    if (curr_log_entry == NULL) {
    	curr_log_entry = log_l;
    }

    if (curr_log_entry == NULL) {
    	return 0;
    }

    // Timestamp
	snprintf(buf,PAGE_SIZE, "%lu ", curr_log_entry->entry.timestamp);
	strcat(buffer, buf);

	// Protocol
	snprintf(buf,PAGE_SIZE, "%d ", curr_log_entry->entry.protocol);
	strcat(buffer, buf);

	// Action
	snprintf(buf,PAGE_SIZE, "%d ", curr_log_entry->entry.action);
	strcat(buffer, buf);

	// Hooknum
	snprintf(buf,PAGE_SIZE, "%d ", curr_log_entry->entry.hooknum);
	strcat(buffer, buf);

	// IPs
	snprintf(buf, PAGE_SIZE, "%d.%d.%d.%d ", NIPQUAD(curr_log_entry->entry.src_ip));
	strcat(buffer, buf);

	snprintf(buf, PAGE_SIZE, "%d.%d.%d.%d ", NIPQUAD(curr_log_entry->entry.dst_ip));
	strcat(buffer, buf);

	// Ports
	snprintf(buf,PAGE_SIZE, "%d ", ntohs(curr_log_entry->entry.src_port));
	strcat(buffer, buf);

	snprintf(buf,PAGE_SIZE, "%d ", ntohs(curr_log_entry->entry.dst_port));
	strcat(buffer, buf);

	// Reason
	snprintf(buf,PAGE_SIZE, "%d ", curr_log_entry->entry.reason);
	strcat(buffer, buf);

	// Count
	snprintf(buf,PAGE_SIZE, "%d\n", curr_log_entry->entry.count);
	strcat(buffer, buf);

	curr_log_entry = curr_log_entry->next;

    return 0;
}

/* Get the clear log command from the user, and execute */
static ssize_t clear_log_func(struct file *file, const char __user * buffer, size_t length, loff_t * offset) {
	clear_log();

	return 0;
}

/***** Log Size *****/

static ssize_t log_size_show_func(struct device *dev, struct device_attribute *attr, char *buf) {
	return snprintf(buf, PAGE_SIZE, "%d", log_size_num);
}

static ssize_t log_size_store_func(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
	return 1;
}

static DEVICE_ATTR(log_size, 0666, log_size_show_func, log_size_store_func);

/* Read the rule sent from the user, parse it, and add it to table */
static ssize_t write_rule(struct file *file, const char __user * buffer, size_t length, loff_t * offset) {
	int src_size, dst_size, dir, src_port, dst_port, ack;
	short protocol, action;
	char src_ip_str[16] = {0,};
	char dst_ip_str[16] = {0,};
	rule_link *rule = kmalloc(sizeof(rule_link), GFP_KERNEL);

	if (rule == NULL) {
		printk(KERN_INFO "Error in kmalloc: Could not allocate a new rule.");
		return 0;
	}

	if (strcmp("clear_rule_table00000", buffer) == 0) {
		clear_rules();

		return 0;
	}

	sscanf(buffer, "%s %d %s %d %s %d %hd %d %d %d %hd", rule->rule.rule_name, &dir, src_ip_str, &src_size, dst_ip_str, &dst_size, &protocol, &src_port, &dst_port, &ack, &action);

	// Direction
	if (dir == 1) {
		rule->rule.direction = DIRECTION_IN;
	} else if (dir == 2) {
		rule->rule.direction = DIRECTION_OUT;
	} else if (dir == 3) {
		rule->rule.direction = DIRECTION_ANY;
	}

	// Source IP/Mask
	rule->rule.src_ip = in_aton(src_ip_str);
	rule->rule.src_prefix_size = src_size;

	// Dest IP/Mask
	rule->rule.dst_ip = in_aton(dst_ip_str);
	rule->rule.dst_prefix_size = dst_size;

	rule->rule.protocol = protocol;

	// Ports
	rule->rule.src_port = htons(src_port);
	rule->rule.dst_port = htons(dst_port);

	// Ack
	if (ack == 1) {
		rule->rule.ack = ACK_NO;
	} else if (ack == 2) {
		rule->rule.ack = ACK_YES;
	} else if (ack == 3) {
		rule->rule.ack = ACK_ANY;
	}

	// Action
	rule->rule.action = action;

	// Add rule to list
	if (list == NULL) {
		list = rule;
		last = rule;
	} else {
		last->next = rule;
		last = rule;
	}

	num_of_rules++;

	return 0;
}

rule_link *curr_rule = NULL;

static ssize_t read_rules(struct file *file, char __user * buffer, size_t length, loff_t * offset) {
	char tmp[100] = {0,};
	int port;

	if (curr_rule == NULL) {
		curr_rule = list;
	}

	if (curr_rule == NULL) {
		return 0;
	}

	// Name
	strcat(buffer, curr_rule->rule.rule_name);
	strcat(buffer, " ");

	// Direction
	if (curr_rule->rule.direction == DIRECTION_IN) {
		strcat(buffer, "in ");
	} else if (curr_rule->rule.direction == DIRECTION_OUT) {
		strcat(buffer, "out ");
	} else {
		strcat(buffer, "any ");
	}

	// Source IP
	if (curr_rule->rule.src_ip == in_aton("0.0.0.0")) {
		strcat(buffer, "any ");
	} else {
		snprintf(tmp, PAGE_SIZE, "%d.%d.%d.%d/%d ", NIPQUAD(curr_rule->rule.src_ip), curr_rule->rule.src_prefix_size);
		strcat(buffer, tmp);
	}

	// Destination IP
	if (curr_rule->rule.dst_ip == in_aton("0.0.0.0")) {
		strcat(buffer, "any ");
	} else {
		snprintf(tmp, PAGE_SIZE, "%d.%d.%d.%d/%d ", NIPQUAD(curr_rule->rule.dst_ip), curr_rule->rule.dst_prefix_size);
		strcat(buffer, tmp);
	}

	// Protocol
	if (curr_rule->rule.protocol == PROT_ICMP) {
		strcat(buffer, "ICMP ");
	} else if (curr_rule->rule.protocol == PROT_TCP) {
		strcat(buffer, "TCP ");
	} else if (curr_rule->rule.protocol == PROT_UDP) {
		strcat(buffer, "UDP ");
	} else if (curr_rule->rule.protocol == PROT_OTHER) {
		strcat(buffer, "other ");
	} else if (curr_rule->rule.protocol == PROT_ANY) {
		strcat(buffer, "any ");
	} else {
		snprintf(tmp, PAGE_SIZE, "%d ", curr_rule->rule.protocol);
		strcat(buffer, tmp);
	}

	// Source Port
	port = ntohs(curr_rule->rule.src_port);
	if (port == 0) {
		strcat(buffer, "any ");
	} else if (port == 1023) {
		strcat(buffer, ">1023 ");
	} else {
		snprintf(tmp, PAGE_SIZE, "%d ", port);
		strcat(buffer, tmp);
	}

	// Destination Port
	port = ntohs(curr_rule->rule.dst_port);
	if (port == 0) {
		strcat(buffer, "any ");
	} else if (port == 1023) {
		strcat(buffer, ">1023 ");
	} else {
		snprintf(tmp, PAGE_SIZE, "%d ", port);
		strcat(buffer, tmp);
	}

	// Ack
	if (curr_rule->rule.ack == ACK_NO) {
		strcat(buffer, "no ");
	} else if (curr_rule->rule.ack == ACK_YES) {
		strcat(buffer, "yes ");
	} else {
		strcat(buffer, "any ");
	}

	// Action
	if (curr_rule->rule.action == 0) {
		strcat(buffer, "drop\n");
	} else {
		strcat(buffer, "accept\n");
	}

	curr_rule = curr_rule->next;

	return 0;
}

struct file_operations fops_rules = {
	.write = write_rule,
	.read = read_rules,
	.owner = THIS_MODULE
};

struct file_operations fops_active = {
	.owner = THIS_MODULE	
};

struct file_operations fops_log = {
	.open = device_open,
	.read = read_log,
	.write = clear_log_func,
	.owner = THIS_MODULE	
};

struct file_operations fops_log_size = {
	.owner = THIS_MODULE	
};

/* Init function */
static int __init module_init_function(void) {
	/* HOOKS */
	nfho_hook.hook = hook_func;
	nfho_hook.hooknum = NF_INET_FORWARD;
	nfho_hook.pf = PF_INET;
	nfho_hook.priority = NF_IP_PRI_FIRST;

	/* Register the hooks in the OS */
	nf_register_hook(&nfho_hook);

	/******** Create Devices ********/

	/* Create fw - The parent */
	m_c_fw = class_create(THIS_MODULE, "fw");


	/* Create fw_rules device */
	major_rules = register_chrdev(0, "fw_rules", &fops_rules);

	m_dev_rules = MKDEV(major_rules, 0);

	dev_rules = device_create(m_c_fw, NULL, m_dev_rules, NULL, "fw_rules");

	device_create_file(dev_rules, &dev_attr_fw_rules);

	/* Create active device */
	major_rules_active = register_chrdev(0, "active", &fops_active);

	m_dev_rules_active = MKDEV(major_rules_active, 0);

	dev_rules_active = device_create(m_c_fw, dev_rules, m_dev_rules_active, NULL, "active");

	device_create_file(dev_rules_active, &dev_attr_active);

	/* Create fw_log device */
	major_log = register_chrdev(0, "fw_log", &fops_log);

	m_dev_log = MKDEV(major_log, 0);

	dev_log = device_create(m_c_fw, NULL, m_dev_log, NULL, "fw_log");

	device_create_file(dev_log, &dev_attr_fw_log);

	/* Create log_size device */
	major_log_size = register_chrdev(0, "log_size", &fops_log_size);

	m_dev_log_size = MKDEV(major_log_size, 0);

	dev_log_size = device_create(m_c_fw, dev_log, m_dev_log_size, NULL, "log_size");

	device_create_file(dev_log_size, &dev_attr_log_size);

	return 0;
}

static void __exit module_exit_function(void) {
	clear_rules();
	clear_dynamic_rules();
	clear_log();

	/* Clear the hooks from the OS */
	nf_unregister_hook(&nfho_hook);

	/* unregister active */
	device_remove_file(dev_rules_active, &dev_attr_active);

	device_destroy(m_c_fw, m_dev_rules_active);

	unregister_chrdev(major_rules_active, "active");

	/* unregister fw_rules */
	device_remove_file(dev_rules, &dev_attr_fw_rules);

	device_destroy(m_c_fw, m_dev_rules);

	unregister_chrdev(major_rules, "fw_rules");

	/* unregister active */
	device_remove_file(dev_log_size, &dev_attr_log_size);

	device_destroy(m_c_fw, m_dev_log_size);

	unregister_chrdev(major_log_size, "log_size");

	/* unregister fw_log */
	device_remove_file(dev_log, &dev_attr_fw_log);

	device_destroy(m_c_fw, m_dev_log);

	unregister_chrdev(major_log, "fw_log");


	/* unregister fw */

	class_destroy(m_c_fw);
}

module_init(module_init_function);
module_exit(module_exit_function);