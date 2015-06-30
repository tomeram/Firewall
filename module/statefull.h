/*** Statefull Inspection ***/
#ifndef _STATEFULL_H_
#define _STATEFULL_H_

#include "fw.h"
#include "stateless.h"

/** Structs and Types **/
// Dynamic Rule
typedef struct {
	__be32 			src_ip;
	__be16 			src_port;
	__be32 			dst_ip;
	__be16 			dst_port;
	tcp_type 		protocol;
	ftp_state_enum	ftp_state;
	http_state_enum	http_state;
	unsigned long 	timestamp;	// To check if the rule is still relevant
} dynamic_rule;

// Link for Dynamic Table
typedef struct dynamic_rule_link {
	dynamic_rule rule;
	struct dynamic_rule_link *next;
} dynamic_rule_link;


/** Globals **/
extern int num_of_dynamic_rules;
extern dynamic_rule_link *dynamic_table;

/** Functions **/
void clear_dynamic_rules(void);
void create_dynamic_rule(rule_t input, struct tcphdr *tcph);
void update_ftp_rule(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph);
void update_connection_state(dynamic_rule_link *curr, dynamic_rule_link *prev, struct tcphdr *tcph);
int check_dynamic_action(rule_t input, struct tcphdr *tcph);

#endif // _STATEFULL_H_
