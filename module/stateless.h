/*** Stateless Packet Filtering ***/
#ifndef _STATELESS_H_
#define _STATELESS_H_

/** Includes **/
#include "fw.h"
#include "log.h"

/** Structs and Types **/
// Link for the rule list
typedef struct rule_link {
	rule_t rule;
	struct rule_link *next;

} rule_link;

/** Globals **/
extern int num_of_rules;
extern rule_link *list;
extern rule_link *last;

/** Functions **/
void clear_rules(void);
int check_static_action(rule_t input, int hooknum);

#endif // _STATELESS_H_
