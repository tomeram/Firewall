/*** Log Logic ***/
#ifndef _LOG_H_
#define _LOG_H_

#include "fw.h"
#include "stateless.h"

/** Structs and Types **/
// Log Entry
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

// Log Link
typedef struct log_link {
	log_row_t entry;
	struct log_link *next;
} log_link;


/** Globals **/
extern int log_size_num;
extern log_link *log_l;


/** Functions **/
void clear_log(void);
void log_entry(rule_t *input, rule_t *rule, reason_t reason, int hooknum, int action);


#endif // _LOG_H_
