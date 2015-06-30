/*** General Include ***/
#ifndef _FW_H_
#define _FW_H_


/** Includes **/

// Linux devices libs
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/sysfs.h>
#include <asm/uaccess.h>

// internet libs
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// Protocol libs
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// General libs
#include <linux/string.h>
#include <linux/time.h>


/** Defines **/
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

/** Structs and Types **/
// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;

typedef enum {
	FTP			= 1,
	HTTP		= 2,
	OTHER_TCP	= 3
} tcp_type;

typedef enum {
	FTP_HANDSHAKE	= 0
} ftp_state_enum;

typedef enum {
	HTTP_HANDSHAKE	= 0
} http_state_enum;

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

/** Stateless **/
// Static Rule
typedef struct {
	char rule_name[20];
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// Link for the rule list
typedef struct rule_link {
	rule_t rule;
	struct rule_link *next;

} rule_link;

/** Statefull **/
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

typedef struct dynamic_rule_link
{
	dynamic_rule rule;
	struct dynamic_rule_link *next;
} dynamic_rule_link;

/** Log **/
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

#endif // _FW_H_