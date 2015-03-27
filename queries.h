
struct query_hostrange
{
	struct query_hostrange * next;
	
	u_int32_t start;
	u_int32_t end;
	u_int16_t port;
	
	int query_count;
	char ** queries;
	char * community;

	char ** get_ids;
	char ** set_ids;
	char ** walk_ids;
	
	char get_count;
	char set_count;
	char walk_count;
	oid ** first_oid;

	asnobject * get_message;	
	asnobject * set_message;
}; 

int bapp_rangesplit_query(struct query_hostrange ** head, char * string, char * errbuff, int len);

struct query
{
	struct query * hashnext;
	struct query * listnext;
	
	u_int32_t host;

	char get_retries;
	char set_retries;

	oid ** latest_oid;
	char * walk_retries; 
	struct timeb * walk_contact;
	
	struct query_hostrange * range;
}; /* 26 + 2 bytes */

struct queryhash
{
	int version, responses_needed, responses_received;

	struct query * last_sent;

	struct query * list;
#define QUERY_HASH_SIZE 256
	struct query * hash[QUERY_HASH_SIZE];
};

/* request ID:

   7 bits (optional) WALK ID + 16 bits TIMESTAMP + 8 bits PDU TYPE

*/

struct queryhash * bapp_make_hash(int version, struct query_hostrange *head, char * errbuf, int len);


int bapp_processmessages(int s, struct queryhash *qh, int hexdump);
int bapp_sendmessage(struct queryhash *qh, int s, int retries, int xdelay, int sdelay, int pass_delay);
#define MAX_RECV_PACKET 1600
#define RETRIES_MAX 126
#define DEFAULT_XDELAY 20000
