#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>

#include "braaoids.h"
#include "braaasn.h"
#include "braaprotocol.h"
#include "queries.h"

#define ERRORBUFFER_SIZE 200

void help(void)
{
	printf("braa 0.81 - Mateusz 'mteg' Golicz <mtg@elsat.net.pl>, 2003 - 2006\n");
	printf("usage: braa [options] [query1] [query2] ...\n");
	printf("  -h        Show this help.\n");
	printf("  -2        Claim to be a SNMP2C agent.\n");
	printf("  -v        Show short summary after doing all queries.\n");
	printf("  -x        Hexdump octet-strings\n");
	printf("  -t <s>    Wait <s> seconds for responses.\n");
	printf("  -d <s>    Wait <s> microseconds after sending each packet.\n");
	printf("  -p <s>    Wait <s> miliseconds between subsequent passes.\n");
	printf("  -f <file> Load queries from file <file> (one by line).\n");
	printf("  -a <time> Quit after <time> seconds, independent on what happens.\n");
	printf("  -r <rc>   Retry count (default: 3).\n");
	printf("\n");
	printf("Query format:\n");
	printf("  GET:   [community@]iprange[:port]:oid[/id]\n");
	printf("  WALK:  [community@]iprange[:port]:oid.*[/id]\n");
	printf("  SET:   [community@]iprange[:port]:oid=value[/id]\n");
	printf("\nExamples:\n");
	printf("         public@10.253.101.1:161:.1.3.6.*\n");
	printf("         10.253.101.1-10.253.101.255:.1.3.6.1.2.1.1.4.0=sme\n");
	printf("         10.253.101.1:.1.3.6.1.2.1.1.1.0/description\n");
	printf("\nIt is also possible to specify multiple queries at once:\n");
	printf("         10.253.101.1-10.253.101.255:.1.3.6.1.2.1.1.4.0=sme,.1.3.6.*\n");
	printf("         (Will set .1.3.6.1.2.1.1.4.0 to 'me' and do a walk starting from .1.3.6)\n");
	printf("\n\nValues for SET queries have to be prepended with a character specifying the value type:\n");
	printf("  i      is INTEGER\n");
	printf("  a      is IPADDRESS\n");
	printf("  s      is OCTET STRING\n");
	printf("  o      is OBJECT IDENTIFIER\n");
	printf("If the type specifier is missing, the value type is auto-detected\n");
}

void doquit(int sig)
{
	_exit(0);
}

int main(int argc, char **argv)
{
	/* queries:
	      [community@]host[:port]:oid[/id] - get
		  [community@]host[:port]:oid.*[/id] - walk
		  [community@]host[:port]:oid.[/id]=... - set */
	
	int c, i, ver = BRAA_VERSION_SNMP1, verbose = 0,
	    r = 3, time = 2, sdelay = 0, pass_delay = 500, hexdump = 0;

	struct query_hostrange * head = NULL;
	struct queryhash * qh;
	char error[ERRORBUFFER_SIZE];
	
	while((c = getopt(argc, argv, "a:h2vd:r:p:d:f:t:x")) != EOF)
	{
		switch(c)
		{
			case 'h':
				help();
				return(0);
			case '2': ver = BRAA_VERSION_SNMP2C; break;
			case 'v': verbose ++; break;
			case 't': time = atoi(optarg); break;
			case 'p': pass_delay = atoi(optarg); break;
			case 'd': sdelay = atoi(optarg); break;
			case 'x': hexdump = 1; break;
			case 'r': r = atoi(optarg);
					  if(!r)
					  {
						fprintf(stderr, "Invalid retry count.\n");
						return 1;
					  }
					  break;
			case 'a': 
			{
				int t;
				t = atoi(optarg);
				if(!t)
				{
					fprintf(stderr, "Invalid alarm time.\n");
					return 1;
				}
				signal(SIGALRM, doquit);
				alarm(t);
				break;
			}
			case 'f':
			{
				FILE *fh;
				char buffer[512];
				fh = fopen(optarg, "r");
				if(!fh)
				{
					perror("fopen");
					return(1);
				}

				while(fgets(buffer, 512, fh))
				{
					char *r;

					if((r = index(buffer, '\n')))
						*r = 0;
					
					if(strlen(buffer) > 2)
					{
						if(!bapp_rangesplit_query(&head, buffer, error, ERRORBUFFER_SIZE))
						{
							fprintf(stderr, "Unable to process queries: %s (file %s)\n", error, optarg);
							return(1);
						}
					}
				}
				fclose(fh);
			}
		}
	}
	
	if(optind >= argc && (!head))
	{
		help();
		return(1);
	}
	
	for(i = optind; i < argc; i++)
	{
		if(!bapp_rangesplit_query(&head, argv[i], error, ERRORBUFFER_SIZE))
		{
			fprintf(stderr, "Unable to process queries: %s\n", error);
			return(1);
		}
	}
	
	if(!(qh = bapp_make_hash(ver, head, error, ERRORBUFFER_SIZE)))
	{
		fprintf(stderr, "Unable to process queries: %s\n", error);
		return(1);
	}
	
	{
		int s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		struct timeval tv;
		
		if(s < 0)
		{
			perror("socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)");
			return(1);
		}
		
		if(fcntl(s, F_SETFL, O_NONBLOCK) < 0)
		{
			perror("fcntl(socket, F_SETFL, O_NONBLOCK)");
			return(1);
		}
		
		for(;;)
		{
			if(!bapp_sendmessage(qh, s, r, DEFAULT_XDELAY, sdelay, pass_delay)) break;
			if(bapp_processmessages(s, qh, hexdump)) break;
			usleep(250);
		}
		
		tv.tv_sec = time;
		tv.tv_usec = 0;
		while(!bapp_processmessages(s, qh, hexdump))
		{
			fd_set fds;
			
			FD_ZERO(&fds);
			FD_SET(s, &fds);
			if(select(s + 1, &fds, NULL, NULL, &tv) < 1) break;
		}
		
		if(verbose)
			printf("%d queries made, %d queries acknowledged.\n", qh->responses_needed, qh->responses_received);
	}
	return(0);
}
