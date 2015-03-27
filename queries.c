#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include "braaoids.h"
#include "braaasn.h"
#include "braaprotocol.h"
#include "queries.h"

#define MAX_PACKET_SIZE 1300

static struct query_hostrange * duplicate_hostrange(struct query_hostrange *h)
{
	struct query_hostrange * n;
	int i;
	
	assert(n = (struct query_hostrange*) gmalloc(sizeof(struct query_hostrange)));
	
	n->port = h->port;
	assert(n->community = strdup(h->community));
	
	n->query_count = h->query_count;
	assert(n->queries = (char**) gmalloc(sizeof(char*) * h->query_count));
	for(i = 0; i<n->query_count; i++)
		assert(n->queries[i] = strdup(h->queries[i]));

	return(n);
}

int bapp_rangesplit_query(struct query_hostrange ** head, char * string, char * errbuff, int len)
{
	/* [public@]hostrange[:port]:whatever/id,whatever/id,whatever/id */
	char * community = "public",
	     * pstr, * hostrange = NULL,
		 * queries, * portno = NULL,
		 * nxqry;
	struct query_hostrange * hr, * prev;
	u_int32_t hostrange_start, hostrange_end;
	u_int16_t port = 161;
	struct in_addr ina;
		 
	assert(string = strdup(string));
	
	if((pstr = index(string, '@')))
	{
		community = string;
		*pstr = 0;
		hostrange = pstr + 1;
	}
	else
		hostrange = string;
	
	if(!(pstr = index(hostrange, ':')))
	{
		snprintf(errbuff, len, "Invalid syntax: '%s'.", string);
		goto err;
	}
	
	*pstr = 0;
	queries = pstr + 1;

	if((pstr = index(queries, ':')))
	{
		portno = queries;
		*pstr = 0;
		queries = pstr + 1;
	}

	if((pstr = index(hostrange, '-')))
	{
		*pstr = 0;
		pstr++;
	}
	
	if(!inet_aton(hostrange, &ina))
	{
		snprintf(errbuff, len, "Invalid IP address: '%s'.", hostrange);
		goto err;
	}
	
	hostrange_start = ntohl(ina.s_addr);
	
	if(pstr)
	{
		if(!inet_aton(pstr, &ina))
		{
			snprintf(errbuff, len, "Invalid IP address: '%s'.", pstr);
			goto err;
		}
	
		hostrange_end = ntohl(ina.s_addr);
	}
	else
		hostrange_end = hostrange_start;
	
	if(hostrange_end < hostrange_start)
	{
		snprintf(errbuff, len, "Invalid range: '%s - %s'.", hostrange, pstr);
		goto err;
	}
	
	if(portno)
	{
		char * eptr;
		port = strtol(portno, &eptr, 10);
		if(*eptr)
		{
			snprintf(errbuff, len, "Invalid port: '%s'.", portno);
			goto err;
		}
		if(port > 65535 || port < 1) 
		{
			snprintf(errbuff, len, "Invalid port: '%s'.", portno);
			goto err;
		}
	}
	
	for(hr = *head, prev = (struct query_hostrange*) head; hr; prev = hr, hr = hr->next)
	{
		if(port != hr->port) continue;
		if(strcmp(community, hr->community)) continue;

		if(hostrange_start >= hr->start && hostrange_end <= hr->end)
		{
			u_int32_t bef = hostrange_start - hr->start, aft = hr->end - hostrange_end;
			
			if(bef)
			{
				struct query_hostrange * bh;
				bh = duplicate_hostrange(hr);
				
				bh->start = hr->start;
				bh->end = hostrange_start - 1;
				prev->next = bh;
				bh->next = hr;
			}
			if(aft)
			{
				struct query_hostrange * ah;
				ah = duplicate_hostrange(hr);
				
				ah->start = hostrange_end + 1;
				ah->end = hr->end;
				prev->next = ah;
				ah->next = hr;
			}
			hr->start = hostrange_start;
			hr->end = hostrange_end;
			break;
		}
	}
	
	if(!hr)
	{
		assert(hr = (struct query_hostrange*) gmalloc(sizeof(struct query_hostrange)));
		prev->next = hr;
		hr->next = NULL;

		hr->start = hostrange_start;
		hr->end = hostrange_end;
		assert(hr->community = strdup(community));
		hr->query_count = 0;
		hr->queries = NULL;
		hr->port = port;
	}
	
	do
	{
		if((nxqry = index(queries, ',')))
		{
			*nxqry = 0;
			nxqry++;
		}
		
		hr->queries = (char**) grealloc(hr->queries, (hr->query_count + 1) * sizeof(char*));
		assert(hr->queries[hr->query_count++] = strdup(queries));
	}
	while((queries = nxqry));
	
	return(1);

err:
	free(string);
	return(0);
}

struct queryhash * bapp_make_hash(int version, struct query_hostrange *head, char * errbuf, int len)
{
	struct query_hostrange * hr;
	struct queryhash * qh;
	
	assert(qh = (struct queryhash*) malloc(sizeof(struct queryhash)));
	memset(qh, 0, sizeof(struct queryhash));
	qh->version = version;
	qh->responses_received = qh->responses_needed = 0;
	
	for(hr = head; hr; hr = hr->next)
	{
		int qc = hr->query_count, i;

		asnobject * setmsg = NULL;
		asnobject * getmsg = NULL;

		oid ** first_oids = NULL;
		char ** get_ids = NULL;
		char ** set_ids = NULL;
		char ** walk_ids = NULL;
		
		int get_count = 0, set_count = 0, walk_count = 0;
		u_int32_t host;
		
		struct query * hosts;

		for(i = 0; i<qc; i++)
		{
			char * q = hr->queries[i];
			char * pstr, * id = NULL;
			int type = 0;
			asnobject * value;
			oid * o;
			
			
			if((pstr = index(q, '/')))
			{
				*pstr = 0;
				id = pstr + 1;
			}
			
			if(strlen(q) < 2)
			{
				snprintf(errbuf, len, "Invalid query: '%s'!", q);
				return(0);
			}
			
			if(q[strlen(q) - 1] == '*')
			{
				type = 2; /* walk */
				if(q[strlen(q) - 2] != '.')
				{
					snprintf(errbuf, len, "Invalid query: '%s'!", q);
					return(0);
				}
				q[strlen(q) - 2] = 0;
				assert(walk_ids = (char**) grealloc(walk_ids, (walk_count + 1) * sizeof(char*)));
				walk_ids[walk_count] = id;
			}
			else if((pstr = index(q, '=')))
			{
				type = 1; /* set */
				*pstr = 0;
				pstr++;
				
				if(!*pstr)
				{
					snprintf(errbuf, len, "Invalid value: '%s'!", pstr);
					return(0);
				}
				
				if(!(value = braa_ASNObject_CreateFromString(pstr)))
				{
					snprintf(errbuf, len, "Invalid value: '%s'!", pstr);
					return(0);
				}
				assert(set_ids = (char**) grealloc(set_ids, (set_count + 1) * sizeof(char*)));
				set_ids[walk_count] = id;
			}
			else
			{
				type = 0;
				assert(get_ids = (char**) grealloc(get_ids, (get_count + 1) * sizeof(char*)));
				get_ids[get_count] = id;
			}
			
			if(!(o = braa_OID_CreateFromString(q)))
			{
				snprintf(errbuf, len, "Invalid OID: '%s'!", q);
				return(0);
			}
			
			switch(type)
			{
				case 0:
					if(!getmsg)
						getmsg = braa_GetRequestMsg_Create(hr->community, version);
					
					braa_GetRequestMsg_Insert(getmsg, o);
					get_count++;
					break;
				case 1:
					if(!setmsg)
						setmsg = braa_SetRequestMsg_Create(hr->community, version);
					
					braa_SetRequestMsg_Insert(setmsg, o, value);
					set_count++;
					break;
				case 2:
					assert(first_oids = (oid**) grealloc(first_oids, (walk_count + 1) * sizeof(oid*)));
					first_oids[walk_count++] = o;
					break;
			}
		}
		if(getmsg)
			qh->responses_needed += hr->end - hr->start + 1;
		if(setmsg)
			qh->responses_needed += hr->end - hr->start + 1;
		if(first_oids)
			qh->responses_needed += hr->end - hr->start + 1;
			
		assert(hosts = (struct query*) gmalloc(sizeof(struct query) * (hr->end - hr->start + 1)));

		hr->get_message = getmsg;
		hr->set_message = setmsg;
		hr->get_ids = get_ids;
		hr->set_ids = set_ids;
		hr->walk_ids = walk_ids;
		hr->get_count = get_count;
		hr->set_count = set_count;
		hr->walk_count = walk_count;
		hr->first_oid = first_oids;
		
		for(host = hr->start; host <= hr->end; host++)
		{
			struct query * thisquery = hosts + (host - hr->start);
			
			thisquery->host = host;
			
			thisquery->listnext = qh->list;
			qh->list = thisquery;
			
			thisquery->hashnext = qh->hash[host & 0xff];
			qh->hash[host & 0xff] = thisquery;
			
			thisquery->get_retries = thisquery->set_retries = 0;
			
			if(walk_count)
			{
				assert(thisquery->latest_oid = (oid**) gmalloc(sizeof(oid*) * walk_count));
				assert(thisquery->walk_retries = (char*) gmalloc(sizeof(char) * walk_count));
				assert(thisquery->walk_contact = (struct timeb*) gmalloc(sizeof(struct timeb) * walk_count));
				memset(thisquery->latest_oid, 0, sizeof(oid*) * walk_count);
				memset(thisquery->walk_retries, 0, sizeof(char) * walk_count);
				memset(thisquery->walk_contact, 0, sizeof(struct timeb) * walk_count);
			}
			else
			{
				thisquery->walk_retries = NULL;
				thisquery->walk_contact = NULL;
				thisquery->latest_oid = NULL;
			}
			thisquery->range = hr;
		}
	}
	qh->last_sent = qh->list;
	return(qh);
}

int bapp_sendmessage(struct queryhash *qh, int s, int retries, int xdelay, int sdelay, int pass_delay)
{
	struct sockaddr_in dst;
	struct timeval tv;
	struct query * q = qh->last_sent;
	struct query * start_query = qh->last_sent;
	u_int16_t momentid;
	char buffer[MAX_PACKET_SIZE];
	int len, activity = 0;
	

	for(;;)
	{
	 	struct query_hostrange *hr = q->range;
		
		dst.sin_family = PF_INET;
		dst.sin_port = htons(q->range->port);
		dst.sin_addr.s_addr = htonl(q->host);
	

		if(q->range->get_message && (q->get_retries < retries))
		{
			gettimeofday(&tv, NULL);
			momentid = ((tv.tv_sec % 64) * 1000) + (tv.tv_usec / 1000);
			braa_RequestMsg_ModifyID(q->range->get_message, BRAAASN_PDU_GETREQUEST | (momentid << 8));
			if((len = braa_ASNObject_EncodeBER(q->range->get_message, buffer, MAX_PACKET_SIZE)) < 0)
				fprintf(stderr, "Trouble encoding BRAAASN_PDU_GETREQUEST message for %s. Internal error?\n", inet_ntoa(dst.sin_addr));
			else
			{
				if(sendto(s, buffer, len, 0, (struct sockaddr*) &dst, (socklen_t) sizeof(struct sockaddr_in)) < 0)
					perror("sendto");
			}
			q->get_retries++;
			activity = 1;
			if(sdelay) usleep(sdelay);
		}

		if(q->range->set_message && (q->set_retries < retries))
		{
			gettimeofday(&tv, NULL);
			momentid = ((tv.tv_sec % 64) * 1000) + (tv.tv_usec / 1000);
			braa_RequestMsg_ModifyID(q->range->set_message, BRAAASN_PDU_SETREQUEST | (momentid << 8));
			if((len = braa_ASNObject_EncodeBER(q->range->set_message, buffer, MAX_PACKET_SIZE)) < 0)
				fprintf(stderr, "Trouble encoding BRAAASN_PDU_SETREQUEST message for %s. Internal error?\n", inet_ntoa(dst.sin_addr));
			else
				if(sendto(s, buffer, len, 0, (struct sockaddr*) &dst, (socklen_t) sizeof(struct sockaddr_in)) < 0)
					perror("sendto");

			q->set_retries++;
			activity = 1;
			if(sdelay) usleep(sdelay);
		}

		if(q->latest_oid)
		{
			int i, wc = q->range->walk_count;

			for(i = 0; i<wc; i++)
			{
				asnobject * walkmsg;
				struct timeb ft;
				if(q->walk_retries[i] >= retries) continue;
				
				ftime(&ft);
				if(q->walk_retries[i] > 0)
				{
					struct timeb *prv;
					unsigned int msec;

					prv = &q->walk_contact[i];
					msec = (ft.time - prv->time) * 1000 + ft.millitm - prv->millitm;
					
					
					if(msec < pass_delay)
					{
//					printf("msec = %d, pass_delay = %d, waiting\n", msec, pass_delay);
						activity = 1;
						continue;
					}
//					else
//						printf("msec = %d, pass_delay = %d, proceeding\n", msec, pass_delay);
				}
				
				walkmsg = braa_GetNextRequestMsg_Create(hr->community, qh->version);
				gettimeofday(&tv, NULL);
				momentid = ((tv.tv_sec % 64) * 1000) + (tv.tv_usec / 1000);
				braa_RequestMsg_ModifyID(walkmsg, BRAAASN_PDU_GETNEXTREQUEST | (momentid << 8) | (i << 24));

				if(q->latest_oid[i])
					braa_GetNextRequestMsg_Insert(walkmsg,  q->latest_oid[i]);
				else
					braa_GetNextRequestMsg_Insert(walkmsg,  q->range->first_oid[i]);


				if((len = braa_ASNObject_EncodeBER(walkmsg, buffer, MAX_PACKET_SIZE)) < 0)
					fprintf(stderr, "Trouble encoding BRAAASN_PDU_GETNEXTREQUEST message for %s. Internal error?\n", inet_ntoa(dst.sin_addr));
				else
					if(sendto(s, buffer, len, 0, (struct sockaddr*) &dst, (socklen_t) sizeof(struct sockaddr_in)) < 0)
						perror("sendto");

				braa_ASNObject_Dispose(walkmsg);
				q->walk_retries[i]++;
				activity = 1;
				
				memcpy(&q->walk_contact[i], &ft, sizeof(struct timeb));
				
				if(sdelay) usleep(sdelay);
			}
		}

		q = q->listnext;
		if(!q)
		{
			q = qh->list;
			if(xdelay)
				usleep(xdelay);
		}
		
		if(activity)
			break;
		else
		{
			if(q == start_query)
				return(0);
		}
	}
	qh->last_sent = q;
	return(1);
}

int bapp_processmessages(int s, struct queryhash *qh, int hexdump)
{
	for(;;)
	{
		struct sockaddr_in sa;
		socklen_t salen = sizeof(struct sockaddr_in);
		int l;
		char pbuff[MAX_RECV_PACKET];
		asnobject * ao;
		
		struct timeval tv;
		int delay, secd;
		
		if((l = recvfrom(s, pbuff, MAX_RECV_PACKET, 0, (struct sockaddr *) &sa, (socklen_t *) &salen)) <= 0)
		{
			if(errno == EAGAIN) break;
			perror("recvfrom");
		}
		gettimeofday(&tv, NULL);
				
		ao = braa_ASNObject_DecodeBER(pbuff, l);
		if(ao)
		{
			u_int32_t host;
			struct query *q;
			int resp, error, ei;
			
			if(braa_Msg_Identify(ao) != BRAAASN_PDU_GETRESPONSE)
			{
				fprintf(stderr, "%s: Invalid message type!\n", inet_ntoa(sa.sin_addr));
				goto dispose;
			}
			
			host = ntohl(sa.sin_addr.s_addr);
			
			for(q = qh->hash[host & 0xff]; q; q = q->hashnext)
				if(q->host == host) break;
			
			if(!q)
			{
				fprintf(stderr, "%s: Unknown host sending messages!\n", inet_ntoa(sa.sin_addr));
				goto dispose;
			}
			
			resp = braa_PDUMsg_GetRequestID(ao);

			secd = (tv.tv_sec % 64) - (((resp >> 8) & 0xffff) / 1000);
			if(secd < 0) secd = 64 - secd;
			delay = secd * 1000 + (tv.tv_usec / 1000) - (((resp >> 8) & 0xffff) % 1000);

			error = braa_PDUMsg_GetErrorCode(ao);
			ei = braa_PDUMsg_GetErrorIndex(ao);


			switch(resp & 0xff)
			{
				case BRAAASN_PDU_GETREQUEST:
				{
					int v, vc;
					
					if(q->get_retries == RETRIES_MAX) goto dispose;
					qh->responses_received++;
					q->get_retries = RETRIES_MAX;

					vc = braa_PDUMsg_GetVariableCount(ao);
					
					if(error)
					{
						ei--;
						if(ei >= 0 && ei < vc)
						{
							asnobject *name;
							char buffer[500];

							if(q->range->get_ids[ei])
								fprintf(stderr, "%s:", q->range->get_ids[ei]);

							name = braa_PDUMsg_GetVariableName(ao, ei);
							assert(name->type == BRAAASN_OID);
							braa_OID_ToString((oid*) name->pdata, buffer, 500);
							
							fprintf(stderr, "%s:%dms:%s:Error %s.\n", inet_ntoa(sa.sin_addr), delay, buffer, braa_StrError(error));
						}
						else
							fprintf(stderr, "%s:%dms:Error %s. Index: %d.\n", inet_ntoa(sa.sin_addr), delay, braa_StrError(error), ei);
					}
					else
					{
						if(vc > q->range->get_count) vc = q->range->get_count;
						
						for(v = 0; v<vc; v++)
						{
							asnobject * name, * value;
							char buffer[500];
							
							name = braa_PDUMsg_GetVariableName(ao, v);
							value = braa_PDUMsg_GetVariableValue(ao, v);
							assert(name->type == BRAAASN_OID);
					
							if(q->range->get_ids[v])
								printf("%s:", q->range->get_ids[v]);

							printf("%s:%dms:", inet_ntoa(sa.sin_addr), delay);
							braa_OID_ToString((oid*) name->pdata, buffer, 500);
							printf("%s:", buffer);
							braa_ASNObject_ToString(value, buffer, 500, hexdump);
							printf("%s\n", buffer);
						}
					}
					break;
				}
				case BRAAASN_PDU_GETNEXTREQUEST:
				{
					int walkid = resp >> 24;
					assert(walkid < q->range->walk_count);
					
					if(error)
					{
						asnobject *name;
						char buffer[500];

						if(q->range->walk_ids[walkid])
							fprintf(stderr, "%s:", q->range->walk_ids[walkid]);

						assert(ei == 1);

						name = braa_PDUMsg_GetVariableName(ao, 0);
						assert(name->type == BRAAASN_OID);
						braa_OID_ToString((oid*) name->pdata, buffer, 500);
							
						fprintf(stderr, "%s:%dms:%s:Error %s.\n", inet_ntoa(sa.sin_addr), delay, buffer, braa_StrError(error));
						q->walk_retries[walkid] = RETRIES_MAX;
						qh->responses_received++;
					}
					else
					{
						asnobject * name, * value;
						
						assert(braa_PDUMsg_GetVariableCount(ao) == 1);

						name = braa_PDUMsg_GetVariableName(ao, 0);
						assert(name->type == BRAAASN_OID);
							
						if(braa_OID_CompareN(q->range->first_oid[walkid], (oid*) name->pdata))
						{
							char buffer[500];

							if(q->range->walk_ids[walkid])
								fprintf(stderr, "%s:", q->range->walk_ids[walkid]);

							value = braa_PDUMsg_GetVariableValue(ao, 0);
							printf("%s:%dms:", inet_ntoa(sa.sin_addr), delay);
							braa_OID_ToString((oid*) name->pdata, buffer, 500);
							printf("%s:", buffer);
							braa_ASNObject_ToString(value, buffer, 500, hexdump);
							printf("%s\n", buffer);
							if(q->latest_oid[walkid])
								braa_OID_Dispose(q->latest_oid[walkid]);
							
							q->latest_oid[walkid] = braa_OID_Duplicate((oid*) name->pdata);
							q->walk_retries[walkid] = 0;
						}
						else
						{	/* end of walk */
							q->walk_retries[walkid] = RETRIES_MAX;
							qh->responses_received++;
						}
					}
					break;
				
				}
				case BRAAASN_PDU_SETREQUEST:
				{
					int vc, v;
					
					if(q->set_retries == RETRIES_MAX) goto dispose;
					qh->responses_received++;
					q->set_retries = RETRIES_MAX;

					
					vc = braa_PDUMsg_GetVariableCount(ao);

					if(error)
					{
						ei--;
						if(ei >= 0 && ei < vc)
						{
							asnobject *name;
							char buffer[500];

							if(q->range->set_ids[ei])
								fprintf(stderr, "%s:", q->range->set_ids[ei]);

							name = braa_PDUMsg_GetVariableName(ao, ei);
							assert(name->type == BRAAASN_OID);
							braa_OID_ToString((oid*) name->pdata, buffer, 500);
							
							fprintf(stderr, "%s:%dms:%s:Error %s.\n", inet_ntoa(sa.sin_addr), delay, buffer, braa_StrError(error));
						}
						else
							fprintf(stderr, "%s:%dms:Error %s. Index: %d.\n", inet_ntoa(sa.sin_addr), delay, braa_StrError(error), ei);
					}
					else
					{
						if(vc > q->range->set_count) vc = q->range->set_count;
						
						for(v = 0; v<vc; v++)
						{
							asnobject * name;
							char buffer[500];
							
							name = braa_PDUMsg_GetVariableName(ao, v);
							assert(name->type == BRAAASN_OID);
					
							if(q->range->set_ids[v])
								printf("%s:", q->range->set_ids[v]);

							printf("%s:%dms:", inet_ntoa(sa.sin_addr), delay);
							braa_OID_ToString((oid*) name->pdata, buffer, 500);
							printf("%s:OK, set.\n", buffer);
						}
					}
						
					break;
				}
				default:
					fprintf(stderr, "%s: Message cannot be dispatched!\n", inet_ntoa(sa.sin_addr));
					break;		
				
			}
			
//			braa_ASNObject_Dump(ao);
dispose:
			braa_ASNObject_Dispose(ao);
		}
		else
			fprintf(stderr, "%s: Message cannot be decoded!\n", inet_ntoa(sa.sin_addr));
	}
	return(qh->responses_needed == qh->responses_received);
}
