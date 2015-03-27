#include <sys/types.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include "braaoids.h"
#include "braaasn.h"

static inline asnobject * braa_RequestPDU_Create(int type)
{
	asnobject ** pduc;
	asnobject * pdu;
	
	assert(pduc = (asnobject**) gmalloc(sizeof(struct braa_asnobject*) * 4));

	pduc[0] = braa_ASNObject_Create(BRAAASN_INTEGER, type, NULL);
	pduc[1] = braa_ASNObject_Create(BRAAASN_INTEGER, 0, NULL);
	pduc[2] = braa_ASNObject_Create(BRAAASN_INTEGER, 0, NULL);
	pduc[3] = braa_ASNObject_Create(BRAAASN_SEQUENCE, 0, NULL);

	pdu = braa_ASNObject_Create(type, 4, pduc);
	return(pdu);
}

void braa_RequestPDU_ModifyID(asnobject *pdu, int to)
{
	((asnobject **) pdu->pdata)[0]->ldata = to;
}

asnobject * braa_GetRequestPDU_Create(void)
{
	return(braa_RequestPDU_Create(BRAAASN_PDU_GETREQUEST));
}

asnobject * braa_GetNextRequestPDU_Create(void)
{
	return(braa_RequestPDU_Create(BRAAASN_PDU_GETNEXTREQUEST));
}

asnobject * braa_SetRequestPDU_Create(void)
{
	return(braa_RequestPDU_Create(BRAAASN_PDU_SETREQUEST));
}

void braa_GetRequestPDU_Insert(asnobject *pdu, oid *o)
{
	asnobject * oid = braa_ASNObject_Create(BRAAASN_OID, 0, braa_OID_Duplicate(o)), 
			  * var,
			  ** varseql,
			  ** vsq = (asnobject**) (((asnobject**) pdu->pdata)[3]->pdata);
	u_int32_t vsl = ((asnobject**) pdu->pdata)[3]->ldata;
	
	assert(varseql = (struct braa_asnobject**) gmalloc(sizeof(struct braa_asnobject*) * 2));

	varseql[0] = oid;
	varseql[1] = braa_ASNObject_Create(BRAAASN_NULL, 0, NULL);

	var = braa_ASNObject_Create(BRAAASN_SEQUENCE, 2, varseql);

	assert(vsq = (asnobject **) grealloc(vsq, sizeof(asnobject*) * (vsl + 1)));

	vsq[vsl ++] = var;
	
	((asnobject**) pdu->pdata)[3]->pdata = vsq;
	((asnobject**) pdu->pdata)[3]->ldata = vsl;
}

void braa_SetRequestPDU_Insert(asnobject *pdu, oid *o, asnobject *value)
{
	asnobject * oid = braa_ASNObject_Create(BRAAASN_OID, 0, braa_OID_Duplicate(o)), 
			  * var,
			  ** varseql,
			  ** vsq = (asnobject**) (((asnobject**) pdu->pdata)[3]->pdata);
	u_int32_t vsl = ((asnobject**) pdu->pdata)[3]->ldata;
	
	assert(varseql = (struct braa_asnobject**) gmalloc(sizeof(struct braa_asnobject*) * 2));

	varseql[0] = oid;
	varseql[1] = value;

	var = braa_ASNObject_Create(BRAAASN_SEQUENCE, 2, varseql);

	assert(vsq = (asnobject **) grealloc(vsq, sizeof(asnobject*) * (vsl + 1)));

	vsq[vsl ++] = var;
	
	((asnobject**) pdu->pdata)[3]->pdata = vsq;
	((asnobject**) pdu->pdata)[3]->ldata = vsl;
}

static inline asnobject * braa_Msg_Create(asnobject *pdu, char * community, int version)
{
	asnobject **msgc;
	
	assert(community = strdup(community));
	assert(msgc = (asnobject**) gmalloc(sizeof(asnobject*) * 3));

	msgc[0] = braa_ASNObject_Create(BRAAASN_INTEGER, version, NULL);
	msgc[1] = braa_ASNObject_Create(BRAAASN_OCTETSTRING, 0, community);
	msgc[2] = pdu;
	return(braa_ASNObject_Create(BRAAASN_SEQUENCE, 3, msgc));
}

asnobject * braa_GetRequestMsg_Create(char * community, int version)
{
	asnobject * pdu = braa_GetRequestPDU_Create();
	return(braa_Msg_Create(pdu, community, version));
}

asnobject * braa_SetRequestMsg_Create(char * community, int version)
{
	asnobject * pdu = braa_SetRequestPDU_Create();
	return(braa_Msg_Create(pdu, community, version));
}

asnobject * braa_GetNextRequestMsg_Create(char * community, int version)
{
	asnobject * pdu = braa_GetNextRequestPDU_Create();
	return(braa_Msg_Create(pdu, community, version));
}

void braa_GetRequestMsg_Insert(asnobject *msg, oid *o)
{
	braa_GetRequestPDU_Insert(((asnobject**) msg->pdata)[2], o);
}

void braa_GetNextRequestMsg_Insert(asnobject *msg, oid *o)
{
	braa_GetRequestPDU_Insert(((asnobject**) msg->pdata)[2], o);
}

void braa_SetRequestMsg_Insert(asnobject *msg, oid *o, asnobject *val)
{
	braa_SetRequestPDU_Insert(((asnobject**) msg->pdata)[2], o, val);
}

void braa_RequestMsg_ModifyID(asnobject *msg, int to)
{
	braa_RequestPDU_ModifyID(((asnobject **) msg->pdata)[2], to);
}

int braa_Msg_Identify(asnobject *msg)
{
	int t;
	if(msg->type != BRAAASN_SEQUENCE) return(BRAAASN_PDU_UNKNOWN);
	if(msg->ldata != 3) return(BRAAASN_PDU_UNKNOWN);
	
	t = ((asnobject**) msg->pdata)[2]->type;
	
	if(t == BRAAASN_PDU_GETRESPONSE || t == BRAAASN_PDU_GETREQUEST ||
	   t == BRAAASN_PDU_GETNEXTREQUEST || t == BRAAASN_PDU_SETREQUEST)
		return(t);
	else
		return(BRAAASN_PDU_UNKNOWN);
}

int braa_PDUMsg_GetVariableCount(asnobject *msg)
{
	asnobject * varbindings = (asnobject*) ((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[3];
	if(varbindings->type != BRAAASN_SEQUENCE) return(0);
	return(varbindings->ldata);
}

asnobject * braa_PDUMsg_GetVariableName(asnobject *msg, int n)
{
	asnobject * varbindings = (asnobject*) (((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[3]);
	
	if(((asnobject**) varbindings->pdata)[n]->type != BRAAASN_SEQUENCE) return(NULL);
	if(((asnobject**) varbindings->pdata)[n]->ldata != 2) return(NULL);
	return(((asnobject**) (((asnobject**) varbindings->pdata)[n]->pdata))[0]);
}

asnobject * braa_PDUMsg_GetVariableValue(asnobject *msg, int n)
{
	asnobject * varbindings = (asnobject*) (((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[3]);
	return(((asnobject**) (((asnobject**) varbindings->pdata)[n]->pdata))[1]);
}

int braa_PDUMsg_GetErrorCode(asnobject *msg)
{
	asnobject * rc = (asnobject*) (((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[1]);
	if(rc->type != BRAAASN_INTEGER) return(BRAA_ERROR_UNKNOWN);
	return(rc->ldata);
}

int braa_PDUMsg_GetErrorIndex(asnobject *msg)
{
	asnobject * rc = (asnobject*) (((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[2]);
	if(rc->type != BRAAASN_INTEGER) return(0);
	return(rc->ldata);
}

int braa_PDUMsg_GetRequestID(asnobject *msg)
{
	asnobject * rc = (asnobject*) (((asnobject**) (((asnobject**) msg->pdata)[2]->pdata))[0]);
	if(rc->type != BRAAASN_INTEGER) return(BRAA_ERROR_UNKNOWN);
	return(rc->ldata);
}


static char * error_table[] = {"[0] Unknown error", "[1] Too big", "[2] No such name", "[3] Bad value", "[4] Read only", "[5] Generic error"};

char * braa_StrError(int error)
{
	if(error < 0 || error > 5) return(error_table[BRAA_ERROR_UNKNOWN]);
	return(error_table[error]);
}

