/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../support/S1AP-PDU.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted`
 */

#ifndef	_S1ap_HandoverRequestAcknowledge_H_
#define	_S1ap_HandoverRequestAcknowledge_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ProtocolIE-Container.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* S1ap-HandoverRequestAcknowledge */
typedef struct S1ap_HandoverRequestAcknowledge {
	ProtocolIE_Container_5903P4_t	 protocolIEs;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1ap_HandoverRequestAcknowledge_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_HandoverRequestAcknowledge;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_HandoverRequestAcknowledge_H_ */
#include "asn_internal.h"
