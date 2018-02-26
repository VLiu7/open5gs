/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../support/S1AP-PDU.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted`
 */

#ifndef	_S1ap_ENBX2ExtTLA_H_
#define	_S1ap_ENBX2ExtTLA_H_


#include "asn_application.h"

/* Including external dependencies */
#include "S1ap-TransportLayerAddress.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct S1ap_ENBX2GTPTLAs;
struct ProtocolExtensionContainer;

/* S1ap-ENBX2ExtTLA */
typedef struct S1ap_ENBX2ExtTLA {
	S1ap_TransportLayerAddress_t	*iPsecTLA	/* OPTIONAL */;
	struct S1ap_ENBX2GTPTLAs	*gTPTLAa	/* OPTIONAL */;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1ap_ENBX2ExtTLA_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_ENBX2ExtTLA;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "S1ap-ENBX2GTPTLAs.h"
#include "ProtocolExtensionContainer.h"

#endif	/* _S1ap_ENBX2ExtTLA_H_ */
#include "asn_internal.h"
