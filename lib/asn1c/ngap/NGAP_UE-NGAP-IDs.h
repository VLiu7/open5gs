/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.7.0/38413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_NGAP_UE_NGAP_IDs_H_
#define	_NGAP_UE_NGAP_IDs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_AMF-UE-NGAP-ID.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_UE_NGAP_IDs_PR {
	NGAP_UE_NGAP_IDs_PR_NOTHING,	/* No components present */
	NGAP_UE_NGAP_IDs_PR_uE_NGAP_ID_pair,
	NGAP_UE_NGAP_IDs_PR_aMF_UE_NGAP_ID,
	NGAP_UE_NGAP_IDs_PR_choice_Extensions
} NGAP_UE_NGAP_IDs_PR;

/* Forward declarations */
struct NGAP_UE_NGAP_ID_pair;
struct NGAP_ProtocolIE_SingleContainer;

/* NGAP_UE-NGAP-IDs */
typedef struct NGAP_UE_NGAP_IDs {
	NGAP_UE_NGAP_IDs_PR present;
	union NGAP_UE_NGAP_IDs_u {
		struct NGAP_UE_NGAP_ID_pair	*uE_NGAP_ID_pair;
		NGAP_AMF_UE_NGAP_ID_t	 aMF_UE_NGAP_ID;
		struct NGAP_ProtocolIE_SingleContainer	*choice_Extensions;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_UE_NGAP_IDs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_UE_NGAP_IDs;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_UE_NGAP_IDs_H_ */
#include <asn_internal.h>
