/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "../support/s1ap-r16.7.0/36413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_S1AP_M7Configuration_H_
#define	_S1AP_M7Configuration_H_


#include <asn_application.h>

/* Including external dependencies */
#include "S1AP_M7period.h"
#include "S1AP_Links-to-log.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct S1AP_ProtocolExtensionContainer;

/* S1AP_M7Configuration */
typedef struct S1AP_M7Configuration {
	S1AP_M7period_t	 m7period;
	S1AP_Links_to_log_t	 m7_links_to_log;
	struct S1AP_ProtocolExtensionContainer	*iE_Extensions;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} S1AP_M7Configuration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1AP_M7Configuration;

#ifdef __cplusplus
}
#endif

#endif	/* _S1AP_M7Configuration_H_ */
#include <asn_internal.h>
