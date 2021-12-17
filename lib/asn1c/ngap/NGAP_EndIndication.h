/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.7.0/38413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_NGAP_EndIndication_H_
#define	_NGAP_EndIndication_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_EndIndication {
	NGAP_EndIndication_no_further_data	= 0,
	NGAP_EndIndication_further_data_exists	= 1
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_EndIndication;

/* NGAP_EndIndication */
typedef long	 NGAP_EndIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_EndIndication;
asn_struct_free_f NGAP_EndIndication_free;
asn_struct_print_f NGAP_EndIndication_print;
asn_constr_check_f NGAP_EndIndication_constraint;
per_type_decoder_f NGAP_EndIndication_decode_aper;
per_type_encoder_f NGAP_EndIndication_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_EndIndication_H_ */
#include <asn_internal.h>
