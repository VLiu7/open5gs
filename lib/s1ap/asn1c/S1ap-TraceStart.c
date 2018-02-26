/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-PDU-Contents"
 * 	found in "../support/S1AP-PDU.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted`
 */

#include "S1ap-TraceStart.h"

static asn_TYPE_member_t asn_MBR_S1ap_TraceStart_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct S1ap_TraceStart, protocolIEs),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ProtocolIE_Container_5903P50,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"protocolIEs"
		},
};
static const ber_tlv_tag_t asn_DEF_S1ap_TraceStart_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_S1ap_TraceStart_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* protocolIEs */
};
static asn_SEQUENCE_specifics_t asn_SPC_S1ap_TraceStart_specs_1 = {
	sizeof(struct S1ap_TraceStart),
	offsetof(struct S1ap_TraceStart, _asn_ctx),
	asn_MAP_S1ap_TraceStart_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	0,	/* Start extensions */
	2	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_S1ap_TraceStart = {
	"S1ap-TraceStart",
	"S1ap-TraceStart",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	SEQUENCE_decode_aper,
	SEQUENCE_encode_aper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_S1ap_TraceStart_tags_1,
	sizeof(asn_DEF_S1ap_TraceStart_tags_1)
		/sizeof(asn_DEF_S1ap_TraceStart_tags_1[0]), /* 1 */
	asn_DEF_S1ap_TraceStart_tags_1,	/* Same as above */
	sizeof(asn_DEF_S1ap_TraceStart_tags_1)
		/sizeof(asn_DEF_S1ap_TraceStart_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_S1ap_TraceStart_1,
	1,	/* Elements count */
	&asn_SPC_S1ap_TraceStart_specs_1	/* Additional specs */
};

