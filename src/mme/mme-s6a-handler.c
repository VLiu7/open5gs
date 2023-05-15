/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nas-path.h"
#include "s1ap-path.h"
#include "sgsap-path.h"
#include "mme-path.h"

#include "mme-sm.h"
#include "mme-s6a-handler.h"

/* Unfortunately fd doesn't distinguish
 * between result-code and experimental-result-code.
 *
 * However, e.g. 5004 has different meaning
 * if used in result-code than in experimental-result-code */
static uint8_t emm_cause_from_diameter(
                const uint32_t *dia_err, const uint32_t *dia_exp_err);

static uint8_t mme_ue_session_from_slice_data(mme_ue_t *mme_ue, 
    ogs_slice_data_t *slice_data);

uint8_t mme_s6a_handle_aia(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    int r;
    ogs_diam_s6a_aia_message_t *aia_message = NULL;
    ogs_diam_e_utran_vector_t *e_utran_vector = NULL;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    aia_message = &s6a_message->aia_message;
    ogs_assert(aia_message);
    e_utran_vector = &aia_message->e_utran_vector;
    ogs_assert(e_utran_vector);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_warn("Authentication Information failed [%d]",
                    s6a_message->result_code);
        return emm_cause_from_diameter(s6a_message->err, s6a_message->exp_err);
    }

    mme_ue->xres_len = e_utran_vector->xres_len;
    memcpy(mme_ue->xres, e_utran_vector->xres, mme_ue->xres_len);
    memcpy(mme_ue->kasme, e_utran_vector->kasme, OGS_SHA256_DIGEST_SIZE);
    memcpy(mme_ue->rand, e_utran_vector->rand, OGS_RAND_LEN);
    memcpy(mme_ue->autn, e_utran_vector->autn, OGS_AUTN_LEN);

    CLEAR_MME_UE_TIMER(mme_ue->t3460);

    if (mme_ue->nas_eps.ksi == OGS_NAS_KSI_NO_KEY_IS_AVAILABLE)
        mme_ue->nas_eps.ksi = 0;

    r = nas_eps_send_authentication_request(mme_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}

uint8_t mme_s6a_handle_ula(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_ula_message_t *ula_message = NULL;
    ogs_subscription_data_t *subscription_data = NULL;
    ogs_slice_data_t *slice_data = NULL;
    int r, rv, num_of_session;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    ula_message = &s6a_message->ula_message;
    ogs_assert(ula_message);
    subscription_data = &ula_message->subscription_data;
    ogs_assert(subscription_data);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_error("Update Location failed [%d]", s6a_message->result_code);
        return emm_cause_from_diameter(s6a_message->err, s6a_message->exp_err);
    }

    ogs_assert(subscription_data->num_of_slice == 1);
    slice_data = &subscription_data->slice[0];

    memcpy(&mme_ue->ambr, &subscription_data->ambr, sizeof(ogs_bitrate_t));

    mme_session_remove_all(mme_ue);

    num_of_session = mme_ue_session_from_slice_data(mme_ue, slice_data);
    if (num_of_session == 0) {
        ogs_error("No Session");
        return OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE;
    }
    mme_ue->num_of_session = num_of_session;

    mme_ue->context_identifier = slice_data->context_identifier;

    if (mme_ue->nas_eps.type == MME_EPS_TYPE_ATTACH_REQUEST) {
        rv = nas_eps_send_emm_to_esm(mme_ue,
                &mme_ue->pdn_connectivity_request);
        if (rv != OGS_OK) {
            ogs_error("nas_eps_send_emm_to_esm() failed");
            return OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
        }
    } else if (mme_ue->nas_eps.type == MME_EPS_TYPE_TAU_REQUEST) {
        r = nas_eps_send_tau_accept(mme_ue,
                S1AP_ProcedureCode_id_InitialContextSetup);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);
    } else {
        ogs_error("Invalid Type[%d]", mme_ue->nas_eps.type);
        return OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED;
    }

    return OGS_NAS_EMM_CAUSE_REQUEST_ACCEPTED;
}

uint8_t mme_s6a_handle_pua(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_pua_message_t *pua_message = NULL;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    pua_message = &s6a_message->pua_message;
    ogs_assert(pua_message);

    if (s6a_message->result_code != ER_DIAMETER_SUCCESS) {
        ogs_error("Purge UE failed for IMSI[%s] [%d]", mme_ue->imsi_bcd,
            s6a_message->result_code);
        mme_ue_remove(mme_ue);
        return OGS_ERROR;
    }

    if (pua_message->pua_flags & OGS_DIAM_S6A_PUA_FLAGS_FREEZE_MTMSI)
        ogs_debug("Freeze M-TMSI requested but not implemented.");

    mme_ue_remove(mme_ue);

    return OGS_OK;
}

uint8_t mme_s6a_handle_idr(
        mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    ogs_diam_s6a_idr_message_t *idr_message = NULL;
    ogs_subscription_data_t *subscription_data = NULL;
    ogs_slice_data_t *slice_data = NULL;
    int num_of_session;

    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    idr_message = &s6a_message->idr_message;
    ogs_assert(idr_message);
    subscription_data = &idr_message->subscription_data;
    ogs_assert(subscription_data);

    if (idr_message->subdatamask & OGS_DIAM_S6A_SUBDATA_UEAMBR) {
        memcpy(&mme_ue->ambr, &subscription_data->ambr, sizeof(ogs_bitrate_t));
    }

    if (idr_message->subdatamask & OGS_DIAM_S6A_SUBDATA_APN_CONFIG) {
        ogs_assert(subscription_data->num_of_slice == 1);
        slice_data = &subscription_data->slice[0];

        if (slice_data->all_apn_config_inc ==
                OGS_ALL_APN_CONFIGURATIONS_INCLUDED) {
            mme_session_remove_all(mme_ue);
            num_of_session = mme_ue_session_from_slice_data(mme_ue, slice_data);
            if (num_of_session == 0) {
                ogs_error("No Session");
                return OGS_ERROR;
            }
            mme_ue->num_of_session = num_of_session;
        } else {
            ogs_error ("[%d] Partial APN-Configuration Not Supported in IDR.",
                        slice_data->all_apn_config_inc);
            return OGS_ERROR;
        }

        mme_ue->context_identifier = slice_data->context_identifier;
    }

    return OGS_OK;
}

void mme_s6a_handle_clr(mme_ue_t *mme_ue, ogs_diam_s6a_message_t *s6a_message)
{
    int r;
    ogs_diam_s6a_clr_message_t *clr_message = NULL;
    ogs_assert(mme_ue);
    ogs_assert(s6a_message);
    clr_message = &s6a_message->clr_message;
    ogs_assert(clr_message);

    mme_ue = mme_ue_cycle(mme_ue);
    if (!mme_ue) {
        ogs_warn("UE(mme-ue) context has already been removed");
        return;
    }

    /*
     * This causes issues in this scenario:
     * 1. UE attaches
     * 2. UE detaches (Airplane Mode)
     * 3. Cancel Location is triggered by HSS
     *
     * If Cancel Locations are performed, UE(mme-ue) context must be removed.
     */
    if (OGS_FSM_CHECK(&mme_ue->sm, emm_state_de_registered)) {
        ogs_warn("UE has already been de-registered");
        mme_ue_remove(mme_ue);
        return;
    }

    /* Set EPS Detach */
    memset(&mme_ue->nas_eps.detach, 0, sizeof(ogs_nas_detach_type_t));

    if (clr_message->clr_flags & OGS_DIAM_S6A_CLR_FLAGS_REATTACH_REQUIRED)
        mme_ue->nas_eps.detach.value =
            OGS_NAS_DETACH_TYPE_TO_UE_RE_ATTACH_REQUIRED;
    else
        mme_ue->nas_eps.detach.value =
            OGS_NAS_DETACH_TYPE_TO_UE_RE_ATTACH_NOT_REQUIRED;

    /* 1. MME initiated detach request to the UE.
     *    (nas_eps.type = MME_EPS_TYPE_DETACH_REQUEST_TO_UE)
     * 2. If UE is IDLE, Paging sent to the UE
     * 3. If UE is wake-up, UE will send Server Request.
     *    (nas_eps.type = MME_EPS_TYPE_SERVICE_REQUEST)
     *
     * So, we will lose the MME_EPS_TYPE_DETACH_REQUEST_TO_UE.
     *
     * We need more variable(detach_type)
     * to keep Detach-Type whether UE-initiated or MME-initiaed.  */
    mme_ue->nas_eps.type = MME_EPS_TYPE_DETACH_REQUEST_TO_UE;

    ogs_debug("    OGS_NAS_EPS TYPE[%d]", mme_ue->nas_eps.type);

    switch (clr_message->cancellation_type) {
    case OGS_DIAM_S6A_CT_SUBSCRIPTION_WITHDRAWL:
        mme_ue->detach_type = MME_DETACH_TYPE_HSS_EXPLICIT;

        /*
         * Before sending Detach-Request,
         * we need to check whether UE is IDLE or not.
         */
        if (ECM_IDLE(mme_ue)) {
            if (ogs_timer_running(mme_ue->t_implicit_detach.timer)) {
                /*
                * TS 24.301 5.3.7
                * If ISR is not activated, the network behaviour upon expiry of
                * the mobile reachable timer is network dependent, but typically
                * the network stops sending paging messages to the UE on the
                * first expiry, and may take other appropriate actions
                */
                ogs_debug("[%s] Paging stopped: Mobile Reachable timer expiry",
                    mme_ue->imsi_bcd);
                if (MME_P_TMSI_IS_AVAILABLE(mme_ue)) {
                    ogs_assert(OGS_OK == sgsap_send_detach_indication(mme_ue));
                } else {
                    mme_send_delete_session_or_detach(mme_ue);
                }
                MME_CLEAR_PAGING_INFO(mme_ue);
            } else {
                MME_STORE_PAGING_INFO(mme_ue,
                    MME_PAGING_TYPE_DETACH_TO_UE, NULL);
                r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
                ogs_expect(r == OGS_OK);
                ogs_assert(r != OGS_ERROR);
            }
        } else {
            MME_CLEAR_PAGING_INFO(mme_ue);
            r = nas_eps_send_detach_request(mme_ue);
            ogs_expect(r == OGS_OK);
            ogs_assert(r != OGS_ERROR);
            if (MME_P_TMSI_IS_AVAILABLE(mme_ue)) {
                ogs_assert(OGS_OK == sgsap_send_detach_indication(mme_ue));
            } else {
                mme_send_delete_session_or_detach(mme_ue);
            }
        }
        break;
    case OGS_DIAM_S6A_CT_MME_UPDATE_PROCEDURE:
        mme_ue->detach_type = MME_DETACH_TYPE_HSS_IMPLICIT;

        /*
         * There is no need to send NAS or S1AP message to the UE.
         * So, we don't have to check whether UE is IDLE or not.
         */
        if (MME_P_TMSI_IS_AVAILABLE(mme_ue)) {
            ogs_assert(OGS_OK == sgsap_send_detach_indication(mme_ue));
        } else {
            mme_send_delete_session_or_detach(mme_ue);
        }
        break;
    default:
        ogs_fatal("Unsupported Cancellation-Type [%d]",
            clr_message->cancellation_type);
        ogs_assert_if_reached();
        break;
    }
}

static uint8_t mme_ue_session_from_slice_data(mme_ue_t *mme_ue, 
    ogs_slice_data_t *slice_data)
{
    int i;
    for (i = 0; i < slice_data->num_of_session; i++) {
        if (i >= OGS_MAX_NUM_OF_SESS) {
            ogs_warn("Ignore max session count overflow [%d>=%d]",
                    slice_data->num_of_session, OGS_MAX_NUM_OF_SESS);
            break;
        }

        if (slice_data->session[i].name) {
            mme_ue->session[i].name = ogs_strdup(slice_data->session[i].name);
            ogs_assert(mme_ue->session[i].name);
        }

        mme_ue->session[i].context_identifier =
            slice_data->session[i].context_identifier;

        if (slice_data->session[i].session_type == OGS_PDU_SESSION_TYPE_IPV4 ||
            slice_data->session[i].session_type == OGS_PDU_SESSION_TYPE_IPV6 ||
            slice_data->session[i].session_type ==
                OGS_PDU_SESSION_TYPE_IPV4V6) {
            mme_ue->session[i].session_type =
                slice_data->session[i].session_type;
        } else {
            ogs_error("Invalid PDN_TYPE[%d]",
                slice_data->session[i].session_type);
            if (mme_ue->session[i].name)
                ogs_free(mme_ue->session[i].name);
            break;
        }
        memcpy(&mme_ue->session[i].paa, &slice_data->session[i].paa,
                sizeof(mme_ue->session[i].paa));

        memcpy(&mme_ue->session[i].qos, &slice_data->session[i].qos,
                sizeof(mme_ue->session[i].qos));
        memcpy(&mme_ue->session[i].ambr, &slice_data->session[i].ambr,
                sizeof(mme_ue->session[i].ambr));

        memcpy(&mme_ue->session[i].smf_ip, &slice_data->session[i].smf_ip,
                sizeof(mme_ue->session[i].smf_ip));

        memcpy(&mme_ue->session[i].charging_characteristics,
                &slice_data->session[i].charging_characteristics,
                sizeof(mme_ue->session[i].charging_characteristics));
        mme_ue->session[i].charging_characteristics_presence =
            slice_data->session[i].charging_characteristics_presence;
    }

    return i;
}


// #define OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_HSS 2
// #define OGS_NAS_EMM_CAUSE_ILLEGAL_UE 3
// #define OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_VLR 4
// #define OGS_NAS_EMM_CAUSE_ILLEGAL_ME 6
// #define OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK 9
// #define OGS_NAS_EMM_CAUSE_IMPLICITLY_DETACHED 10
// /* A.2 Cause related to subscription options */
// #define OGS_NAS_EMM_CAUSE_IMEI_NOT_ACCEPTED 5
// #define OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED 7
// #define OGS_NAS_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED 8
// #define OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED 11
// #define OGS_NAS_EMM_CAUSE_TRACKING_AREA_NOT_ALLOWED 12
// #define OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA 13
// #define OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN 14
// #define OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA 15
// #define OGS_NAS_EMM_CAUSE_REQUESTED_SERVICE_OPTION_NOT_AUTHORIZED_IN_THIS_PLMN 35
// #define OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED 40
// /* A.3 Causes related to PLMN specific network failures and
//  *     congestion/authentication failures */
// #define OGS_NAS_EMM_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE 16
// #define OGS_NAS_EMM_CAUSE_NETWORK_FAILURE 17
// #define OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE 18
// #define OGS_NAS_EMM_CAUSE_ESM_FAILURE 19
// #define OGS_NAS_EMM_CAUSE_MAC_FAILURE 20
// #define OGS_NAS_EMM_CAUSE_SYNCH_FAILURE 21
// #define OGS_NAS_EMM_CAUSE_CONGESTION 22
// #define OGS_NAS_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH 23
// #define OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED 24
// #define OGS_NAS_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE 26
// #define OGS_NAS_EMM_CAUSE_CS_SERVICE_TEMPORARILY_NOT_AVAILABLE 39
// #define OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE 42
// /* A.4 Causes related to nature of request
//  * NOTE:   This subclause has no entries in this version of the specification *
//  * A.5 Causes related to invalid messages */
// #define OGS_NAS_EMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE 95
// #define OGS_NAS_EMM_CAUSE_INVALID_MANDATORY_INFORMATION 96
// #define OGS_NAS_EMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED 97
// #define OGS_NAS_EMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE 98
// #define OGS_NAS_EMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED 99
// #define OGS_NAS_EMM_CAUSE_CONDITIONAL_IE_ERROR 100
// #define OGS_NAS_EMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE 101
// #define OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED 111


/* 3GPP TS 29.272 Annex A; Table A.1:
 * Mapping from S6a error codes to NAS Cause Codes */
static uint8_t emm_cause_from_diameter(
                const uint32_t *dia_err, const uint32_t *dia_exp_err)
{
    if (dia_exp_err) {
        switch (*dia_exp_err) {
        case OGS_DIAM_S6A_ERROR_USER_UNKNOWN:                   /* 5001 */
            // wei: reject cause test
            return OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED; //11
            // return OGS_NAS_EMM_CAUSE_CONGESTION; //22
            // return OGS_NAS_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED; //8
            // return OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_HSS;//2
            // return OGS_NAS_EMM_CAUSE_ILLEGAL_UE; //3
            // return OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_VLR; //4
            // return OGS_NAS_EMM_CAUSE_ILLEGAL_ME; //6
            // return OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK; //9
            // return OGS_NAS_EMM_CAUSE_IMEI_NOT_ACCEPTED; //5
            // return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED;//7
            // return OGS_NAS_EMM_CAUSE_TRACKING_AREA_NOT_ALLOWED;//12
            // return OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA; //13
            // return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN;//14
            // return OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA; //15
            // return OGS_NAS_EMM_CAUSE_REQUESTED_SERVICE_OPTION_NOT_AUTHORIZED_IN_THIS_PLMN; //35
            // return OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED;//40
            // return OGS_NAS_EMM_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE;//16
            // return OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;//17
            // return OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE; //18
            // return OGS_NAS_EMM_CAUSE_ESM_FAILURE; //19
            // return OGS_NAS_EMM_CAUSE_MAC_FAILURE;//20
            // return OGS_NAS_EMM_CAUSE_SYNCH_FAILURE;//21
            // return OGS_NAS_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH;//23
            // return OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED;//24
            // return OGS_NAS_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE; //26
            // return OGS_NAS_EMM_CAUSE_CS_SERVICE_TEMPORARILY_NOT_AVAILABLE;//39
        case OGS_DIAM_S6A_ERROR_UNKNOWN_EPS_SUBSCRIPTION:       /* 5420 */
            /* FIXME: Error diagnostic? */
            return OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
        case OGS_DIAM_S6A_ERROR_RAT_NOT_ALLOWED:                /* 5421 */
            return OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA;
        case OGS_DIAM_S6A_ERROR_ROAMING_NOT_ALLOWED:            /* 5004 */
            return OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED;
            /* return OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN;
             * (ODB_HPLMN_APN) */
            /* return OGS_NAS_EMM_CAUSE_ESM_FAILURE; (ODB_ALL_APN) */
        case OGS_DIAM_S6A_AUTHENTICATION_DATA_UNAVAILABLE:      /* 4181 */
            return OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;
        }
    }
    if (dia_err) {
        switch (*dia_err) {
        case ER_DIAMETER_AUTHORIZATION_REJECTED:                /* 5003 */
        case ER_DIAMETER_UNABLE_TO_DELIVER:                     /* 3002 */
        case ER_DIAMETER_REALM_NOT_SERVED:                      /* 3003 */
            return OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA;
        case ER_DIAMETER_UNABLE_TO_COMPLY:                      /* 5012 */
        case ER_DIAMETER_INVALID_AVP_VALUE:                     /* 5004 */
        case ER_DIAMETER_AVP_UNSUPPORTED:                       /* 5001 */
        case ER_DIAMETER_MISSING_AVP:                           /* 5005 */
        case ER_DIAMETER_RESOURCES_EXCEEDED:                    /* 5006 */
        case ER_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES:             /* 5009 */
            return OGS_NAS_EMM_CAUSE_NETWORK_FAILURE;
        }
    }

    ogs_error("Unexpected Diameter Result Code %d/%d, defaulting to severe "
              "network failure",
              dia_err ? *dia_err : -1, dia_exp_err ? *dia_exp_err : -1);
    return OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE;
}
