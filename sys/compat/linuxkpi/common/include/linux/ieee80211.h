/*-
 * Copyright (c) 2020-2021 The FreeBSD Foundation
 *
 * This software was developed by Björn Zeeb under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_LINUXKPI_LINUX_IEEE80211_H
#define	_LINUXKPI_LINUX_IEEE80211_H

#include <sys/types.h>
#include <net80211/ieee80211.h>

#include <asm/unaligned.h>
#include <linux/bitops.h>
#include <linux/if_ether.h>


/* 9.4.2.55 Management MIC element (CMAC-256, GMAC-128, and GMAC-256). */
struct ieee80211_mmie_16 {
	uint8_t		element_id;
	uint8_t		length;
	uint16_t	key_id;
	uint8_t		ipn[6];
	uint8_t		mic[16];
};

#define	IEEE80211_CCMP_HDR_LEN			8	/* 802.11i .. net80211 comment */
#define	IEEE80211_CCMP_PN_LEN			6
#define	IEEE80211_CCMP_MIC_LEN			8	/* || 16 */
#define	IEEE80211_CCMP_256_HDR_LEN		8
#define	IEEE80211_CCMP_256_MIC_LEN		16
#define	IEEE80211_GCMP_HDR_LEN			8
#define	IEEE80211_GCMP_MIC_LEN			16
#define	IEEE80211_GCMP_PN_LEN			6
#define	IEEE80211_GMAC_PN_LEN			6

#define	IEEE80211_MAX_PN_LEN			16

#define	IEEE80211_INVAL_HW_QUEUE		((uint8_t)-1)

#define	IEEE80211_MAX_AMPDU_BUF_HT		0x40
#define	IEEE80211_MAX_AMPDU_BUF			256	/* for HE? */
#define	IEEE80211_MAX_AMPDU_BUF_HE		256

#define	IEEE80211_MAX_FRAME_LEN			2352
#define	IEEE80211_MAX_DATA_LEN			(2300 + IEEE80211_CRC_LEN)

#define	IEEE80211_MAX_MPDU_LEN_HT_BA		4095	/* 9.3.2.1 Format of Data frames; non-VHT non-DMG STA */
#define	IEEE80211_MAX_MPDU_LEN_HT_3839		3839
#define	IEEE80211_MAX_MPDU_LEN_HT_7935		7935
#define	IEEE80211_MAX_MPDU_LEN_VHT_3895		3895
#define	IEEE80211_MAX_MPDU_LEN_VHT_7991		7991
#define	IEEE80211_MAX_MPDU_LEN_VHT_11454	11454

#define	IEEE80211_MAX_RTS_THRESHOLD		2346	/* net80211::IEEE80211_RTS_MAX */

#define	IEEE80211_MIN_ACTION_SIZE		23	/* ? */

/* Wi-Fi Peer-to-Peer (P2P) Technical Specification */
#define	IEEE80211_P2P_OPPPS_CTWINDOW_MASK	0x7f
#define	IEEE80211_P2P_OPPPS_ENABLE_BIT		BIT(7)

/* 802.11-2016, 9.2.4.5.1, Table 9-6 QoS Control Field */
#define	IEEE80211_QOS_CTL_TAG1D_MASK		0x0007
#define	IEEE80211_QOS_CTL_TID_MASK		IEEE80211_QOS_TID
#define	IEEE80211_QOS_CTL_EOSP			0x0010
#define	IEEE80211_QOS_CTL_A_MSDU_PRESENT	0x0080
#define	IEEE80211_QOS_CTL_ACK_POLICY_MASK	0x0060
#define	IEEE80211_QOS_CTL_ACK_POLICY_NOACK	0x0020
#define	IEEE80211_QOS_CTL_MESH_CONTROL_PRESENT	0x0100

#define	IEEE80211_RATE_SHORT_PREAMBLE		BIT(0)

enum ieee80211_rate_control_changed_flags {
	IEEE80211_RC_BW_CHANGED			= BIT(0),
	IEEE80211_RC_NSS_CHANGED		= BIT(1),
	IEEE80211_RC_SUPP_RATES_CHANGED		= BIT(2),
	IEEE80211_RC_SMPS_CHANGED		= BIT(3),
};

#define	IEEE80211_SCTL_FRAG			IEEE80211_SEQ_FRAG_MASK
#define	IEEE80211_SCTL_SEQ			IEEE80211_SEQ_SEQ_MASK

#define	IEEE80211_TKIP_ICV_LEN			4
#define	IEEE80211_TKIP_IV_LEN			8	/* WEP + KID + EXT */

#define	IEEE80211_VHT_EXT_NSS_BW_CAPABLE	(1 << 13)	/* assigned to tx_highest */

#define	IEEE80211_VHT_MAX_AMPDU_1024K		7	/* 9.4.2.56.3 A-MPDU Parameters field, Table 9-163 */

#define	IEEE80211_WEP_IV_LEN			3	/* net80211: IEEE80211_WEP_IVLEN */
#define	IEEE80211_WEP_ICV_LEN			4

#define	WLAN_AUTH_OPEN				__LINE__ /* TODO FIXME brcmfmac */
#define	WLAN_CAPABILITY_IBSS			__LINE__ /* TODO FIXME no longer used? */
#define	WLAN_CAPABILITY_SHORT_PREAMBLE		__LINE__ /* TODO FIXME brcmfmac */
#define	WLAN_CAPABILITY_SHORT_SLOT_TIME		__LINE__ /* TODO FIXME brcmfmac */

enum wlan_ht_cap_sm_ps {
	WLAN_HT_CAP_SM_PS_STATIC		= 0,
	WLAN_HT_CAP_SM_PS_DYNAMIC,
	WLAN_HT_CAP_SM_PS_INVALID,
	WLAN_HT_CAP_SM_PS_DISABLED,
};

#define	WLAN_MAX_KEY_LEN			32 /* TODO FIXME brcmfmac */
#define	WLAN_PMKID_LEN				16 /* TODO FIXME brcmfmac */

#define	WLAN_KEY_LEN_WEP40			5
#define	WLAN_KEY_LEN_WEP104			13
#define	WLAN_KEY_LEN_TKIP			32
#define	WLAN_KEY_LEN_CCMP			16
#define	WLAN_KEY_LEN_GCMP			16
#define	WLAN_KEY_LEN_GCMP_256			32

/* 802.11-2020, 9.4.2.55.3, Table 9-185 Subfields of the A-MPDU Parameters field */
enum ieee80211_min_mpdu_start_spacing {
	IEEE80211_HT_MPDU_DENSITY_NONE		= 0,
#if 0
	IEEE80211_HT_MPDU_DENSITY_XXX		= 1,	/* 1/4 us */
	IEEE80211_HT_MPDU_DENSITY_YYY		= 2,	/* 1/2 us */
#endif
	IEEE80211_HT_MPDU_DENSITY_1		= 3,	/* 1 us */
	IEEE80211_HT_MPDU_DENSITY_2		= 4,	/* 2 us */
	IEEE80211_HT_MPDU_DENSITY_4		= 5,	/* 4us */
	IEEE80211_HT_MPDU_DENSITY_8		= 6,	/* 8us */
	IEEE80211_HT_MPDU_DENSITY_16		= 7, 	/* 16us */
};

/* 9.4.2.57, Table 9-168, HT Operation element fields and subfields */
#define	IEEE80211_HT_STBC_PARAM_DUAL_CTS_PROT	0x0080	/* B24.. */

#define	IEEE80211_FCTL_FTYPE			IEEE80211_FC0_TYPE_MASK
#define	IEEE80211_FCTL_STYPE			IEEE80211_FC0_SUBTYPE_MASK
#define	IEEE80211_FCTL_ORDER			(IEEE80211_FC1_ORDER << 8)
#define	IEEE80211_FCTL_PROTECTED		(IEEE80211_FC1_PROTECTED << 8)
#define	IEEE80211_FCTL_FROMDS			(IEEE80211_FC1_DIR_FROMDS << 8)
#define	IEEE80211_FCTL_TODS			(IEEE80211_FC1_DIR_TODS << 8)
#define	IEEE80211_FCTL_MOREFRAGS		(IEEE80211_FC1_MORE_FRAG << 8)

#define	IEEE80211_FTYPE_MGMT			IEEE80211_FC0_TYPE_MGT
#define	IEEE80211_FTYPE_CTL			IEEE80211_FC0_TYPE_CTL
#define	IEEE80211_FTYPE_DATA			IEEE80211_FC0_TYPE_DATA

#define	IEEE80211_STYPE_ASSOC_REQ		IEEE80211_FC0_SUBTYPE_ASSOC_REQ
#define	IEEE80211_STYPE_REASSOC_REQ		IEEE80211_FC0_SUBTYPE_REASSOC_REQ
#define	IEEE80211_STYPE_PROBE_REQ		IEEE80211_FC0_SUBTYPE_PROBE_REQ
#define	IEEE80211_STYPE_DISASSOC		IEEE80211_FC0_SUBTYPE_DISASSOC
#define	IEEE80211_STYPE_AUTH			IEEE80211_FC0_SUBTYPE_AUTH
#define	IEEE80211_STYPE_DEAUTH			IEEE80211_FC0_SUBTYPE_DEAUTH
#define	IEEE80211_STYPE_ACTION			IEEE80211_FC0_SUBTYPE_ACTION
#define	IEEE80211_STYPE_QOS_DATA		IEEE80211_FC0_SUBTYPE_QOS_DATA

#define	IEEE80211_NUM_ACS			4	/* net8021::WME_NUM_AC */

#define	IEEE80211_MAX_SSID_LEN			32	/* 9.4.2.2 SSID element, net80211: IEEE80211_NWID_LEN */


/* Figure 9-27, BAR Control field */
#define	IEEE80211_BAR_CTRL_TID_INFO_MASK	0xf000
#define	IEEE80211_BAR_CTRL_TID_INFO_SHIFT	12

#define	IEEE80211_PPE_THRES_INFO_PPET_SIZE		1 /* TODO FIXME ax? */
#define	IEEE80211_PPE_THRES_NSS_MASK			2 /* TODO FIXME ax? */
#define	IEEE80211_PPE_THRES_RU_INDEX_BITMASK_POS	3 /* TODO FIXME ax? */
#define	IEEE80211_PPE_THRES_RU_INDEX_BITMASK_MASK	8 /* TODO FIXME ax? */
#define	IEEE80211_HE_PPE_THRES_INFO_HEADER_SIZE		16	/* TODO FIXME ax? */

#define	IEEE80211_HT_OP_MODE_PROTECTION			0x03	/* MASK */
#define	IEEE80211_HT_OP_MODE_PROTECTION_NONE		0x00
#define	IEEE80211_HT_OP_MODE_PROTECTION_20MHZ		0x01
#define	IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED	0x02
#define	IEEE80211_HT_OP_MODE_PROTECTION_NONMEMBER	0x03


/* 9.6.13.1, Table 9-342 TDLS Action field values. */
enum ieee80211_tdls_action_code {
	WLAN_TDLS_SETUP_REQUEST			= 0,
	WLAN_TDLS_SETUP_RESPONSE		= 1,
	WLAN_TDLS_SETUP_CONFIRM			= 2,
	WLAN_TDLS_TEARDOWN			= 3,
	WLAN_TDLS_PEER_TRAFFIC_INDICATION	= 4,
	WLAN_TDLS_CHANNEL_SWITCH_REQUEST	= 5,
	WLAN_TDLS_CHANNEL_SWITCH_RESPONSE	= 6,
	WLAN_TDLS_PEER_PSM_REQUEST		= 7,
	WLAN_TDLS_PEER_PSM_RESPONSE		= 8,
	WLAN_TDLS_PEER_TRAFFIC_RESPONSE		= 9,
	WLAN_TDLS_DISCOVERY_REQUEST		= 10,
	/* 11-255 reserved */
};

/* 9.4.2.27, Table 9-135. Extended Capabilities field. */
/* This is split up into octets CAPA1 = octet 1, ... */
#define	WLAN_EXT_CAPA1_EXT_CHANNEL_SWITCHING			BIT(2  % 8)
#define	WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT			BIT(22 % 8)
#define	WLAN_EXT_CAPA8_OPMODE_NOTIF				BIT(62 % 8)

#define	WLAN_EXT_CAPA10_TWT_REQUESTER_SUPPORT			BIT(5)		/* XXX */
#define	WLAN_EXT_CAPA10_OBSS_NARROW_BW_RU_TOLERANCE_SUPPORT	BIT(7)		/* XXX */
#define	WLAN_EXT_CAPA10_TWT_RESPONDER_SUPPORT			BIT(6)		/* XXX */


/* iwlwifi/mvm/utils:: for (ac = IEEE80211_AC_VO; ac <= IEEE80211_AC_VI; ac++) */
/* Would be so much easier if we'd define constants to the same. */
enum ieee80211_ac_numbers {
	IEEE80211_AC_VO = 0,			/* net80211::WME_AC_VO */
	IEEE80211_AC_VI = 1,			/* net80211::WME_AC_VI */
	IEEE80211_AC_BE = 2,			/* net80211::WME_AC_BE */
	IEEE80211_AC_BK = 3,			/* net80211::WME_AC_BK */
};

#define	IEEE80211_MAX_QUEUES			16	/* Assume IEEE80211_NUM_TIDS for the moment. */

#define	IEEE80211_WMM_IE_STA_QOSINFO_AC_VO	1
#define	IEEE80211_WMM_IE_STA_QOSINFO_AC_VI	2
#define	IEEE80211_WMM_IE_STA_QOSINFO_AC_BK	4
#define	IEEE80211_WMM_IE_STA_QOSINFO_AC_BE	8
#define	IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL	0xf


/* XXX net80211 calls these IEEE80211_HTCAP_* */
#define	IEEE80211_HT_CAP_LDPC_CODING		0x0001	/* IEEE80211_HTCAP_LDPC */
#define	IEEE80211_HT_CAP_SUP_WIDTH_20_40	0x0002	/* IEEE80211_HTCAP_CHWIDTH40 */
#define	IEEE80211_HT_CAP_SM_PS			0x000c	/* IEEE80211_HTCAP_SMPS */
#define	IEEE80211_HT_CAP_SM_PS_SHIFT		2
#define	IEEE80211_HT_CAP_GRN_FLD		0x0010	/* IEEE80211_HTCAP_GREENFIELD */
#define	IEEE80211_HT_CAP_SGI_20			0x0020	/* IEEE80211_HTCAP_SHORTGI20 */
#define	IEEE80211_HT_CAP_SGI_40			0x0040	/* IEEE80211_HTCAP_SHORTGI40 */
#define	IEEE80211_HT_CAP_TX_STBC		0x0080	/* IEEE80211_HTCAP_TXSTBC */
#define	IEEE80211_HT_CAP_RX_STBC		0x0100	/* IEEE80211_HTCAP_RXSTBC */
#define	IEEE80211_HT_CAP_RX_STBC_SHIFT		8	/* IEEE80211_HTCAP_RXSTBC_S */
#define	IEEE80211_HT_CAP_MAX_AMSDU		0x0800	/* IEEE80211_HTCAP_MAXAMSDU */
#define	IEEE80211_HT_CAP_DSSSCCK40		0x1000	/* IEEE80211_HTCAP_DSSSCCK40 */
#define	IEEE80211_HT_CAP_LSIG_TXOP_PROT		0x8000	/* IEEE80211_HTCAP_LSIGTXOPPROT */

#define	IEEE80211_HT_MCS_TX_DEFINED		0x0001
#define	IEEE80211_HT_MCS_TX_RX_DIFF		0x0002
#define	IEEE80211_HT_MCS_TX_MAX_STREAMS_SHIFT	2
#define	IEEE80211_HT_MCS_TX_MAX_STREAMS_MASK	0x0c
#define	IEEE80211_HT_MCS_RX_HIGHEST_MASK	0x3ff
#define	IEEE80211_HT_MCS_MASK_LEN		10

struct ieee80211_mcs_info {
	uint8_t		rx_mask[IEEE80211_HT_MCS_MASK_LEN];
	uint16_t	rx_highest;
	uint8_t		tx_params;
	uint8_t		__reserved[3];
};

/* 802.11-2020, 9.4.2.55.1 HT Capabilities element structure */
struct ieee80211_ht_cap {
	uint16_t				cap_info;
	uint8_t					ampdu_params_info;
	struct ieee80211_mcs_info		mcs;
	uint16_t				extended_ht_cap_info;
	uint32_t				tx_BF_cap_info;
	uint8_t					antenna_selection_info;
};

#define	IEEE80211_HT_MAX_AMPDU_FACTOR		13

enum ieee80211_ht_max_ampdu_len {
	IEEE80211_HT_MAX_AMPDU_64K
};

enum ieee80211_ampdu_mlme_action {
	IEEE80211_AMPDU_RX_START,
	IEEE80211_AMPDU_RX_STOP,
	IEEE80211_AMPDU_TX_OPERATIONAL,
	IEEE80211_AMPDU_TX_START,
	IEEE80211_AMPDU_TX_STOP_CONT,
	IEEE80211_AMPDU_TX_STOP_FLUSH,
	IEEE80211_AMPDU_TX_STOP_FLUSH_CONT
};

#define	IEEE80211_AMPDU_TX_START_IMMEDIATE	1
#define	IEEE80211_AMPDU_TX_START_DELAY_ADDBA	2

enum ieee80211_chanctx_switch_mode {
	CHANCTX_SWMODE_REASSIGN_VIF,
	CHANCTX_SWMODE_SWAP_CONTEXTS,
};

enum ieee80211_chanctx_change_flags {
	IEEE80211_CHANCTX_CHANGE_MIN_WIDTH	= BIT(0),
	IEEE80211_CHANCTX_CHANGE_RADAR		= BIT(1),
	IEEE80211_CHANCTX_CHANGE_RX_CHAINS	= BIT(2),
	IEEE80211_CHANCTX_CHANGE_WIDTH		= BIT(3),
	IEEE80211_CHANCTX_CHANGE_CHANNEL	= BIT(4),
};

enum ieee80211_frame_release_type {
	IEEE80211_FRAME_RELEASE_PSPOLL		= 1,
	IEEE80211_FRAME_RELEASE_UAPSD		= 2,
};

enum ieee80211_p2p_attr_ids {
	IEEE80211_P2P_ATTR_DEVICE_ID,
	IEEE80211_P2P_ATTR_DEVICE_INFO,
	IEEE80211_P2P_ATTR_GROUP_ID,
	IEEE80211_P2P_ATTR_LISTEN_CHANNEL,
	IEEE80211_P2P_ATTR_ABSENCE_NOTICE,
};

enum ieee80211_reconfig_type {
	IEEE80211_RECONFIG_TYPE_RESTART,
	IEEE80211_RECONFIG_TYPE_SUSPEND,
};

enum ieee80211_roc_type {
	IEEE80211_ROC_TYPE_MGMT_TX,
	IEEE80211_ROC_TYPE_NORMAL,
};

enum ieee80211_smps_mode {
	IEEE80211_SMPS_OFF,
	IEEE80211_SMPS_STATIC,
	IEEE80211_SMPS_DYNAMIC,
	IEEE80211_SMPS_AUTOMATIC,
	IEEE80211_SMPS_NUM_MODES,
};

/* net80211::IEEE80211_S_* different but represents the state machine. */
/* Note: order here is important! */
enum ieee80211_sta_state {
	IEEE80211_STA_NOTEXIST,
	IEEE80211_STA_NONE,
	IEEE80211_STA_AUTH,
	IEEE80211_STA_ASSOC,
	IEEE80211_STA_AUTHORIZED,		/* 802.1x */
};

enum ieee80211_sta_rx_bw {
	IEEE80211_STA_RX_BW_20,
	IEEE80211_STA_RX_BW_40,
	IEEE80211_STA_RX_BW_80,
	IEEE80211_STA_RX_BW_160,
	IEEE80211_STA_RX_BW_320,
};

enum ieee80211_tx_info_flags {
	/* XXX TODO .. right shift numbers - not sure where that came from? */
	IEEE80211_TX_CTL_AMPDU			= BIT(0),
	IEEE80211_TX_CTL_ASSIGN_SEQ		= BIT(1),
	IEEE80211_TX_CTL_NO_ACK			= BIT(2),
	IEEE80211_TX_CTL_SEND_AFTER_DTIM	= BIT(3),
	IEEE80211_TX_CTL_TX_OFFCHAN		= BIT(4),
	IEEE80211_TX_CTL_REQ_TX_STATUS		= BIT(5),
	IEEE80211_TX_STATUS_EOSP		= BIT(6),
	IEEE80211_TX_STAT_ACK			= BIT(7),
	IEEE80211_TX_STAT_AMPDU			= BIT(8),
	IEEE80211_TX_STAT_AMPDU_NO_BACK		= BIT(9),
	IEEE80211_TX_STAT_TX_FILTERED		= BIT(10),
	IEEE80211_TX_STAT_NOACK_TRANSMITTED	= BIT(11),
	IEEE80211_TX_CTL_FIRST_FRAGMENT		= BIT(12),
	IEEE80211_TX_INTFL_DONT_ENCRYPT		= BIT(13),
	IEEE80211_TX_CTL_NO_CCK_RATE		= BIT(14),
	IEEE80211_TX_CTL_INJECTED		= BIT(15),
	IEEE80211_TX_CTL_HW_80211_ENCAP		= BIT(16),
	IEEE80211_TX_CTL_USE_MINRATE		= BIT(17),
	IEEE80211_TX_CTL_RATE_CTRL_PROBE	= BIT(18),
};

enum ieee80211_tx_control_flags {
	/* XXX TODO .. right shift numbers */
	IEEE80211_TX_CTRL_PORT_CTRL_PROTO	= BIT(0),
	IEEE80211_TX_CTRL_PS_RESPONSE		= BIT(1),
};

enum ieee80211_tx_rate_flags {
	/* XXX TODO .. right shift numbers */
	IEEE80211_TX_RC_40_MHZ_WIDTH		= BIT(0),
	IEEE80211_TX_RC_80_MHZ_WIDTH		= BIT(1),
	IEEE80211_TX_RC_160_MHZ_WIDTH		= BIT(2),
	IEEE80211_TX_RC_GREEN_FIELD		= BIT(3),
	IEEE80211_TX_RC_MCS			= BIT(4),
	IEEE80211_TX_RC_SHORT_GI		= BIT(5),
	IEEE80211_TX_RC_VHT_MCS			= BIT(6),
	IEEE80211_TX_RC_USE_SHORT_PREAMBLE	= BIT(7),
};

#define	IEEE80211_HT_CTL_LEN	4

struct ieee80211_hdr {		/* net80211::ieee80211_frame_addr4 */
        __le16		frame_control;
        __le16		duration_id;
	uint8_t		addr1[ETH_ALEN];
	uint8_t		addr2[ETH_ALEN];
	uint8_t		addr3[ETH_ALEN];
	__le16		seq_ctrl;
	uint8_t		addr4[ETH_ALEN];
};

struct ieee80211_hdr_3addr {	/* net80211::ieee80211_frame */
        __le16		frame_control;
        __le16		duration_id;
	uint8_t		addr1[ETH_ALEN];
	uint8_t		addr2[ETH_ALEN];
	uint8_t		addr3[ETH_ALEN];
	__le16		seq_ctrl;
};

struct ieee80211_vendor_ie {
};

/* 802.11-2020, Table 9-359-Block Ack Action field values */
enum ieee80211_back {
	WLAN_ACTION_ADDBA_REQ		= 0,
};

/* 802.11-2020, Table 9-51-Category values */
enum ieee80211_category {
	WLAN_CATEGORY_BACK		= 3,
};

/* 80211-2020 9.3.3.2 Format of Management frames */
struct ieee80211_mgmt {
	__le16		frame_control;
        __le16		duration_id;
	uint8_t		da[ETH_ALEN];
	uint8_t		sa[ETH_ALEN];
	uint8_t		bssid[ETH_ALEN];
	__le16		seq_ctrl;
	union {
		/* 9.3.3.3 Beacon frame format */
		struct {
			uint64_t	timestamp;
			uint16_t	beacon_int;
			uint16_t	capab_info;
			uint8_t		variable[0];
		} beacon;
		/* 9.3.3.10 Probe Request frame format */
		struct {
			uint8_t		variable[0];
		} probe_req;
		/* 9.3.3.11 Probe Response frame format */
		struct {
			uint64_t	timestamp;
			uint16_t	beacon_int;
			uint16_t	capab_info;
			uint8_t		variable[0];
		} probe_resp;
		/* 9.3.3.14 Action frame format */
		struct {
			/* 9.4.1.11 Action field */
			uint8_t		category;
			/* 9.6.8 Public Action details */
			union {
				/* 9.6.2.5 TPC Report frame format */
				struct {
					uint8_t spec_mgmt;
					uint8_t dialog_token;
					/* uint32_t tpc_rep_elem:: */
					uint8_t tpc_elem_id;
					uint8_t tpc_elem_length;
					uint8_t tpc_elem_tx_power;
					uint8_t tpc_elem_link_margin;
				} tpc_report;
				/* 9.6.8.33 Fine Timing Measurement frame format */
				struct {
					uint8_t	dialog_token;
					uint8_t	follow_up;
					uint8_t	tod[6];
					uint8_t	toa[6];
					uint16_t tod_error;
					uint16_t toa_error;
					uint8_t variable[0];
				} ftm;
				/* 802.11-2016, 9.6.5.2 ADDBA Request frame format */
				struct {
					uint8_t action_code;
					uint8_t dialog_token;
					uint16_t capab;
					uint16_t timeout;
					uint16_t start_seq_num;
					/* Optional follows... */
					uint8_t variable[0];
				} addba_req;
			} u;
		} action;
	} u;
};

#define	MHZ_TO_KHZ(_f)		((_f) * 1000)
#define	DBI_TO_MBI(_g)		((_g) * 100)
#define	MBI_TO_DBI(_x)		((_x) / 100)
#define	DBM_TO_MBM(_g)		((_g) * 100)
#define	MBM_TO_DBM(_x)		((_x) / 100)

#define	IEEE80211_SEQ_TO_SN(_seqn)	(((_seqn) & IEEE80211_SEQ_SEQ_MASK) >> \
					    IEEE80211_SEQ_SEQ_SHIFT)

/* Time unit (TU) to .. See net80211: IEEE80211_DUR_TU */
#define	TU_TO_JIFFIES(_tu)	(usecs_to_jiffies(_tu) * 1024)
#define	TU_TO_EXP_TIME(_tu)	(jiffies + TU_TO_JIFFIES(_tu))

/* 9.4.2.21.1, Table 9-82. */
#define	IEEE80211_SPCT_MSR_RPRT_TYPE_LCI	8
#define	IEEE80211_SPCT_MSR_RPRT_TYPE_CIVIC	11

/* 9.4.2.1, Table 9-77. Element IDs. */
enum ieee80211_eid {
	WLAN_EID_SSID				= 0,
	WLAN_EID_SUPP_RATES			= 1,
	WLAN_EID_DS_PARAMS			= 3,
	WLAN_EID_TIM				= 5,
	WLAN_EID_COUNTRY			= 7,	/* IEEE80211_ELEMID_COUNTRY */
	WLAN_EID_REQUEST			= 10,
	WLAN_EID_CHANNEL_SWITCH			= 37,
	WLAN_EID_MEASURE_REPORT			= 39,
	WLAN_EID_HT_CAPABILITY			= 45,	/* IEEE80211_ELEMID_HTCAP */
	WLAN_EID_RSN				= 48,	/* IEEE80211_ELEMID_RSN */
	WLAN_EID_EXT_SUPP_RATES			= 50,
	WLAN_EID_EXT_CHANSWITCH_ANN		= 60,
	WLAN_EID_MULTIPLE_BSSID			= 71,	/* IEEE80211_ELEMID_MULTIBSSID */
	WLAN_EID_MULTI_BSSID_IDX		= 85,
	WLAN_EID_EXT_CAPABILITY			= 127,
	WLAN_EID_VHT_CAPABILITY			= 191,	/* IEEE80211_ELEMID_VHT_CAP */
	WLAN_EID_VENDOR_SPECIFIC		= 221,
};

enum ieee80211_eid_ext {
	WLAN_EID_EXT_HE_CAPABILITY		= 35,
};

#define	for_each_element(_elem, _data, _len) \
	for (_elem = (const struct element *)(_data); \
	    (((const uint8_t *)(_data) + (_len) - (const uint8_t *)_elem) >= sizeof(*_elem)) && \
		(((const uint8_t *)(_data) + (_len) - (const uint8_t *)_elem) >= (sizeof(*_elem) + _elem->datalen)); \
	    _elem = (const struct element *)(_elem->data + _elem->datalen))

#define	for_each_element_id(_elem, _eid, _data, _len) \
	for_each_element(_elem, _data, _len) \
		if (_elem->id == (_eid))

/* 9.4.1.7, Table 9-45. Reason codes. */
enum ieee80211_reason_code {
	/* reserved				= 0, */
	WLAN_REASON_UNSPECIFIED			= 1,
	WLAN_REASON_DEAUTH_LEAVING		= 3,	/* LEAVING_NETWORK_DEAUTH */
	WLAN_REASON_TDLS_TEARDOWN_UNREACHABLE	= 25,
	WLAN_REASON_TDLS_TEARDOWN_UNSPECIFIED	= 26,
};

/* 9.4.1.9, Table 9-46. Status codes. */
enum ieee80211_status_code {
	WLAN_STATUS_SUCCESS			= 0,
	WLAN_STATUS_AUTH_TIMEOUT		= 16,	/* REJECTED_SEQUENCE_TIMEOUT */
};

/* 9.3.1.22 Trigger frame format; 80211ax-2021 */
struct ieee80211_trigger {
        __le16		frame_control;
        __le16		duration_id;
	uint8_t		ra[ETH_ALEN];
	uint8_t		ta[ETH_ALEN];
	__le64		common_info;		/* 8+ really */
	uint8_t		variable[];
};

/* Table 9-29c-Trigger Type subfield encoding */
enum {
	IEEE80211_TRIGGER_TYPE_BASIC		= 0x0,
#if 0
	/* Not seen yet. */
	BFRP					= 0x1,
	MU-BAR					= 0x2,
	MU-RTS					= 0x3,
	BSRP					= 0x4,
	GCR MU-BAR				= 0x5,
	BQRP					= 0x6,
	NFRP					= 0x7,
	/* 0x8..0xf reserved */
#endif
	IEEE80211_TRIGGER_TYPE_MASK		= 0xf
};

/* 802.11-2020, Figure 9-687-Control field format; 802.11ax-2021 */
#define	IEEE80211_TWT_CONTROL_NEG_TYPE_BROADCAST	BIT(3)
#define	IEEE80211_TWT_CONTROL_RX_DISABLED		BIT(4)
#define	IEEE80211_TWT_CONTROL_WAKE_DUR_UNIT		BIT(5)

/* 802.11-2020, Figure 9-688-Request Type field format; 802.11ax-2021 */
#define	IEEE80211_TWT_REQTYPE_SETUP_CMD		(BIT(1) | BIT(2) | BIT(3))
#define	IEEE80211_TWT_REQTYPE_TRIGGER		BIT(4)
#define	IEEE80211_TWT_REQTYPE_IMPLICIT		BIT(5)
#define	IEEE80211_TWT_REQTYPE_FLOWTYPE		BIT(6)
#define	IEEE80211_TWT_REQTYPE_FLOWID		(BIT(7) | BIT(8) | BIT(9))
#define	IEEE80211_TWT_REQTYPE_WAKE_INT_EXP	(BIT(10) | BIT(11) | BIT(12) | BIT(13) | BIT(14))
#define	IEEE80211_TWT_REQTYPE_PROTECTION	BIT(15)

struct ieee80211_twt_params {
	int	mantissa, min_twt_dur, twt;
	uint16_t				req_type;
};

struct ieee80211_twt_setup {
	int	control;
	struct ieee80211_twt_params		*params;
};

/* 802.11-2020, Table 9-297-TWT Setup Command field values */
enum ieee80211_twt_setup_cmd {
	TWT_SETUP_CMD_REQUEST			= 0,
	TWT_SETUP_CMD_SUGGEST			= 1,
	/* DEMAND				= 2, */
	/* GROUPING				= 3, */
	TWT_SETUP_CMD_ACCEPT			= 4,
	/* ALTERNATE				= 5 */
	TWT_SETUP_CMD_DICTATE			= 6,
	TWT_SETUP_CMD_REJECT			= 7,
};

struct ieee80211_bssid_index {
	int	bssid_index;
};

/* net80211: IEEE80211_IS_CTL() */
static __inline bool
ieee80211_is_ctl(__le16 fc)
{
	__le16 v;

	fc &= htole16(IEEE80211_FC0_TYPE_MASK);
	v = htole16(IEEE80211_FC0_TYPE_CTL);

	return (fc == v);
}

/* net80211: IEEE80211_IS_DATA() */
static __inline bool
ieee80211_is_data(__le16 fc)
{
	__le16 v;

	fc &= htole16(IEEE80211_FC0_TYPE_MASK);
	v = htole16(IEEE80211_FC0_TYPE_DATA);

	return (fc == v);
}

/* net80211: IEEE80211_IS_QOSDATA() */
static __inline bool
ieee80211_is_data_qos(__le16 fc)
{
	__le16 v;

	fc &= htole16(IEEE80211_FC0_SUBTYPE_QOS_DATA | IEEE80211_FC0_TYPE_MASK);
	v = htole16(IEEE80211_FC0_SUBTYPE_QOS_DATA | IEEE80211_FC0_TYPE_DATA);

	return (fc == v);
}

/* net80211: IEEE80211_IS_MGMT() */
static __inline bool
ieee80211_is_mgmt(__le16 fc)
{
	__le16 v;

	fc &= htole16(IEEE80211_FC0_TYPE_MASK);
	v = htole16(IEEE80211_FC0_TYPE_MGT);

	return (fc == v);
}


/* Derived from net80211::ieee80211_anyhdrsize. */
static __inline unsigned int
ieee80211_hdrlen(__le16 fc)
{
	unsigned int size;

	if (ieee80211_is_ctl(fc)) {
		switch (fc & htole16(IEEE80211_FC0_SUBTYPE_MASK)) {
		case htole16(IEEE80211_FC0_SUBTYPE_CTS):
		case htole16(IEEE80211_FC0_SUBTYPE_ACK):
			return sizeof(struct ieee80211_frame_ack);
		case htole16(IEEE80211_FC0_SUBTYPE_BAR):
			return sizeof(struct ieee80211_frame_bar);
		}
		return (sizeof(struct ieee80211_frame_min));
	}

	size = sizeof(struct ieee80211_frame);
	if (ieee80211_is_data(fc)) {
		if ((fc & htole16(IEEE80211_FC1_DIR_MASK << 8)) ==
		    htole16(IEEE80211_FC1_DIR_DSTODS << 8))
			size += IEEE80211_ADDR_LEN;
		if ((fc & htole16(IEEE80211_FC0_SUBTYPE_QOS_DATA |
		    IEEE80211_FC0_TYPE_MASK)) ==
		    htole16(IEEE80211_FC0_SUBTYPE_QOS_DATA |
		    IEEE80211_FC0_TYPE_DATA))
			size += sizeof(uint16_t);
	}

	if (ieee80211_is_mgmt(fc)) {
#ifdef __notyet__
		printf("XXX-BZ %s: TODO? fc %#04x size %u\n",
		    __func__, fc, size);
#endif
		;
	}

	return (size);
}

static inline bool
ieee80211_is_trigger(__le16 fc)
{
	__le16 v;

	fc &= htole16(IEEE80211_FC0_SUBTYPE_MASK | IEEE80211_FC0_TYPE_MASK);
	v = htole16(IEEE80211_FC0_SUBTYPE_TRIGGER | IEEE80211_FC0_TYPE_CTL);

	return (fc == v);
}

#endif	/* _LINUXKPI_LINUX_IEEE80211_H */
