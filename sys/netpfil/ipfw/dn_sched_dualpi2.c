/* 
 * DUALPI2 - Low Latency Low Loss Scalable Throughput (DUALPI2) scheduler/AQM
 * 
 * Copyright (C) 2016 Centre for Advanced Internet Architectures,
 *  Swinburne University of Technology, Melbourne, Australia.
 * Portions of this code were made possible in part by a gift from 
 *  The Comcast Innovation Fund.
 * Implemented by Rasool Al-Saadi <ralsaadi@swin.edu.au>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Important note:
 * This DUALPI2 implementation is a beta version and have not been tested 
 * extensively. Our DUALPI2 uses stand-alone PIE AQM per sub-queue. By
 * default, timestamp is used to calculate queue delay instead of departure
 * rate estimation method. Although departure rate estimation is available 
 * as testing option, the results could be incorrect. Moreover, turning PIE on 
 * and off option is available but it does not work properly in this version.
 */

#ifdef _KERNEL
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <net/if.h>	/* IFNAMSIZ */
#include <netinet/in.h>
#include <netinet/ip_var.h>		/* ipfw_rule_ref */
#include <netinet/ip_fw.h>	/* flow_id */
#include <netinet/ip_dummynet.h>

#include <sys/proc.h>
#include <sys/rwlock.h>

#include <netpfil/ipfw/ip_fw_private.h>
#include <sys/sysctl.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/queue.h>
#include <sys/hash.h>

#include <netpfil/ipfw/dn_heap.h>
#include <netpfil/ipfw/ip_dn_private.h>

#include <netpfil/ipfw/dn_aqm.h>
#include <netpfil/ipfw/dn_aqm_pie.h>
#include <netpfil/ipfw/dn_sched.h>

#else
#include <dn_test.h>
#endif

#define DN_SCHED_DUALPI2 8

/* list of queues */
STAILQ_HEAD(dualpi2_list, dualpi2_flow);


enum { 
	CLASSIC_QUEUE	= 0,	/* C queue */
	L4S_QUEUE		= 1,	/* L queue (scalable marking/classic drops) */
};



/* DUALPI2 parameters including PIE */
struct dn_sch_dualpi2_parms {
	struct dn_aqm_pie_parms	pcfg;	/* PIE configuration Parameters */
	/* DUALPI2 Parameters */
	uint32_t flows_cnt;	/* number of flows */
	uint32_t limit;	/* hard limit of DUALPI2 queue size*/
	uint32_t quantum;
};

/* flow (sub-queue) stats */
struct flow_stats {
	uint64_t tot_pkts;	/* statistics counters  */
	uint64_t tot_bytes;
	uint32_t length;		/* Queue length, in packets */
	uint32_t len_bytes;	/* Queue length, in bytes */
	uint32_t drops;
};

/* A flow of packets (sub-queue)*/
struct dualpi2_flow {
	struct mq	mq;	/* list of packets */
	struct flow_stats stats;	/* statistics */
	int deficit;
	uint8_t wl;
	uint8_t wc;
	unsigned int queue_type : 1; // 1-bit field, 0 - Classic Queue, and 1 - DUALPI2 Queue
	uint32_t	l_base_drop_prob;
	uint32_t	c_base_drop_prob;
	int active;		/* 1: flow is active (in a list) */
	struct pie_status pst;	/* pie status variables */
	struct dualpi2_si_extra *psi_extra;
	STAILQ_ENTRY(dualpi2_flow) flowchain;
};

/* extra dualpi2 scheduler configurations */
struct dualpi2_schk {
	struct dn_sch_dualpi2_parms cfg;
};

/* dualpi2 scheduler instance extra state vars.
 * The purpose of separation this structure is to preserve number of active
 * sub-queues and the flows array pointer even after the scheduler instance
 * is destroyed.
 * Preserving these varaiables allows freeing the allocated memory by
 * dualpi2_callout_cleanup() independently from dualpi2_free_sched().
 */
struct dualpi2_si_extra {
	uint32_t nr_active_q;	/* number of active queues */
	struct dualpi2_flow *flows;	/* array of flows (queues) */
	};

/* dualpi2 scheduler instance */
struct dualpi2_si {
	struct dn_sch_inst _si;	/* standard scheduler instance. SHOULD BE FIRST */ 
	struct dn_queue main_q; /* main queue is after si directly */
	uint32_t perturbation; 	/* random value */
	struct dualpi2_list newflows;	/* list of new queues */
	struct dualpi2_list oldflows;	/* list of old queues */
	struct dualpi2_si_extra *si_extra; /* extra state vars*/
};

static struct dn_alg dualpi2_desc;

/*  Default DUALPI2 parameters including PIE */
/*  PIE defaults
 * target=15ms, max_burst=150ms, max_ecnth=0.1, 
 * alpha=0.125, beta=1.25, tupdate=15ms
 * FQ-
 * flows=2, limit=10240, quantum =1514
 */
struct dn_sch_dualpi2_parms 
 dualpi2_sysctl = {{15000 * AQM_TIME_1US, 15000 * AQM_TIME_1US,
	150000 * AQM_TIME_1US, PIE_SCALE * 0.1, PIE_SCALE * 0.125, 
	PIE_SCALE * 1.25,	PIE_CAPDROP_ENABLED | PIE_DERAND_ENABLED},
	2, 10240, 1514};

static int
dualpi2_sysctl_alpha_beta_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	long  value;

	if (!strcmp(oidp->oid_name,"alpha"))
		value = dualpi2_sysctl.pcfg.alpha;
	else
		value = dualpi2_sysctl.pcfg.beta;
		
	value = value * 1000 / PIE_SCALE;
	error = sysctl_handle_long(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > 7 * PIE_SCALE)
		return (EINVAL);
	value = (value * PIE_SCALE) / 1000;
	if (!strcmp(oidp->oid_name,"alpha"))
			dualpi2_sysctl.pcfg.alpha = value;
	else
		dualpi2_sysctl.pcfg.beta = value;
	return (0);
}

static int
dualpi2_sysctl_target_tupdate_maxb_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	long  value;

	if (!strcmp(oidp->oid_name,"target"))
		value = dualpi2_sysctl.pcfg.qdelay_ref;
	else if (!strcmp(oidp->oid_name,"tupdate"))
		value = dualpi2_sysctl.pcfg.tupdate;
	else
		value = dualpi2_sysctl.pcfg.max_burst;

	value = value / AQM_TIME_1US;
	error = sysctl_handle_long(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > 10 * AQM_TIME_1S)
		return (EINVAL);
	value = value * AQM_TIME_1US;

	if (!strcmp(oidp->oid_name,"target"))
		dualpi2_sysctl.pcfg.qdelay_ref  = value;
	else if (!strcmp(oidp->oid_name,"tupdate"))
		dualpi2_sysctl.pcfg.tupdate  = value;
	else
		dualpi2_sysctl.pcfg.max_burst = value;
	return (0);
}

static int
dualpi2_sysctl_max_ecnth_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	long  value;

	value = dualpi2_sysctl.pcfg.max_ecnth;
	value = value * 1000 / PIE_SCALE;
	error = sysctl_handle_long(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 1 || value > PIE_SCALE)
		return (EINVAL);
	value = (value * PIE_SCALE) / 1000;
	dualpi2_sysctl.pcfg.max_ecnth = value;
	return (0);
}

/* define DUALPI2 sysctl variables */
SYSBEGIN(f4)
SYSCTL_DECL(_net_inet);
SYSCTL_DECL(_net_inet_ip);
SYSCTL_DECL(_net_inet_ip_dummynet);
static SYSCTL_NODE(_net_inet_ip_dummynet, OID_AUTO, dualpi2,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "DUALPI2");

#ifdef SYSCTL_NODE

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, target,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_target_tupdate_maxb_handler, "L",
    "queue target in microsecond");

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, tupdate,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_target_tupdate_maxb_handler, "L",
    "the frequency of drop probability calculation in microsecond");

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, max_burst,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_target_tupdate_maxb_handler, "L",
    "Burst allowance interval in microsecond");

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, max_ecnth,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_max_ecnth_handler, "L",
    "ECN safeguard threshold scaled by 1000");

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, alpha,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_alpha_beta_handler, "L",
    "PIE alpha scaled by 1000");

SYSCTL_PROC(_net_inet_ip_dummynet_dualpi2, OID_AUTO, beta,
    CTLTYPE_LONG | CTLFLAG_RW | CTLFLAG_NEEDGIANT, NULL, 0,
    dualpi2_sysctl_alpha_beta_handler, "L",
    "beta scaled by 1000");

SYSCTL_UINT(_net_inet_ip_dummynet_dualpi2, OID_AUTO, quantum,
	CTLFLAG_RW, &dualpi2_sysctl.quantum, 1514, "quantum for DUALPI2");
SYSCTL_UINT(_net_inet_ip_dummynet_dualpi2, OID_AUTO, flows,
	CTLFLAG_RW, &dualpi2_sysctl.flows_cnt, 2, "Number of queues for DUALPI2");
SYSCTL_UINT(_net_inet_ip_dummynet_dualpi2, OID_AUTO, limit,
	CTLFLAG_RW, &dualpi2_sysctl.limit, 10240, "limit for DUALPI2");
#endif

/* Helper function to update queue&main-queue and scheduler statistics.
 * negative len & drop -> drop
 * negative len -> dequeue
 * positive len -> enqueue
 * positive len + drop -> drop during enqueue
 */
__inline static void
fq_update_stats(struct dualpi2_flow *q, struct dualpi2_si *si, int len,
	int drop)
{
	int inc = 0;

	if (len < 0) 
		inc = -1;
	else if (len > 0)
		inc = 1;

	if (drop) {
		si->main_q.ni.drops ++;
		q->stats.drops ++;
		si->_si.ni.drops ++;
		V_dn_cfg.io_pkt_drop ++;
	} 

	if (!drop || (drop && len < 0)) {
		/* Update stats for the main queue */
		si->main_q.ni.length += inc;
		si->main_q.ni.len_bytes += len;

		/*update sub-queue stats */
		q->stats.length += inc;
		q->stats.len_bytes += len;

		/*update scheduler instance stats */
		si->_si.ni.length += inc;
		si->_si.ni.len_bytes += len;
	}

	if (inc > 0) {
		si->main_q.ni.tot_bytes += len;
		si->main_q.ni.tot_pkts ++;
		
		q->stats.tot_bytes +=len;
		q->stats.tot_pkts++;
		
		si->_si.ni.tot_bytes +=len;
		si->_si.ni.tot_pkts ++;
	}

}

/*
 * Extract a packet from the head of sub-queue 'q'
 * Return a packet or NULL if the queue is empty.
 * If getts is set, also extract packet's timestamp from mtag.
 */
__inline static struct mbuf *
dualpi2_extract_head(struct dualpi2_flow *q, aqm_time_t *pkt_ts,
	struct dualpi2_si *si, int getts)
{
	struct mbuf *m;

	m = q->mq.head;
	if (m == NULL)
		return m;
	q->mq.head = m->m_nextpkt;

	fq_update_stats(q, si, -m->m_pkthdr.len, 0);

	if (si->main_q.ni.length == 0) /* queue is now idle */
			si->main_q.q_time = V_dn_cfg.curr_time;

	if (getts) {
		/* extract packet timestamp*/
		struct m_tag *mtag;
		mtag = m_tag_locate(m, MTAG_ABI_COMPAT, DN_AQM_MTAG_TS, NULL);
		if (mtag == NULL){
			D("PIE timestamp mtag not found!");
			*pkt_ts = 0;
		} else {
			*pkt_ts = *(aqm_time_t *)(mtag + 1);
			m_tag_delete(m,mtag); 
		}
	}
	return m;
}


// /*
//  * Extract a packet from the head of sub-queue 'q'
//  * Return a packet or NULL if the queue is empty.
//  * If getts is set, also extract packet's timestamp from mtag.
//  */
// __inline static struct mbuf *
// dualpi2_extract_head(struct dualpi2_flow *q, aqm_time_t *pkt_ts,
// 	struct dualpi2_si *si, int getts)
// {
// 	struct mbuf *m;

// next:	m = q->mq.head;
// 	if (m == NULL)
// 		return m;
// 	q->mq.head = m->m_nextpkt;

// 	fq_update_stats(q, si, -m->m_pkthdr.len, 0);

// 	if (si->main_q.ni.length == 0) /* queue is now idle */
// 			si->main_q.q_time = V_dn_cfg.curr_time;

// 	if (getts) {
// 		/* extract packet timestamp*/
// 		struct m_tag *mtag;
// 		mtag = m_tag_locate(m, MTAG_ABI_COMPAT, DN_AQM_MTAG_TS, NULL);
// 		if (mtag == NULL){
// 			D("PIE timestamp mtag not found!");
// 			*pkt_ts = 0;
// 		} else {
// 			*pkt_ts = *(aqm_time_t *)(mtag + 1);
// 			m_tag_delete(m,mtag); 
// 		}
// 	}
// 	if (m->m_pkthdr.rcvif != NULL &&
// 	    __predict_false(m_rcvif_restore(m) == NULL)) {
// 		m_freem(m);
// 		goto next;
// 	}
// 	return m;
// }

/*
 * Callout function for drop probability calculation 
 * This function is called over tupdate ms and takes pointer of DUALPI2
 * flow as an argument
  */
static void
fq_calculate_drop_prob(void *x)
{
	struct dualpi2_flow *q = (struct dualpi2_flow *) x;
	struct pie_status *pst = &q->pst;
	struct dn_aqm_pie_parms *pprms; 
	int64_t p, prob, oldprob;
	int p_isneg;

	pprms = pst->parms;
	prob = pst->drop_prob;

	/* calculate current qdelay using DRE method.
	 * If TS is used and no data in the queue, reset current_qdelay
	 * as it stays at last value during dequeue process.
	*/
	if (pprms->flags & PIE_DEPRATEEST_ENABLED)
		pst->current_qdelay = ((uint64_t)q->stats.len_bytes  * pst->avg_dq_time)
			>> PIE_DQ_THRESHOLD_BITS;
	else
		if (!q->stats.len_bytes)
			pst->current_qdelay = 0;

	/* calculate drop probability */
	p = (int64_t)pprms->alpha * 
		((int64_t)pst->current_qdelay - (int64_t)pprms->qdelay_ref); 
	p +=(int64_t) pprms->beta * 
		((int64_t)pst->current_qdelay - (int64_t)pst->qdelay_old); 

	/* take absolute value so right shift result is well defined */
	p_isneg = p < 0;
	if (p_isneg) {
		p = -p;
	}
		
	/* We PIE_MAX_PROB shift by 12-bits to increase the division precision  */
	p *= (PIE_MAX_PROB << 12) / AQM_TIME_1S;

	/* auto-tune drop probability */
	if (prob < (PIE_MAX_PROB / 1000000)) /* 0.000001 */
		p >>= 11 + PIE_FIX_POINT_BITS + 12;
	else if (prob < (PIE_MAX_PROB / 100000)) /* 0.00001 */
		p >>= 9 + PIE_FIX_POINT_BITS + 12;
	else if (prob < (PIE_MAX_PROB / 10000)) /* 0.0001 */
		p >>= 7 + PIE_FIX_POINT_BITS + 12;
	else if (prob < (PIE_MAX_PROB / 1000)) /* 0.001 */
		p >>= 5 + PIE_FIX_POINT_BITS + 12;
	else if (prob < (PIE_MAX_PROB / 100)) /* 0.01 */
		p >>= 3 + PIE_FIX_POINT_BITS + 12;
	else if (prob < (PIE_MAX_PROB / 10)) /* 0.1 */
		p >>= 1 + PIE_FIX_POINT_BITS + 12;
	else
		p >>= PIE_FIX_POINT_BITS + 12;

	oldprob = prob;

	if (p_isneg) {
		prob = prob - p;

		/* check for multiplication underflow */
		if (prob > oldprob) {
			prob= 0;
			D("underflow");
		}
	} else {
		/* Cap Drop adjustment */
		if ((pprms->flags & PIE_CAPDROP_ENABLED) &&
		    prob >= PIE_MAX_PROB / 10 &&
		    p > PIE_MAX_PROB / 50 ) {
			p = PIE_MAX_PROB / 50;
		}

		prob = prob + p;

		/* check for multiplication overflow */
		if (prob<oldprob) {
			D("overflow");
			prob= PIE_MAX_PROB;
		}
	}

	/*
	 * decay the drop probability exponentially
	 * and restrict it to range 0 to PIE_MAX_PROB
	 */
	if (prob < 0) {
		prob = 0;
	} else {
		if (pst->current_qdelay == 0 && pst->qdelay_old == 0) {
			/* 0.98 ~= 1- 1/64 */
			prob = prob - (prob >> 6); 
		}

		if (prob > PIE_MAX_PROB) {
			prob = PIE_MAX_PROB;
		}
	}

	pst->drop_prob = prob;
	// printf("fq_calculate_drop_prob \n");
	if (q->queue_type == L4S_QUEUE)	{
		// printf("Queue type is DUALPI2.  -- ");
		q->l_base_drop_prob = pst->drop_prob;
		// printf("Assign l_base_drop_prob: %u \n",q->l_base_drop_prob);
	}
	else	{
		// printf("Queue type is classic.  -- ");
		q->c_base_drop_prob = pst->drop_prob;
		// printf("Assign c_base_drop_prob: %u \n",q->c_base_drop_prob);
	}

	/* store current delay value */
	pst->qdelay_old = pst->current_qdelay;

	/* update burst allowance */
	if ((pst->sflags & PIE_ACTIVE) && pst->burst_allowance) {
		if (pst->burst_allowance > pprms->tupdate)
			pst->burst_allowance -= pprms->tupdate;
		else 
			pst->burst_allowance = 0;
	}

	if (pst->sflags & PIE_ACTIVE)
	callout_reset_sbt(&pst->aqm_pie_callout,
		(uint64_t)pprms->tupdate * SBT_1US,
		0, fq_calculate_drop_prob, q, 0);

	mtx_unlock(&pst->lock_mtx);
}

/* 
 * Reset PIE variables & activate the queue
 */
__inline static void
fq_activate_pie(struct dualpi2_flow *q)
{
	// printf("Activate PIE :%u \n", q->queue_type); 
	struct pie_status *pst = &q->pst;
	struct dn_aqm_pie_parms *pprms;

	mtx_lock(&pst->lock_mtx);
	pprms = pst->parms;

	pprms = pst->parms;
	pst->drop_prob = 0;
	q->l_base_drop_prob=0;
	q->c_base_drop_prob=0;
	pst->qdelay_old = 0;
	pst->burst_allowance = pprms->max_burst;
	pst->accu_prob = 0;
	pst->dq_count = 0;
	pst->avg_dq_time = 0;
	pst->sflags = PIE_INMEASUREMENT | PIE_ACTIVE;
	pst->measurement_start = AQM_UNOW;

	callout_reset_sbt(&pst->aqm_pie_callout,
		(uint64_t)pprms->tupdate * SBT_1US,
		0, fq_calculate_drop_prob, q, 0);

	mtx_unlock(&pst->lock_mtx);
}

 /* 
  * Deactivate PIE and stop probe update callout
  */
__inline static void
fq_deactivate_pie(struct pie_status *pst)
{ 
	mtx_lock(&pst->lock_mtx);
	pst->sflags &= ~(PIE_ACTIVE | PIE_INMEASUREMENT);
	callout_stop(&pst->aqm_pie_callout);
	//D("PIE Deactivated");
	mtx_unlock(&pst->lock_mtx);
	// printf("Deactivate PIE \n");
}

 /* 
  * Initialize PIE for sub-queue 'q'
  */
static int
pie_init(struct dualpi2_flow *q, struct dualpi2_schk *dualpi2_schk)
{
	struct pie_status *pst=&q->pst;
	struct dn_aqm_pie_parms *pprms = pst->parms;

	int err = 0;
	if (!pprms){
		D("AQM_PIE is not configured");
		err = EINVAL;
	} else {
		q->psi_extra->nr_active_q++;

		/* For speed optimization, we caculate 1/3 queue size once here */
		// XXX limit divided by number of queues divided by 3 ??? 
		pst->one_third_q_size = (dualpi2_schk->cfg.limit / 
			dualpi2_schk->cfg.flows_cnt) / 3;

		mtx_init(&pst->lock_mtx, "mtx_pie", NULL, MTX_DEF);
		callout_init_mtx(&pst->aqm_pie_callout, &pst->lock_mtx,
			CALLOUT_RETURNUNLOCKED);
	}

	return err;
}

/* 
 * callout function to destroy PIE lock, and free dualpi2 flows and dualpi2 si
 * extra memory when number of active sub-queues reaches zero.
 * 'x' is a dualpi2_flow to be destroyed
 */
static void
dualpi2_callout_cleanup(void *x)
{
	struct dualpi2_flow *q = x;
	struct pie_status *pst = &q->pst;
	struct dualpi2_si_extra *psi_extra;

	mtx_unlock(&pst->lock_mtx);
	mtx_destroy(&pst->lock_mtx);
	psi_extra = q->psi_extra;

	dummynet_sched_lock();
	psi_extra->nr_active_q--;

	/* when all sub-queues are destroyed, free flows dualpi2 extra vars memory */
	if (!psi_extra->nr_active_q) {
		free(psi_extra->flows, M_DUMMYNET);
		free(psi_extra, M_DUMMYNET);
		dualpi2_desc.ref_count--;
	}
	dummynet_sched_unlock();
}

/* 
 * Clean up PIE status for sub-queue 'q' 
 * Stop callout timer and destroy mtx using dualpi2_callout_cleanup() callout.
 */
static int
pie_cleanup(struct dualpi2_flow *q)
{
	struct pie_status *pst  = &q->pst;

	mtx_lock(&pst->lock_mtx);
	callout_reset_sbt(&pst->aqm_pie_callout,
		SBT_1US, 0, dualpi2_callout_cleanup, q, 0);
	mtx_unlock(&pst->lock_mtx);
	return 0;
}

/* 
 * Dequeue and return a pcaket from sub-queue 'q' or NULL if 'q' is empty.
 * Also, caculate depature time or queue delay using timestamp
 */
 static struct mbuf *
pie_dequeue(struct dualpi2_flow *q, struct dualpi2_si *si)
{
	struct mbuf *m;
	struct dn_aqm_pie_parms *pprms;
	struct pie_status *pst;
	aqm_time_t now;
	aqm_time_t pkt_ts, dq_time;
	int32_t w;

	pst  = &q->pst;
	pprms = q->pst.parms;

	/*we extarct packet ts only when Departure Rate Estimation dis not used*/
	m = dualpi2_extract_head(q, &pkt_ts, si, 
		!(pprms->flags & PIE_DEPRATEEST_ENABLED));

	if (!m || !(pst->sflags & PIE_ACTIVE))
		return m;

	now = AQM_UNOW;
	if (pprms->flags & PIE_DEPRATEEST_ENABLED) {
		/* calculate average depature time */
		if(pst->sflags & PIE_INMEASUREMENT) {
			pst->dq_count += m->m_pkthdr.len;

			if (pst->dq_count >= PIE_DQ_THRESHOLD) {
				dq_time = now - pst->measurement_start;

				/* 
				 * if we don't have old avg dq_time i.e PIE is (re)initialized, 
				 * don't use weight to calculate new avg_dq_time
				 */
				if(pst->avg_dq_time == 0)
					pst->avg_dq_time = dq_time;
				else {
					/*
					 * weight = PIE_DQ_THRESHOLD/2^6, but we scaled
					 * weight by 2^8. Thus, scaled
					 * weight = PIE_DQ_THRESHOLD /2^8
					 * */
					w = PIE_DQ_THRESHOLD >> 8;
					pst->avg_dq_time = (dq_time* w
						+ (pst->avg_dq_time * ((1L << 8) - w))) >> 8;
					pst->sflags &= ~PIE_INMEASUREMENT;
				}
			}
		}

		/*
		 * Start new measurement cycle when the queue has
		 * PIE_DQ_THRESHOLD worth of bytes.
		 */
		if(!(pst->sflags & PIE_INMEASUREMENT) &&
			q->stats.len_bytes >= PIE_DQ_THRESHOLD) {
			pst->sflags |= PIE_INMEASUREMENT;
			pst->measurement_start = now;
			pst->dq_count = 0;
		}
	}
	/* Optionally, use packet timestamp to estimate queue delay */
	else
		pst->current_qdelay = now - pkt_ts;

	return m;
}

/* 
* For c-queue drop early, its drop probability is p'^2 
* Packets in the C queue are subject to a marking probability pC, which is the
* square of the internal PI2 probability (i.e., have an overall lower mark/drop
* probability). If the qdisc is overloaded, ignore ECT values and only drop.
* Note that this marking scheme is also applied to DUALPI2 packets during overload.
*/
__inline static int
cqueue_drop_early(struct pie_status *pst, uint32_t qlen)
{
	// printf("cqueue_drop_early start \n");
	struct dn_aqm_pie_parms *pprms;

	pprms = pst->parms;

	/* queue is not congested */

	if ((pst->qdelay_old < (pprms->qdelay_ref >> 1)
		&& pst->drop_prob < PIE_MAX_PROB / 5 )
		||  qlen <= 2 * MEAN_PKTSIZE)
		return ENQUE;

	if (pst->drop_prob == 0)
		pst->accu_prob = 0;

	/* increment accu_prob */
	if (pprms->flags & PIE_DERAND_ENABLED)
		pst->accu_prob += pst->drop_prob;

	/* De-randomize option 
	 * if accu_prob < 0.85 -> enqueue
	 * if accu_prob>8.5 ->drop
	 * between 0.85 and 8.5 || !De-randomize --> drop on prob
	 * 
	 * (0.85 = 17/20 ,8.5 = 17/2)
	 */
	if (pprms->flags & PIE_DERAND_ENABLED) {
		if(pst->accu_prob < (uint64_t) (PIE_MAX_PROB * 17 / 20))
			return ENQUE;
		 if( pst->accu_prob >= (uint64_t) (PIE_MAX_PROB * 17 / 2))
			return DROP;
	}

	// Squaring Classic Probability
	if (random() < pst->drop_prob && random() < pst->drop_prob) {
		pst->accu_prob = 0;
		return DROP;
	}

	return ENQUE;
}


/* 
 * For l-queue drop early, its drop probability is max(p'_L,p_CL) where p'_L is base probability
 * and p_CL is internal PI2 probability scaled by the coupling factor
 *
 * On overload (i.e., @local_l_prob is >= 100%):
 * - if the qdisc is configured to trade losses to preserve latency (i.e.,
 *   @q->drop_overload), apply classic drops first before marking.
 * - otherwise, preserve the "no loss" property of ECN at the cost of queueing
 *   delay, eventually resulting in taildrop behavior once sch->limit is
 *   reached.
 */
__inline static int
lqueue_drop_early(struct pie_status *pst, uint32_t qlen, uint32_t local_l_prob, bool overload)
{
	// printf("lqueue_drop_early start \n");
	struct dn_aqm_pie_parms *pprms;

	pprms = pst->parms;

	/* queue is not congested */
	if ((pst->qdelay_old < (pprms->qdelay_ref >> 1)
		&& local_l_prob  < PIE_MAX_PROB / 5 )
		||  qlen <= 2 * MEAN_PKTSIZE)
		return ENQUE;

	if (local_l_prob  == 0)
		pst->accu_prob = 0;

	/* increment accu_prob */
	if (pprms->flags & PIE_DERAND_ENABLED)
		pst->accu_prob += local_l_prob ;

	/* De-randomize option 
	 * if accu_prob < 0.85 -> enqueue
	 * if accu_prob>8.5 ->drop
	 * between 0.85 and 8.5 || !De-randomize --> drop on prob
	 * 
	 * (0.85 = 17/20 ,8.5 = 17/2)
	 */
	if (pprms->flags & PIE_DERAND_ENABLED) {
		if(pst->accu_prob < (uint64_t) (PIE_MAX_PROB * 17 / 20))
			return ENQUE;
		 if( pst->accu_prob >= (uint64_t) (PIE_MAX_PROB * 17 / 2))
			return DROP;
	}

	if (overload) {
		if (random() < pst->drop_prob && random() < pst->drop_prob) {
			pst->accu_prob = 0;
			return DROP;
		}
	}
	else {
		if (random() < local_l_prob ) {
			pst->accu_prob = 0;
			return DROP;
		}
	}	

	return ENQUE;
}

 /*
 * Enqueue a packet in q, subject to space and DUALPI2 queue management policy
 * (whose parameters are in q->fs).
 * Update stats for the queue and the scheduler.
 * Return 0 on success, 1 on drop. The packet is consumed anyways.
 */
static int
pie_enqueue(struct dualpi2_flow *q, struct mbuf* m, struct dualpi2_si *si)
{
	uint64_t len;
	struct pie_status *pst;
	struct dn_aqm_pie_parms *pprms;
	int t;

	len = m->m_pkthdr.len;
	pst  = &q->pst;
	pprms = pst->parms;
	t = ENQUE;
	uint32_t local_l_prob ;
	uint8_t coupling_factor = 2;
	local_l_prob  = (pst->drop_prob > q->c_base_drop_prob * coupling_factor) ? pst->drop_prob : q->c_base_drop_prob * coupling_factor;
	bool overload = local_l_prob > PIE_MAX_PROB;
	// Output the boolean value using %s
    // printf("Overload: %s\n", overload ? "true" : "false");

	if (q->queue_type == CLASSIC_QUEUE)
		t = cqueue_drop_early(pst, q->stats.len_bytes);
	else if (q->queue_type == L4S_QUEUE)
		t = lqueue_drop_early(pst, q->stats.len_bytes, local_l_prob, overload);

	// printf("dequeue_action: %d \n", dequeue_action);

	
	/* drop/mark the packet when PIE is active and burst time elapsed */
	if (pst->sflags & PIE_ACTIVE && pst->burst_allowance == 0
		&& t == DROP) {
			/* 
			 * if drop_prob over ECN threshold, drop the packet 
			 * otherwise mark and enqueue it.
			 */
			if (pprms->flags & PIE_ECN_ENABLED && pst->drop_prob < 
				(pprms->max_ecnth << (PIE_PROB_BITS - PIE_FIX_POINT_BITS))
				&& ecn_mark(m))
				t = ENQUE;
			else
				t = DROP;
		}


	// printf("dualpi2_ecn_marking-start,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%u,%u,%u,%u,%lu,%lu,%u,%u,%u,%d,end \n",q->queue_type,pprms->qdelay_ref,pprms->tupdate,
	// pprms->max_burst,pprms->max_ecnth,pprms->alpha,pprms->beta,pprms->flags,
	// pst->burst_allowance,pst->drop_prob,pst->current_qdelay,pst->qdelay_old,pst->accu_prob,
	// pst->measurement_start,pst->avg_dq_time,pst->dq_count,pst->sflags,q->stats.tot_pkts,q->stats.tot_bytes,q->stats.length,
	// q->stats.len_bytes,q->stats.drops, dequeue_action);

	/* Turn PIE on when 1/3 of the queue is full */ 
	if (!(pst->sflags & PIE_ACTIVE) && q->stats.len_bytes >= 
		pst->one_third_q_size) {
		fq_activate_pie(q);
	}

	/*  reset burst tolerance and optinally turn PIE off*/
	if (pst->drop_prob == 0 && pst->current_qdelay < (pprms->qdelay_ref >> 1)
		&& pst->qdelay_old < (pprms->qdelay_ref >> 1)) {
			
			pst->burst_allowance = pprms->max_burst;
		if (pprms->flags & PIE_ON_OFF_MODE_ENABLED && q->stats.len_bytes<=0)
			fq_deactivate_pie(pst);
	}

	/* Use timestamp if Departure Rate Estimation mode is disabled */
	if (t != DROP && !(pprms->flags & PIE_DEPRATEEST_ENABLED)) {
		/* Add TS to mbuf as a TAG */
		struct m_tag *mtag;
		mtag = m_tag_locate(m, MTAG_ABI_COMPAT, DN_AQM_MTAG_TS, NULL);
		if (mtag == NULL)
			mtag = m_tag_alloc(MTAG_ABI_COMPAT, DN_AQM_MTAG_TS,
				sizeof(aqm_time_t), M_NOWAIT);
		if (mtag == NULL) {
			t = DROP;
		} else {
			*(aqm_time_t *)(mtag + 1) = AQM_UNOW;
			m_tag_prepend(m, mtag);
		}
	}

	if (t != DROP) {
		mq_append(&q->mq, m);
		fq_update_stats(q, si, len, 0);
		return 0;
	} else {
		fq_update_stats(q, si, len, 1);
		pst->accu_prob = 0;
		FREE_PKT(m);
		return 1;
	}

	return 0;
}

/* Drop a packet form the head of DUALPI2 sub-queue */
static void
pie_drop_head(struct dualpi2_flow *q, struct dualpi2_si *si)
{
	struct mbuf *m = q->mq.head;

	if (m == NULL)
		return;
	q->mq.head = m->m_nextpkt;

	fq_update_stats(q, si, -m->m_pkthdr.len, 1);

	if (si->main_q.ni.length == 0) /* queue is now idle */
			si->main_q.q_time = V_dn_cfg.curr_time;
	/* reset accu_prob after packet drop */
	q->pst.accu_prob = 0;

	FREE_PKT(m);
}

/*
 * Classify a packet to queue number using Jenkins hash function.
 * Return: queue number 
 * the input of the hash are protocol no, perturbation, src IP, dst IP,
 * src port, dst port,
 */
static inline int
dualpi2_classify_flow(struct mbuf *m, uint16_t fcount, struct dualpi2_si *si)
{
	struct ip *ip;
	struct tcphdr *th;
	struct udphdr *uh;
	uint8_t tuple[41];
	uint16_t hash=0;

	ip = (struct ip *)mtodo(m, dn_tag_get(m)->iphdr_off);
//#ifdef INET6
	struct ip6_hdr *ip6;
	int isip6;
	isip6 = (ip->ip_v == 6);

	if(isip6) {
		ip6 = (struct ip6_hdr *)ip;
		*((uint8_t *) &tuple[0]) = ip6->ip6_nxt;
		*((uint32_t *) &tuple[1]) = si->perturbation;
		memcpy(&tuple[5], ip6->ip6_src.s6_addr, 16);
		memcpy(&tuple[21], ip6->ip6_dst.s6_addr, 16);

		switch (ip6->ip6_nxt) {
		case IPPROTO_TCP:
			th = (struct tcphdr *)(ip6 + 1);
			*((uint16_t *) &tuple[37]) = th->th_dport;
			*((uint16_t *) &tuple[39]) = th->th_sport;
			break;

		case IPPROTO_UDP:
			uh = (struct udphdr *)(ip6 + 1);
			*((uint16_t *) &tuple[37]) = uh->uh_dport;
			*((uint16_t *) &tuple[39]) = uh->uh_sport;
			break;
		default:
			memset(&tuple[37], 0, 4);
		}

		hash = jenkins_hash(tuple, 41, HASHINIT) %  fcount;
		return hash;
	} 
//#endif

	/* IPv4 */
	*((uint8_t *) &tuple[0]) = ip->ip_p;
	*((uint32_t *) &tuple[1]) = si->perturbation;
	*((uint32_t *) &tuple[5]) = ip->ip_src.s_addr;
	*((uint32_t *) &tuple[9]) = ip->ip_dst.s_addr;

	switch (ip->ip_p) {
		case IPPROTO_TCP:
			th = (struct tcphdr *)(ip + 1);
			*((uint16_t *) &tuple[13]) = th->th_dport;
			*((uint16_t *) &tuple[15]) = th->th_sport;
			break;

		case IPPROTO_UDP:
			uh = (struct udphdr *)(ip + 1);
			*((uint16_t *) &tuple[13]) = uh->uh_dport;
			*((uint16_t *) &tuple[15]) = uh->uh_sport;
			break;
		default:
			memset(&tuple[13], 0, 4);
	}
	hash = jenkins_hash(tuple, 17, HASHINIT) % fcount;

	return hash;
}

/*
 * Enqueue a packet into an appropriate queue according to
 * DUALPI2; algorithm.
 */
static int 
dualpi2_enqueue(struct dn_sch_inst *_si, struct dn_queue *_q, 
	struct mbuf *m)
{ 
	struct dualpi2_si *si;
	struct dualpi2_schk *schk;
	struct dn_sch_dualpi2_parms *param;
	struct dn_queue *mainq;
	struct dualpi2_flow *flows;
	int idx, drop, i, maxidx;

	mainq = (struct dn_queue *)(_si + 1);
	si = (struct dualpi2_si *)_si;
	flows = si->si_extra->flows;
	schk = (struct dualpi2_schk *)(si->_si.sched+1);
	param = &schk->cfg;

	 /* classify a packet to queue number*/
	// idx = dualpi2_classify_flow(m, param->flows_cnt/2, si);
	

	/* Read IP packet header to classify packet into DUALPI2 and CLassic Queues
	* 0 - Classic Queue - Default
	* 1 - DUALPI2 Queue - ECT1 enabled in its packet header
	*/
	idx = 0;
    struct ip *ip;
	ip = (struct ip *)mtodo(m, dn_tag_get(m)->iphdr_off);
	if ((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT1)
		idx = 1 ;
	// printf("idx queue Type: %d \n",idx);
	/* enqueue packet into appropriate queue using PIE AQM.
	 * Note: 'pie_enqueue' function returns 1 only when it unable to 
	 * add timestamp to packet (no limit check)*/
	drop = pie_enqueue(&flows[idx], m, si);

	/* pie unable to timestamp a packet */ 
	if (drop)
		return 1;

	/* If the flow (sub-queue) is not active ,then add it to tail of
	 * new flows list, initialize and activate it.
	 */
	if (!flows[idx].active) {
		STAILQ_INSERT_TAIL(&si->newflows, &flows[idx], flowchain);
		//flows[idx].deficit = param->quantum;
		if (flows[idx].queue_type == L4S_QUEUE)
			flows[idx].deficit = flows[idx].wl * param->quantum;
		else
			flows[idx].deficit = flows[idx].wc * param->quantum;
		fq_activate_pie(&flows[idx]);
		flows[idx].active = 1;
	}

	/* check the limit for all queues and remove a packet from the
	 * largest one 
	 */
	if (mainq->ni.length > schk->cfg.limit) {
		/* find first active flow */
		for (maxidx = 0; maxidx < schk->cfg.flows_cnt; maxidx++)
			if (flows[maxidx].active)
				break;
		if (maxidx < schk->cfg.flows_cnt) {
			/* find the largest sub- queue */
			for (i = maxidx + 1; i < schk->cfg.flows_cnt; i++) 
				if (flows[i].active && flows[i].stats.length >
					flows[maxidx].stats.length)
					maxidx = i;
			pie_drop_head(&flows[maxidx], si);
			drop = 1;
		}
	}

	return drop;
}

/*
 * Dequeue a packet from an appropriate queue according to
 * DUALPI2 algorithm.
 */
static struct mbuf *
dualpi2_dequeue(struct dn_sch_inst *_si)
{ 
	struct dualpi2_si *si;
	struct dualpi2_schk *schk;
	struct dn_sch_dualpi2_parms *param;
	struct dualpi2_flow *f;
	struct mbuf *mbuf;
	struct dualpi2_list *dualpi2_flowlist;

	si = (struct dualpi2_si *)_si;
	schk = (struct dualpi2_schk *)(si->_si.sched+1);
	param = &schk->cfg;

	do {
		/* select a list to start with */
		if (STAILQ_EMPTY(&si->newflows))
			dualpi2_flowlist = &si->oldflows;
		else
			dualpi2_flowlist = &si->newflows;

		/* Both new and old queue lists are empty, return NULL */
		if (STAILQ_EMPTY(dualpi2_flowlist)) 
			return NULL;

		f = STAILQ_FIRST(dualpi2_flowlist);
		while (f != NULL)	{
			/* if there is no flow(sub-queue) deficit, increase deficit
			 * by quantum, move the flow to the tail of old flows list
			 * and try another flow.
			 * Otherwise, the flow will be used for dequeue.
			 */
			if (f->deficit < 0) {
				//  f->deficit += param->quantum;
				if (f->queue_type == L4S_QUEUE)
					f->deficit += f->wl * param->quantum;
				else
					f->deficit += f->wc * param->quantum;
				 STAILQ_REMOVE_HEAD(dualpi2_flowlist, flowchain);
				 STAILQ_INSERT_TAIL(&si->oldflows, f, flowchain);
			 } else 
				 break;

			f = STAILQ_FIRST(dualpi2_flowlist);
		}
		
		/* the new flows list is empty, try old flows list */
		if (STAILQ_EMPTY(dualpi2_flowlist)) 
			continue;

		/* Dequeue a packet from the selected flow */
		mbuf = pie_dequeue(f, si);

		/* pie did not return a packet */
		if (!mbuf) {
			/* If the selected flow belongs to new flows list, then move 
			 * it to the tail of old flows list. Otherwise, deactivate it and
			 * remove it from the old list and
			 */
			if (dualpi2_flowlist == &si->newflows) {
				STAILQ_REMOVE_HEAD(dualpi2_flowlist, flowchain);
				STAILQ_INSERT_TAIL(&si->oldflows, f, flowchain);
			}	else {
				f->active = 0;
				fq_deactivate_pie(&f->pst);
				STAILQ_REMOVE_HEAD(dualpi2_flowlist, flowchain);
			}
			/* start again */
			continue;
		}

		/* we have a packet to return, 
		 * update flow deficit and return the packet*/
		f->deficit -= mbuf->m_pkthdr.len;
		return mbuf;

	} while (1);

	/* unreachable point */
	return NULL;
}

/*
 * Initialize dualpi2 scheduler instance.
 * also, allocate memory for flows array.
 */
static int
dualpi2_new_sched(struct dn_sch_inst *_si)
{
	struct dualpi2_si *si;
	struct dn_queue *q;
	struct dualpi2_schk *schk;
	struct dualpi2_flow *flows;
	int i;

	si = (struct dualpi2_si *)_si;
	schk = (struct dualpi2_schk *)(_si->sched+1);

	if(si->si_extra) {
		D("si already configured!");
		return 0;
	}

	/* init the main queue */
	q = &si->main_q;
	set_oid(&q->ni.oid, DN_QUEUE, sizeof(*q));
	q->_si = _si;
	q->fs = _si->sched->fs;

	/* allocate memory for scheduler instance extra vars */
	si->si_extra = malloc(sizeof(struct dualpi2_si_extra),
		 M_DUMMYNET, M_NOWAIT | M_ZERO);
	if (si->si_extra == NULL) {
		D("cannot allocate memory for dualpi2 si extra vars");
		return ENOMEM ; 
	}
	/* allocate memory for flows array */
	si->si_extra->flows = mallocarray(schk->cfg.flows_cnt,
	    sizeof(struct dualpi2_flow), M_DUMMYNET, M_NOWAIT | M_ZERO);
	flows = si->si_extra->flows;
	if (flows == NULL) {
		free(si->si_extra, M_DUMMYNET);
		si->si_extra = NULL;
		D("cannot allocate memory for dualpi2 flows");
		return ENOMEM ; 
	}

	/* init perturbation for this si */
	si->perturbation = random();
	si->si_extra->nr_active_q = 0;

	/* init the old and new flows lists */
	STAILQ_INIT(&si->newflows);
	STAILQ_INIT(&si->oldflows);

	/* init the flows (sub-queues) */
	for (i = 0; i < schk->cfg.flows_cnt; i++) {
		flows[i].pst.parms = &schk->cfg.pcfg;
		flows[i].psi_extra = si->si_extra;
		pie_init(&flows[i], schk);
		// Set queue_type based on the index
		
    	flows[i].queue_type = i; // i will be 0 for the first queue, 1 for the second queue
		// printf("dualpi2_new_sched: i:%d ----- queue_type:%u \n",i,flows[i].queue_type);
		flows[i].l_base_drop_prob = 0;
		flows[i].c_base_drop_prob = 0;
		flows[i].wc = 1;
		flows[i].wl = 2;
	}

	dummynet_sched_lock();
	dualpi2_desc.ref_count++;
	dummynet_sched_unlock();

	return 0;
}

/*
 * Free dualpi2 scheduler instance.
 */
static int
dualpi2_free_sched(struct dn_sch_inst *_si)
{
	struct dualpi2_si *si;
	struct dualpi2_schk *schk;
	struct dualpi2_flow *flows;
	int i;

	si = (struct dualpi2_si *)_si;
	schk = (struct dualpi2_schk *)(_si->sched+1);
	flows = si->si_extra->flows;
	for (i = 0; i < schk->cfg.flows_cnt; i++) {
		pie_cleanup(&flows[i]);
	}
	si->si_extra = NULL;
	return 0;
}

/*
 * Configure DUALPI2 scheduler.
 * the configurations for the scheduler is passed fromipfw  userland.
 */
static int
dualpi2_config(struct dn_schk *_schk)
{
	struct dualpi2_schk *schk;
	struct dn_extra_parms *ep;
	struct dn_sch_dualpi2_parms *fqp_cfg;

	schk = (struct dualpi2_schk *)(_schk+1);
	ep = (struct dn_extra_parms *) _schk->cfg;

	/* par array contains dualpi2 configuration as follow
	 * PIE: 0- qdelay_ref,1- tupdate, 2- max_burst
	 * 3- max_ecnth, 4- alpha, 5- beta, 6- flags
	 * DUALPI2: 7- quantum, 8- limit, 9- flows
	 */
	if (ep && ep->oid.len ==sizeof(*ep) &&
		ep->oid.subtype == DN_SCH_PARAMS) {
		fqp_cfg = &schk->cfg;
		if (ep->par[0] < 0)
			fqp_cfg->pcfg.qdelay_ref = dualpi2_sysctl.pcfg.qdelay_ref;
		else
			fqp_cfg->pcfg.qdelay_ref = ep->par[0];
		if (ep->par[1] < 0)
			fqp_cfg->pcfg.tupdate = dualpi2_sysctl.pcfg.tupdate;
		else
			fqp_cfg->pcfg.tupdate = ep->par[1];
		if (ep->par[2] < 0)
			fqp_cfg->pcfg.max_burst = dualpi2_sysctl.pcfg.max_burst;
		else
			fqp_cfg->pcfg.max_burst = ep->par[2];
		if (ep->par[3] < 0)
			fqp_cfg->pcfg.max_ecnth = dualpi2_sysctl.pcfg.max_ecnth;
		else
			fqp_cfg->pcfg.max_ecnth = ep->par[3];
		if (ep->par[4] < 0)
			fqp_cfg->pcfg.alpha = dualpi2_sysctl.pcfg.alpha;
		else
			fqp_cfg->pcfg.alpha = ep->par[4];
		if (ep->par[5] < 0)
			fqp_cfg->pcfg.beta = dualpi2_sysctl.pcfg.beta;
		else
			fqp_cfg->pcfg.beta = ep->par[5];
		if (ep->par[6] < 0)
			fqp_cfg->pcfg.flags = 0;
		else
			fqp_cfg->pcfg.flags = ep->par[6];

		/* FQ configurations */
		if (ep->par[7] < 0)
			fqp_cfg->quantum = dualpi2_sysctl.quantum;
		else
			fqp_cfg->quantum = ep->par[7];
		if (ep->par[8] < 0)
			fqp_cfg->limit = dualpi2_sysctl.limit;
		else
			fqp_cfg->limit = ep->par[8];
		if (1)
			fqp_cfg->flows_cnt = dualpi2_sysctl.flows_cnt;
		else
			fqp_cfg->flows_cnt = ep->par[9];

		/* Bound the configurations */
		fqp_cfg->pcfg.qdelay_ref = BOUND_VAR(fqp_cfg->pcfg.qdelay_ref,
			1, 5 * AQM_TIME_1S);
		fqp_cfg->pcfg.tupdate = BOUND_VAR(fqp_cfg->pcfg.tupdate,
			1, 5 * AQM_TIME_1S);
		fqp_cfg->pcfg.max_burst = BOUND_VAR(fqp_cfg->pcfg.max_burst,
			0, 5 * AQM_TIME_1S);
		fqp_cfg->pcfg.max_ecnth = BOUND_VAR(fqp_cfg->pcfg.max_ecnth,
			0, PIE_SCALE);
		fqp_cfg->pcfg.alpha = BOUND_VAR(fqp_cfg->pcfg.alpha, 0, 7 * PIE_SCALE);
		fqp_cfg->pcfg.beta = BOUND_VAR(fqp_cfg->pcfg.beta, 0, 7 * PIE_SCALE);

		fqp_cfg->quantum = BOUND_VAR(fqp_cfg->quantum,1,9000);
		fqp_cfg->limit= BOUND_VAR(fqp_cfg->limit,1,20480);
		fqp_cfg->flows_cnt= BOUND_VAR(fqp_cfg->flows_cnt,1,65536);
	}
	else {
		D("Wrong parameters for dualpi2 scheduler");
		return 1;
	}

	return 0;
}

/*
 * Return DUALPI2 scheduler configurations
 * the configurations for the scheduler is passed to userland.
 */
static int 
dualpi2_getconfig (struct dn_schk *_schk, struct dn_extra_parms *ep) {
	struct dualpi2_schk *schk = (struct dualpi2_schk *)(_schk+1);
	struct dn_sch_dualpi2_parms *fqp_cfg;

	fqp_cfg = &schk->cfg;

	strcpy(ep->name, dualpi2_desc.name);
	ep->par[0] = fqp_cfg->pcfg.qdelay_ref;
	ep->par[1] = fqp_cfg->pcfg.tupdate;
	ep->par[2] = fqp_cfg->pcfg.max_burst;
	ep->par[3] = fqp_cfg->pcfg.max_ecnth;
	ep->par[4] = fqp_cfg->pcfg.alpha;
	ep->par[5] = fqp_cfg->pcfg.beta;
	ep->par[6] = fqp_cfg->pcfg.flags;

	ep->par[7] = fqp_cfg->quantum;
	ep->par[8] = fqp_cfg->limit;
	ep->par[9] = fqp_cfg->flows_cnt;

	return 0;
}

/*
 *  DUALPI2 scheduler descriptor
 * contains the type of the scheduler, the name, the size of extra
 * data structures, and function pointers.
 */
static struct dn_alg dualpi2_desc = {
	_SI( .type = )  DN_SCHED_DUALPI2,
	_SI( .name = ) "DUALPI2",
	_SI( .flags = ) 0,

	_SI( .schk_datalen = ) sizeof(struct dualpi2_schk),
	_SI( .si_datalen = ) sizeof(struct dualpi2_si) - sizeof(struct dn_sch_inst),
	_SI( .q_datalen = ) 0,

	_SI( .enqueue = ) dualpi2_enqueue,
	_SI( .dequeue = ) dualpi2_dequeue,
	_SI( .config = ) dualpi2_config, /* new sched i.e. sched X config ...*/
	_SI( .destroy = ) NULL,  /*sched x delete */
	_SI( .new_sched = ) dualpi2_new_sched, /* new schd instance */
	_SI( .free_sched = ) dualpi2_free_sched,	/* delete schd instance */
	_SI( .new_fsk = ) NULL,
	_SI( .free_fsk = ) NULL,
	_SI( .new_queue = ) NULL,
	_SI( .free_queue = ) NULL,
	_SI( .getconfig = )  dualpi2_getconfig,
	_SI( .ref_count = ) 0
};

DECLARE_DNSCHED_MODULE(dn_dualpi2, &dualpi2_desc);