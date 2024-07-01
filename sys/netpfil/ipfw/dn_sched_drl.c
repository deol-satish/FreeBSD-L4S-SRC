#include <sys/param.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>

#include <sys/types.h>
#include <sys/systm.h>

#include <sys/malloc.h>

static uint drl_prob = 0;

static MALLOC_DEFINE(M_DQN, "DQN scheduler data", "Per connection DQN scheduler data.");


struct pkt {
	u_int		cwnd;
	int		smoothed_rtt;
	int		cong_events;

	u_int		laddr;
	u_int		lport;
};

int drl_get_buffer(struct thread *td, struct aqm_get_buffer_args *uap)
{
    struct pkt *pb = NULL;
    int size = 2;


    // Allocate memory for the struct
    pb = malloc(sizeof(struct pkt) * size, M_DQN, M_NOWAIT|M_ZERO);


    copyout(pb, uap->data, sizeof(struct pkt) * size);
	copyout(&size, uap->size, sizeof(int));

    printf("System call  %d\n", pb->cwnd);
    printf("System call  %d\n", pb->smoothed_rtt);
    printf("System call  %d\n", pb->cong_events);
    printf("System call  %d\n", pb->laddr);
    printf("System call  %d\n", pb->lport);

    free(pb, M_DQN);

	return (0);
}

static int drl_update_prob(uint prob) {
    drl_prob = prob;
    return 0; // success
}
