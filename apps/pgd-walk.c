#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifdef __APPLE__
#define _AC(X,Y)        X
#else
#include <linux/const.h>
#endif

#include <libtlp.h>


/* from arch_x86/include/asm/page_64_types.h */
#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)
//#define __PAGE_OFFSET_BASE      _AC(0xffff880000000000, UL)
#define __PAGE_OFFSET_BASE      _AC(0xffff888000000000, UL)
#define __PAGE_OFFSET           __PAGE_OFFSET_BASE
#define __START_KERNEL_map      _AC(0xffffffff80000000, UL)



/* from arch/x86/include/asm/page_types.h */
#define PAGE_OFFSET	((unsigned long)__PAGE_OFFSET)

#define phys_base	0x1000000	/* x86 */

/* from arch/x86/mm/physaddr.c */
unsigned long __phys_addr(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	if (x > y) {
		return 0;
		//x = y + phys_base;

		//if (y >= KERNEL_IMAGE_SIZE)
		//return 0;
	} else {
		x = y + (__START_KERNEL_map - PAGE_OFFSET);

		/* carry flag will be set if starting x was >= PAGE_OFFSET */
		//VIRTUAL_BUG_ON((x > y) || !phys_addr_valid(x));
	}

	return x;
}



/* from include/linux/sched.h*/
/* Used in tsk->state: */
#define TASK_RUNNING                    0x0000
#define TASK_INTERRUPTIBLE              0x0001
#define TASK_UNINTERRUPTIBLE            0x0002
#define __TASK_STOPPED                  0x0004
#define __TASK_TRACED                   0x0008
/* Used in tsk->exit_state: */
#define EXIT_DEAD                       0x0010
#define EXIT_ZOMBIE                     0x0020
#define EXIT_TRACE                      (EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->state again: */
#define TASK_PARKED                     0x0040
#define TASK_DEAD                       0x0080
#define TASK_WAKEKILL                   0x0100
#define TASK_WAKING                     0x0200
#define TASK_NOLOAD                     0x0400
#define TASK_NEW                        0x0800
#define TASK_STATE_MAX                  0x1000

char state_to_char(long state)
{
	switch(state &0x00FF) {
	case TASK_RUNNING:
		return 'R';
	case TASK_INTERRUPTIBLE:
		return 'S';
	case TASK_UNINTERRUPTIBLE:
		return 'D';
	case __TASK_STOPPED:
	case __TASK_TRACED:
		return 'T';
	case TASK_DEAD:
		return 'X';
	default:
		return 'u';
	}
}


struct list_head {
	struct list_head *next, *prev;
};


/* task struct offset */
#define OFFSET_HEAD_STATE	16
#define OFFSET_HEAD_MM		2040
#define OFFSET_HEAD_PID		2216
#define OFFSET_HEAD_CHILDREN	2240
#define OFFSET_HEAD_SIBLING	2256
#define OFFSET_HEAD_COMM	2632

#define OFFSET_MM_HEAD_PGD	80


#define TASK_COMM_LEN		16

struct task_struct {
	uintptr_t	vhead, phead;
	uintptr_t	vmm, pmm;
	uintptr_t	vstate, pstate;
	uintptr_t	vpid, ppid;
	uintptr_t	vchildren, pchildren;
	uintptr_t	vsibling, psibling;
	uintptr_t	vcomm, pcomm;

	struct list_head children;
	struct list_head sibling;

	uintptr_t	children_next;
	uintptr_t	children_prev;
	uintptr_t	sibling_next;
	uintptr_t	sibling_prev;

	int		pid;
	uintptr_t	pgd;
};

#define print_task_value(t, name) \
	printf(#name "  %#lx %#lx\n", t->v##name, t->p##name)

void dump_task_struct(struct task_struct *t)
{
	print_task_value(t, head);
	print_task_value(t, state);
	print_task_value(t, pid);
	print_task_value(t, children);
	print_task_value(t, sibling);
	print_task_value(t, comm);

	printf("children_next %#lx %#lx\n",
	       t->children_next, __phys_addr(t->children_next));
	printf("children_prev %#lx %#lx\n",
	       t->children_prev, __phys_addr(t->children_prev));
	printf("sibling_next %#lx %#lx\n",
	       t->sibling_next, __phys_addr(t->sibling_next));
	printf("sibling_prev %#lx %#lx\n",
	       t->sibling_prev, __phys_addr(t->sibling_prev));
}

#define check_task_value(t, name)					\
	do {								\
		if(t->v##name == 0) {					\
			fprintf(stderr,					\
				"failed to get address of v" #name	\
				" %#lx\n", t->v##name);			\
			return -1;					\
		}							\
		if(t->p##name == 0) {					\
			fprintf(stderr,					\
				"failed to get physical address for p"	\
				#name					\
				" from %#lx\n", t->v##name);		\
			return -1;					\
		}							\
	} while(0)							\


int fill_task_struct(struct nettlp *nt, uintptr_t vhead,
		     struct task_struct *t)
{
	int ret;
	uintptr_t vmm, pmm;

	t->vhead = vhead;
	t->phead = __phys_addr(t->vhead);
	t->vstate = vhead + OFFSET_HEAD_STATE;
	t->pstate = __phys_addr(t->vstate);
	t->vmm = vhead + OFFSET_HEAD_MM;
	t->pmm = __phys_addr(t->vmm);
	t->vpid = vhead + OFFSET_HEAD_PID;
	t->ppid = __phys_addr(t->vpid);
	t->vchildren = vhead + OFFSET_HEAD_CHILDREN;
	t->pchildren = __phys_addr(t->vchildren);
	t->vsibling = vhead + OFFSET_HEAD_SIBLING;
	t->psibling = __phys_addr(t->vsibling);
	t->vcomm = vhead + OFFSET_HEAD_COMM;
	t->pcomm = __phys_addr(t->vcomm);

	ret = dma_read(nt, t->pchildren, &t->children, sizeof(t->children));
	if (ret < sizeof(t->children))
		return -1;

	ret = dma_read(nt, t->psibling, &t->sibling, sizeof(t->children));
	if (ret < sizeof(t->sibling))
		return -1;

	t->children_next = (uintptr_t)t->children.next;
	t->children_prev = (uintptr_t)t->children.prev;
	t->sibling_next = (uintptr_t)t->sibling.next;
	t->sibling_prev = (uintptr_t)t->sibling.prev;

	check_task_value(t, head);
	check_task_value(t, pid);
	check_task_value(t, children);
	check_task_value(t, sibling);
	check_task_value(t, comm);

	/* get pid from task_struct */
	ret = dma_read(nt, t->ppid, &t->pid, sizeof(t->pid));
	if (ret < sizeof(t->pid)) {
		fprintf(stderr, "failed to read pid from %#lx\n", t->ppid);
		return -1;
	}


	/* get pgd from mm_struct 
	 * vmm is virtual address of mm_struct, and pmm is the phsical addr of
	 * the mm_struct
	 */
	ret = dma_read(nt, t->pmm, &vmm, sizeof(vmm));
	if (ret < sizeof(vmm))
		return -1;

	if (vmm == 0) {
		/* no memory space task */
		t->pgd = 0;
		return 0;
	}

	pmm = __phys_addr(vmm);
	if (pmm == 0) {
		fprintf(stderr, "failed to convirt vmm %#lx to pmm\n", vmm);
		return -1;
	}
	
	ret = dma_read(nt, pmm + OFFSET_MM_HEAD_PGD, &t->pgd,
		       sizeof(t->pgd));
	if (ret < 0) {
		fprintf(stderr,
			"failed to dma_read pgd from %#lx, "
			"vmm is %#lx, pmm is %#lx\n",
			pmm + OFFSET_MM_HEAD_PGD, vmm, pmm);
		return -1;
	}


	return 0;
}


void print_process_vaddr(struct nettlp *nt, uintptr_t vaddr, uintptr_t pgd)
{
	int ret;
	uintptr_t ptr, ptr_next, paddr;
	uint16_t pm, dp, pd, pt, off;
	char buf[64];

	memset(buf, 0, sizeof(buf));
	
	pm = 0;
	dp = 0;
	pd = 0;
	pt = 0;
	off = 0;

	off = (vaddr & 0x0FFF);
	pt = (vaddr >> 12) & 0x01FF;
	pd = (vaddr >> (9 + 12)) & 0x01FF;
	dp = (vaddr >> (9 + 9 + 12)) & 0x01FF;
	pm = (vaddr >> (9 + 9 + 9 + 12)) & 0x01FF;

	printf("pm %u, dp %u, pd %u, pt %u, off %u\n", pm, dp, pd, pt, off);
	printf("pm %x, dp %x, pd %x, pt %x, off %x\n", pm, dp, pd, pt, off);

	printf("pgd %#lx\n", pgd);
	printf("phy addr pgd is %#lx\n", __phys_addr(pgd));
	printf("phy addr pgd read is is %#lx\n", __phys_addr(pgd) + pm);

	/* read Page Directory Pointer from PML4 */
	ret = dma_read(nt, __phys_addr(pgd) + (pm << 3),
		       &ptr_next, sizeof(ptr_next));
	if (ret < sizeof(ptr_next)) {
		fprintf(stderr, "failed to read page dir ptr from %#lx\n",
			__phys_addr(pgd) + (pm << 3));
		return;
	}
	ptr = ptr_next;
	printf("pdp %#lx\n", ptr);

#define target_ptr(ptr, offset) \
	((ptr & 0x000FFFFFFFFFF000) + (offset << 3))

	/* read Page Directory from Page Directory Pointer */
	ret = dma_read(nt, target_ptr(ptr, dp), &ptr_next, sizeof(ptr_next));
	if (ret < sizeof(ptr)) {
		fprintf(stderr, "failed to read page directory from %#lx\n",
			target_ptr(ptr, dp));
		return;
	}
	ptr = ptr_next;
	printf("pd %#lx\n", ptr);
	
	/* read page table from page directory */
	ret = dma_read(nt, target_ptr(ptr, pd), &ptr_next, sizeof(ptr_next));
	if (ret < sizeof(ptr)) {
		fprintf(stderr, "failed to read page directory from %#lx\n",
			target_ptr(ptr, pd));
		return;
	}
	ptr = ptr_next;
	printf("page table %#lx\n", ptr);

	/* read page entry from page table */
	ret = dma_read(nt, target_ptr(ptr, pt), &ptr_next, sizeof(ptr_next));
	if (ret < sizeof(ptr)) {
		fprintf(stderr, "failed to read page directory from %#lx\n",
			target_ptr(ptr, pt));
		return;
	}
	ptr = ptr_next;
	printf("page entry %#lx\n", ptr);

	/* ok, now ptr is actually the page entry */
	paddr = ((ptr & 0x000FFFFFFFFFF000) | off);
	ret = dma_read(nt, paddr, buf, sizeof(buf));
	if (ret < sizeof(buf)) {
		fprintf(stderr, "failed to read %ld-byte from %#lx\n",
			sizeof(buf), paddr | off);
	}

	buf[sizeof(buf) - 1] = '\0';
	printf("vaddr %#lx is paddr %#lx, dumped: %s\n",
	       vaddr, paddr, buf);

	return;
}



void print_task_struct(struct nettlp *nt, struct task_struct t)
{
	int ret;
	long state;
	char comm[TASK_COMM_LEN];

	ret = dma_read(nt, t.pstate, &state, sizeof(state));
	if (ret < sizeof(state)) {
		fprintf(stderr, "failed to read state from %#lx\n", t.pstate);
		return;
	}

	ret = dma_read(nt, t.pcomm, &comm, sizeof(comm));
	if (ret < sizeof(comm)) {
		fprintf(stderr, "failed to read comm from %#lx\n", t.pcomm);
		return;
	}

	comm[TASK_COMM_LEN - 1] = '\0';	/* preventing overflow */

	printf("%#lx %6d    %c 0x%04lx %s, pgd is %#lx\n",
	       t.phead, t.pid, state_to_char(state), state, comm, t.pgd);
}



int task(struct nettlp *nt, uintptr_t vhead, uintptr_t children, int pid,
	 uintptr_t vaddr)
{
	/*
	 * vhead is kernel virtual address of task_struct.
	 * children is the vaddr of the parent's struct list_head children.
	 */

	int ret;
	struct task_struct t;
	
	ret = fill_task_struct(nt, vhead, &t);
	if (ret < 0) {
		fprintf(stderr, "failed to fill task_struct from %#lx\n",
			vhead);
		return ret;
	}
	
	/* we are finding this process */
	if (pid == t.pid) {
		print_task_struct(nt, t);
		print_process_vaddr(nt, vaddr, t.pgd);
		return 0;
	}

	if (t.children_next != t.vchildren) {
		/* this task_struct has children. walk them  */
		ret = task(nt, t.children_next - OFFSET_HEAD_SIBLING,
			   t.vchildren, pid, vaddr);
		if (ret < 0)
			return ret;
	}
	
	if (children == t.sibling_next) {
		/* walk done of the siblings spawned from the parent */
		return 0;
	}

	/* goto the next sibling */
	return task(nt, t.sibling_next - OFFSET_HEAD_SIBLING, children, pid,
		vaddr);
}

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -b bus number, XX:XX\n"
	       "    -t tag\n"
	       "    -a virtual address of the first task_struct\n"
	       "    -p pid\n"
	       "    -v virtual address to be shown\n"
	);
}


int main(int argc, char **argv)
{
	int ret, ch, pid;
	struct nettlp nt;
	uintptr_t addr, vaddr;
	uint16_t busn, devn;
	struct task_struct t;

	memset(&nt, 0, sizeof(nt));
	addr = 0;
	busn = 0;
	devn = 0;
	pid = -1;	/* not mached */
	vaddr = 0;

	while ((ch = getopt(argc, argv, "r:l:b:t:a:p:v:")) != -1) {
		switch (ch) {
		case 'r':
			ret = inet_pton(AF_INET, optarg, &nt.remote_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'l':
			ret = inet_pton(AF_INET, optarg, &nt.local_addr);
			if (ret < 1) {
				perror("inet_pton");
				return -1;
			}
			break;

		case 'b':
			ret = sscanf(optarg, "%hx:%hx", &busn, &devn);
			nt.requester = (busn << 8 | devn);
			break;

		case 't':
			nt.tag = atoi(optarg);
			break;

		case 'a':
			ret = sscanf(optarg, "0x%lx", &addr);
			break;

		case 'p':
			pid = atoi(optarg);
			break;

		case 'v':
			ret = sscanf(optarg, "0x%lx", &vaddr);
			break;

		default :
			usage();
			return -1;
		}
	}


	ret = nettlp_init(&nt);
	if (ret < 0) {
		perror("nettlp_init");
		return ret;
	}

	fill_task_struct(&nt, addr, &t);

	task(&nt, t.vhead, t.vchildren, pid, vaddr);
	//print_task_struct(&nt, t);
	//dump_task_struct(&t);

	return 0;
}
