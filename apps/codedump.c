#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/const.h>
#include <fcntl.h>

#include <libtlp.h>

#include "util.h"

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
		x = y + phys_base;
		//return 0;

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


/* task_struct offset */
#define OFFSET_HEAD_STATE	16
#define OFFSET_HEAD_MM          2040
#define OFFSET_HEAD_PID		2216
#define OFFSET_HEAD_CHILDREN	2240
#define OFFSET_HEAD_SIBLING	2256
#define OFFSET_HEAD_COMM	2632
#define OFFSET_HEAD_REAL_PARENT	2224

#define TASK_COMM_LEN		16

/* mm_struct offset */
#define OFFSET_MM_HEAD_PGD	80
#define OFFSET_MM_START_CODE	248
#define OFFSET_MM_END_CODE	256

struct task_struct {
	uintptr_t	vhead, phead;
	uintptr_t       vmm, pmm;
	uintptr_t	vstate, pstate;
	uintptr_t	vpid, ppid;
	uintptr_t	vchildren, pchildren;
	uintptr_t	vsibling, psibling;
	uintptr_t	vcomm, pcomm;
	uintptr_t	vreal_parent, preal_parent;

	struct list_head children;
	struct list_head sibling;

	uintptr_t	children_next;
	uintptr_t	children_prev;
	uintptr_t	sibling_next;
	uintptr_t	sibling_prev;

	uintptr_t	real_parent;

        int             pid;
        uintptr_t       pgd;
	uintptr_t	start_code, end_code;
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
	print_task_value(t, real_parent);

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
	t->vreal_parent = vhead + OFFSET_HEAD_REAL_PARENT;
	t->preal_parent = __phys_addr(t->vreal_parent);
	t->vcomm = vhead + OFFSET_HEAD_COMM;
	t->pcomm = __phys_addr(t->vcomm);

	ret = dma_read(nt, t->pchildren, &t->children, sizeof(t->children));
	if (ret < sizeof(t->children))
		return -1;

	ret = dma_read(nt, t->psibling, &t->sibling, sizeof(t->children));
	if (ret < sizeof(t->sibling))
		return -1;

	ret = dma_read(nt, t->preal_parent, &t->real_parent,
		       sizeof(t->real_parent));
	if (ret < sizeof(t->real_parent))
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

	/* get start_code and end_code */
	ret = dma_read(nt, pmm + OFFSET_MM_START_CODE, &t->start_code,
		       sizeof(t->start_code));
	if (ret < 0) {
		fprintf(stderr,
			"failed to dma_read start_code from %#lx\n",
			pmm + OFFSET_MM_START_CODE);
		return -1;
	}

	ret = dma_read(nt, pmm + OFFSET_MM_END_CODE, &t->end_code,
		       sizeof(t->end_code));
	if (ret < 0) {
		fprintf(stderr,
			"failed to dma_read end_code from %#lx\n",
			pmm + OFFSET_MM_END_CODE);
		return -1;
	}

	return 0;
}


struct task_struct* find_task(struct nettlp *nt, int pid,
			     uintptr_t vhead, uintptr_t parent)
{
	/* find task for the pid.
	 * vhead is kernel virtual address of task_struct.
	 * parent is the vaddr of the parent's task_struct.
	 */

	int ret;
	struct task_struct *t;

	t = malloc(sizeof(*t));
	memset(t, 0, sizeof(*t));
	
	ret = fill_task_struct(nt, vhead, t);
	if (ret < 0) {
		fprintf(stderr, "failed to fill task_struct from %#lx\n",
			vhead);
		goto err_out;
	}

	if (t->pid == pid) {
		/* found the task! */
		return t;
	}

	if (t->children_next != t->vchildren) {
		/* this task_struct has children. walk them */
		return find_task(nt, pid,
				 t->children_next - OFFSET_HEAD_SIBLING,
				 t->vhead);
	}
	
	if (t->sibling_next - OFFSET_HEAD_SIBLING == parent ||
	    t->sibling_next - OFFSET_HEAD_CHILDREN == parent) {
		/* walk done of the siblings spawned from the parent */
		return NULL;
	}

	/* goto the next sibling */
	return find_task(nt, pid, t->sibling_next - OFFSET_HEAD_SIBLING,
			 parent);

err_out:
	free(t);
	return NULL;
}

uintptr_t find_init_task_from_systemmap(char *map)
{
	FILE *fp;
	char buf[4096];
	uintptr_t addr = 0;

	fp = fopen(map, "r");
	if (!fp) {
		perror("fopen");
		return 0;
	}

	while(fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "D init_task")) {
			char *p;
			p = strchr(buf, ' ');
			*p = '\0';
			addr = strtoul(buf, NULL, 16);
		}
	}

	fclose(fp);

	return addr;
}

uintptr_t pgd_walk(struct nettlp *nt, uintptr_t pgd, uintptr_t vaddr)
{
	/*
	 * pgd is CR3 value of the target process
	 * vaddr is a virtual address of PROCESS to be converted to physical
	 */

        int ret;
        uintptr_t ptr, ptr_next, paddr;
        uint16_t pm, dp, pd, pt, off;

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

        /* read Page Directory Pointer from PML4 */
        ret = dma_read(nt, __phys_addr(pgd) + (pm << 3),
                       &ptr_next, sizeof(ptr_next));
        if (ret < sizeof(ptr_next)) {
                fprintf(stderr, "failed to read page dir ptr from %#lx\n",
                        __phys_addr(pgd) + (pm << 3));
                return 0;
        }
        ptr = ptr_next;

#define target_ptr(ptr, offset) \
        ((ptr & 0x000FFFFFFFFFF000) + (offset << 3))

        /* read Page Directory from Page Directory Pointer */
        ret = dma_read(nt, target_ptr(ptr, dp), &ptr_next, sizeof(ptr_next));
        if (ret < sizeof(ptr)) {
                fprintf(stderr, "failed to read page directory from %#lx\n",
                        target_ptr(ptr, dp));
                return 0;
        }
        ptr = ptr_next;


        /* read page table from page directory */
        ret = dma_read(nt, target_ptr(ptr, pd), &ptr_next, sizeof(ptr_next));
        if (ret < sizeof(ptr)) {
                fprintf(stderr, "failed to read page directory from %#lx\n",
                        target_ptr(ptr, pd));
                return 0;
        }
        ptr = ptr_next;


        /* read page entry from page table */
        ret = dma_read(nt, target_ptr(ptr, pt), &ptr_next, sizeof(ptr_next));
        if (ret < sizeof(ptr)) {
                fprintf(stderr, "failed to read page directory from %#lx\n",
                        target_ptr(ptr, pt));
                return 0;
        }
        ptr = ptr_next;

        /* ok, finaly we found the physical address  */
        paddr = ((ptr & 0x000FFFFFFFFFF000) | off);
	return paddr;
}
	

void usage(void)
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -b bus number, XX:XX\n"
	       "    -t tag\n"
	       "\n"
	       "    -s Systemmap file\n"
	       "    -p pid\n"
	       "    -o output file\n"
	);
}


int main(int argc, char **argv)
{
	int ret, ch;
	struct nettlp nt;
	uintptr_t addr;
	uint16_t busn, devn;
	struct task_struct t, *target;
	char *map;
	int pid;
	char *output;

	memset(&nt, 0, sizeof(nt));
	addr = 0;
	busn = 0;
	devn = 0;
	map = NULL;
	pid = -1;	/* never match */
	output = NULL;

	while ((ch = getopt(argc, argv, "r:l:b:t:s:p:o:")) != -1) {
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

		case 's':
			map = optarg;
			break;

		case 'p':
			pid = atoi(optarg);
			break;

		case 'o':
			output = optarg;
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

	addr = find_init_task_from_systemmap(map);
	if (addr == 0) {
		fprintf(stderr,
			"init_task not found on System.map file '%s'\n", map);
		return -1;
	}
	fill_task_struct(&nt, addr, &t);

	target = find_task(&nt, pid, t.vhead, t.vhead);
	if (!target) {
		fprintf(stderr, "pid %d not found\n", pid);
		return -1;
	}
	

	/* ok, lets dump code area from task_struct */
#define CODE_SIZE (4096 * 16)
#define MRS 512

	int f;
	char buf[CODE_SIZE];
	uintptr_t pstart_code, pend_code;
	size_t read_len, code_len, done;

	pstart_code = pgd_walk(&nt, target->pgd, target->start_code);
	if (pstart_code == 0) {
		fprintf(stderr, "start_code read failed\n");
		return -1;
	}

	pend_code = pgd_walk(&nt, target->pgd, target->end_code);
	if (pend_code == 0) {
		fprintf(stderr, "end_code read failed\n");
		return -1;
	}

	printf("start_code paddr is %#lx, end_code paddr is %#lx\n",
	       pstart_code, pend_code);

	done = 0;
	code_len = pend_code - pstart_code;
	memset(buf, 0, sizeof(buf));
	
	do {
		read_len = code_len - done < MRS ? code_len - done : MRS;
		ret = dma_read(&nt, pstart_code + done, buf + done, read_len);
		if (ret < 0) {
			fprintf(stderr, "failed to read code area from %#lx\n",
				pstart_code + done);
			return -1;
		}
			
		done += ret;

	} while (done < code_len);


	printf("dump complete\n");

	if (output) {
		printf("write the binary to %s\n", output);
		f = open(output, O_CREAT|O_RDWR,
			 S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
		ret = write(f, buf, code_len);
		if (ret < 0) {
			perror("write");
			return -1;
		}
	} else {
		hexdump(buf, code_len);
	}

	return 0;
}
