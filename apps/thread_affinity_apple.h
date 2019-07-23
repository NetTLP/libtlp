
/* thread_affinity_apple.h
 *
 * macOS does not have cpu_set, pthread_setaffinity_np and related
 * APIs. This header file provdies the API on the macOS way.
 *
 * this header file is based on Binding Threads to Cores on OSX:
 * https://yyshen.github.io/2015/01/18/binding_threads_to_cores_osx.html
 */


#define SYSCTL_CORE_COUNT   "machdep.cpu.core_count"


typedef struct cpu_set {
	uint32_t    count;
} cpu_set_t;

static inline void CPU_ZERO(cpu_set_t *cs)
{
	cs->count = 0; 
}

static inline void CPU_SET(int num, cpu_set_t *cs)
{
	cs->count |= (1 << num); 
}

static inline int CPU_ISSET(int num, cpu_set_t *cs)
{
	return (cs->count & (1 << num));
}

static inline int CPU_COUNT(cpu_set_t *cs)
{
	int n, core_count = 0;
	uint32_t mask = 1;

	for (n = 0; n < 32; n++) {
		if (cs->count & (mask << n))
			core_count++;
	}

	return core_count;
}

int sched_getaffinity(pid_t pid, size_t cpu_size, cpu_set_t *cpu_set)
{
	int32_t core_count = 0;
	size_t  len = sizeof(core_count);
	int ret = sysctlbyname(SYSCTL_CORE_COUNT, &core_count, &len, 0, 0);

	if (ret) {
		printf("error while get core count %d\n", ret);
		return -1;
	}

	cpu_set->count = 0;
	for (int i = 0; i < core_count; i++) {
		cpu_set->count |= (1 << i);
	}

	return 0;
}

int pthread_setaffinity_np(pthread_t thread, size_t cpu_size,
                           cpu_set_t *cpu_set)
{
	thread_port_t mach_thread;
	int core = 0;

	for (core = 0; core < 8 * cpu_size; core++) {
		if (CPU_ISSET(core, cpu_set)) break;
	}

	thread_affinity_policy_data_t policy = { core };
	mach_thread = pthread_mach_thread_np(thread);
	thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
			  (thread_policy_t)&policy, 1);
	return 0;
}

