/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/* This is very much a work in progress IPC benchmarking set. Goal is
   to eventually use this to replace the rest of the random benchmarking
   happening in this app with just what we need */

#include <autoconf.h>
#include <sel4benchipc/gen_config.h>
#include <allocman/vka.h>
#include <allocman/bootstrap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <sel4bench/sel4bench.h>
#include <sel4utils/process.h>
#include <string.h>
#include <utils/util.h>
#include <vka/vka.h>
#include <sel4runtime.h>
#include <muslcsys/vsyscall.h>
#include <utils/attribute.h>

#include <benchmark.h>
#include <ipc.h>

#include <sel4bench/kernel_logging.h>

/* arch/ipc.h requires these defines */
#define NOPS ""

#include <arch/ipc.h>

#define NUM_ARGS 3
/* Ensure that enough warmups are performed to prevent the FPU from
 * being restored. */
#define WARMUPS (1)
// #ifdef CONFIG_FPU_MAX_RESTORES_SINCE_SWITCH
// #define WARMUPS (RUNS + CONFIG_FPU_MAX_RESTORES_SINCE_SWITCH)
// #else
// #define WARMUPS RUNS
// #endif
#define OVERHEAD_RETRIES 4

#ifndef CONFIG_CYCLE_COUNT

#define GENERIC_COUNTER_MASK (BIT(0))
#undef READ_COUNTER_BEFORE
#undef READ_COUNTER_AFTER
#define READ_COUNTER_BEFORE(x) sel4bench_get_counters(GENERIC_COUNTER_MASK, &x);
#define READ_COUNTER_AFTER(x) sel4bench_get_counters(GENERIC_COUNTER_MASK, &x)
#endif

typedef struct helper_thread {
    sel4utils_process_t process;
    seL4_CPtr ep;
    seL4_CPtr result_ep;
    char *argv[NUM_ARGS];
    char argv_strings[NUM_ARGS][WORD_STRING_SIZE];
} helper_thread_t;

#define DCACHEPOLLUTION_SIZE 64000

#define L1_CACHE_LINE_SIZE BIT(CONFIG_L1_CACHE_LINE_SIZE_BITS)
#define POLLUTE_ARRARY_SIZE CONFIG_L1_DCACHE_SIZE / L1_CACHE_LINE_SIZE / sizeof(int)
#define POLLUTE_RUNS 5

// int array[DCACHEPOLLUTION_SIZE];
// int *ptrs[DCACHEPOLLUTION_SIZE];

int *array;
int **ptrs;
int started = 0;

void init_dcache_pollution(void)
{
    array = malloc(DCACHEPOLLUTION_SIZE * sizeof(int));
    ptrs = malloc(DCACHEPOLLUTION_SIZE * sizeof(int *));
}

void deinit_dcache_pollution(void)
{
    free(array);
    free(ptrs);
}

void abort(void)
{
    benchmark_finished(EXIT_FAILURE);
}

static void timing_init(void)
{
    sel4bench_init();
    // if (!started) {
    //     init_dcache_pollution();
    //     started = 1;
    // }
#ifdef CONFIG_GENERIC_COUNTER
    event_id_t event = GENERIC_EVENTS[CONFIG_GENERIC_COUNTER_ID];
    sel4bench_set_count_event(0, event);
    sel4bench_reset_counters();
    sel4bench_start_counters(GENERIC_COUNTER_MASK);
#endif
#ifdef CONFIG_PLATFORM_COUNTER
    sel4bench_set_count_event(0, CONFIG_PLATFORM_COUNTER_CONSTANT);
    sel4bench_reset_counters();
    sel4bench_start_counters(GENERIC_COUNTER_MASK);
#endif
}

void timing_destroy(void)
{
    // deinit_dcache_pollution();
#ifdef CONFIG_GENERIC_COUNTER
    sel4bench_stop_counters(GENERIC_COUNTER_MASK);
    sel4bench_destroy();
#endif
}

static inline void dummy_seL4_Send(seL4_CPtr ep, seL4_MessageInfo_t tag)
{
    (void)ep;
    (void)tag;
}

static inline void dummy_seL4_Call(seL4_CPtr ep, seL4_MessageInfo_t tag)
{
    (void)ep;
    (void)tag;
}

static inline void dummy_seL4_Reply(UNUSED seL4_CPtr reply, seL4_MessageInfo_t tag)
{
    (void)tag;
}

static inline void dummy_cache_func(void) {
}

void pollute_dcache(void)
{
    // for (int i = 0; i < DCACHEPOLLUTION_SIZE; i++)
    // {
    //     ptrs[i] = &array[i];
    // }

    // // shuffle the pointers
    // for (int i = 0; i < DCACHEPOLLUTION_SIZE; i++)
    // {
    //     int j = rand() % DCACHEPOLLUTION_SIZE;
    //     int *tmp = ptrs[i];
    //     ptrs[i] = ptrs[j];
    //     ptrs[j] = tmp;
    // }

    // // access the array through the shuffled pointers
    // for (int i = 0; i < DCACHEPOLLUTION_SIZE; i++)
    // {
    //     *ptrs[i] = i;
    // }

        ALIGN(L1_CACHE_LINE_SIZE)                                            
        volatile int pollute_array[POLLUTE_ARRARY_SIZE][L1_CACHE_LINE_SIZE];
        for (int i = 0; i < POLLUTE_RUNS; i++)                               
        {                                                                    
            for (int j = 0; j < L1_CACHE_LINE_SIZE; j++)                     
            {                                                                
                for (int k = 0; k < POLLUTE_ARRARY_SIZE; k++)                
                {                                                            
                    pollute_array[k][j]++;                                   
                }                                                            
            }                                                                
        }                                                                    
}
void pollute_icache(void)
{
    __asm__(".rept 64000\n\t"
            "nop\n\t"
            ".endr");
}

void real_cache_func(void)
{
    COMPILER_MEMORY_FENCE();
    seL4_BenchmarkFlushCaches();
    COMPILER_MEMORY_FENCE();
    pollute_dcache();
    pollute_icache();
    COMPILER_MEMORY_FENCE();
}

#ifdef CONFIG_CLEAN_L1_ICACHE
#define CACHE_FUNC() do {                           \
    seL4_BenchmarkFlushL1Caches(seL4_ARM_CacheI);   \
} while (0)

#elif CONFIG_CLEAN_L1_DCACHE
#define CACHE_FUNC() do {                           \
    seL4_BenchmarkFlushL1Caches(seL4_ARM_CacheD);   \
} while (0)

#elif CONFIG_CLEAN_L1_CACHE
#define CACHE_FUNC() do {                           \
    seL4_BenchmarkFlushL1Caches(seL4_ARM_CacheID);  \
} while (0)

#elif CONFIG_DIRTY_L1_DCACHE
// #define L1_CACHE_LINE_SIZE BIT(CONFIG_L1_CACHE_LINE_SIZE_BITS)
// #define POLLUTE_ARRARY_SIZE CONFIG_L1_DCACHE_SIZE/L1_CACHE_LINE_SIZE/sizeof(int)
// #define POLLUTE_RUNS 5
#define CACHE_FUNC real_cache_func

#else
#define CACHE_FUNC dummy_cache_func
#endif

seL4_Word ipc_call_func(int argc, char *argv[]);
seL4_Word ipc_call_func2(int argc, char *argv[]);
// seL4_Word ipc_call_10_func(int argc, char *argv[]);
// seL4_Word ipc_call_10_func2(int argc, char *argv[]);
seL4_Word ipc_replyrecv_func2(int argc, char *argv[]);
seL4_Word ipc_replyrecv_func(int argc, char *argv[]);
// seL4_Word ipc_replyrecv_10_func2(int argc, char *argv[]);
// seL4_Word ipc_replyrecv_10_func(int argc, char *argv[]);
// seL4_Word ipc_send_func(int argc, char *argv[]);
// seL4_Word ipc_recv_func(int argc, char *argv[]);

static helper_func_t bench_funcs[] = {
    ipc_call_func,
    ipc_call_func2,
    // ipc_call_10_func,
    // ipc_call_10_func2,
    ipc_replyrecv_func2,
    ipc_replyrecv_func,
    // ipc_replyrecv_10_func2,
    // ipc_replyrecv_10_func,
    // ipc_send_func,
    // ipc_recv_func
};

#define IPC_CALL_FUNC(name, bench_func, send_func, call_func, send_start_end, length, cache_func) \
    seL4_Word name(int argc, char *argv[]) { \
    uint32_t i; \
    ccnt_t start UNUSED, end UNUSED; \
    seL4_CPtr ep = atoi(argv[0]);\
    seL4_CPtr result_ep = atoi(argv[1]);\
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, length); \
    call_func(ep, tag); \
    COMPILER_MEMORY_FENCE(); \
    for (i = 0; i < WARMUPS; i++) { \
        cache_func(); \
        READ_COUNTER_BEFORE(start); \
        bench_func(ep, tag); \
        READ_COUNTER_AFTER(end); \
    } \
    COMPILER_MEMORY_FENCE(); \
    send_result(result_ep, send_start_end); \
    send_func(ep, tag); \
    api_wait(ep, NULL);/* block so we don't run off the stack */ \
    return 0; \
}

IPC_CALL_FUNC(ipc_call_func, DO_REAL_CALL, seL4_Send, dummy_seL4_Call, end, 0, dummy_cache_func)
IPC_CALL_FUNC(ipc_call_func2, DO_REAL_CALL, dummy_seL4_Send, seL4_Call, start, 0, CACHE_FUNC)
// IPC_CALL_FUNC(ipc_call_10_func, DO_REAL_CALL_10, seL4_Send, dummy_seL4_Call, end, 10, dummy_cache_func)
// IPC_CALL_FUNC(ipc_call_10_func2, DO_REAL_CALL_10, dummy_seL4_Send, seL4_Call, start, 10, CACHE_FUNC)

#define IPC_REPLY_RECV_FUNC(name, bench_func, reply_func, recv_func, send_start_end, length, cache_func) \
seL4_Word name(int argc, char *argv[]) { \
    uint32_t i; \
    ccnt_t start UNUSED, end UNUSED; \
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, length); \
    seL4_CPtr ep = atoi(argv[0]);\
    seL4_CPtr result_ep = atoi(argv[1]);\
    seL4_CPtr reply = atoi(argv[2]);\
    if (config_set(CONFIG_KERNEL_MCS)) {\
        api_nbsend_recv(ep, tag, ep, NULL, reply);\
    } else {\
        recv_func(ep, NULL, reply); \
    }\
    COMPILER_MEMORY_FENCE(); \
    for (i = 0; i < WARMUPS; i++) { \
        cache_func(); \
        READ_COUNTER_BEFORE(start); \
        bench_func(ep, tag, reply); \
        READ_COUNTER_AFTER(end); \
    } \
    COMPILER_MEMORY_FENCE(); \
    reply_func(reply, tag); \
    send_result(result_ep, send_start_end); \
    api_wait(ep, NULL); /* block so we don't run off the stack */ \
    return 0; \
}

IPC_REPLY_RECV_FUNC(ipc_replyrecv_func2, DO_REAL_REPLY_RECV, api_reply, api_recv, end, 0, dummy_cache_func)
IPC_REPLY_RECV_FUNC(ipc_replyrecv_func, DO_REAL_REPLY_RECV, dummy_seL4_Reply, api_recv, start, 0, CACHE_FUNC)
// IPC_REPLY_RECV_FUNC(ipc_replyrecv_10_func2, DO_REAL_REPLY_RECV_10, api_reply, api_recv, end, 10, dummy_cache_func)
// IPC_REPLY_RECV_FUNC(ipc_replyrecv_10_func, DO_REAL_REPLY_RECV_10, dummy_seL4_Reply, api_recv, start, 10, CACHE_FUNC)

// seL4_Word
// ipc_recv_func(int argc, char *argv[])
// {
//     uint32_t i;
//     ccnt_t start UNUSED, end UNUSED;
//     seL4_CPtr ep = atoi(argv[0]);
//     seL4_CPtr result_ep = atoi(argv[1]);
//     UNUSED seL4_CPtr reply = atoi(argv[2]);

//     COMPILER_MEMORY_FENCE();
//     for (i = 0; i < WARMUPS; i++) {
//         READ_COUNTER_BEFORE(start);
//         DO_REAL_RECV(ep, reply);
//         READ_COUNTER_AFTER(end);
//     }
//     COMPILER_MEMORY_FENCE();
//     DO_REAL_RECV(ep, reply);
//     send_result(result_ep, end);
//     return 0;
// }

// seL4_Word ipc_send_func(int argc, char *argv[])
// {
//     uint32_t i;
//     ccnt_t start UNUSED, end UNUSED;
//     seL4_CPtr ep = atoi(argv[0]);
//     seL4_CPtr result_ep = atoi(argv[1]);
//     seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 0);
//     COMPILER_MEMORY_FENCE();
//     for (i = 0; i < WARMUPS; i++) {
//         READ_COUNTER_BEFORE(start);
//         DO_REAL_SEND(ep, tag);
//         READ_COUNTER_AFTER(end);
//     }
//     COMPILER_MEMORY_FENCE();
//     send_result(result_ep, start);
//     DO_REAL_SEND(ep, tag);
//     return 0;
// }

#define MEASURE_OVERHEAD(op, dest, decls) do { \
    uint32_t i; \
    timing_init(); \
    for (i = 0; i < OVERHEAD_RETRIES; i++) { \
        uint32_t j; \
        for (j = 0; j < RUNS; j++) { \
            uint32_t k; \
            decls; \
            ccnt_t start, end; \
            COMPILER_MEMORY_FENCE(); \
            for (k = 0; k < WARMUPS; k++) { \
                READ_COUNTER_BEFORE(start); \
                op; \
                READ_COUNTER_AFTER(end); \
            } \
            COMPILER_MEMORY_FENCE(); \
            dest[j] = end - start; \
        } \
        if (results_stable(dest, RUNS)) break; \
    } \
    timing_destroy(); \
} while(0)

static void measure_overhead(ipc_results_t *results)
{
    MEASURE_OVERHEAD(DO_NOP_CALL(0, tag),
                     results->overhead_benchmarks[CALL_OVERHEAD],
                     seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 0));
    MEASURE_OVERHEAD(DO_NOP_REPLY_RECV(0, tag, 0),
                     results->overhead_benchmarks[REPLY_RECV_OVERHEAD],
                     seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 0));
    
    // MEASURE_OVERHEAD(DO_NOP_SEND(0, tag),
    //                  results->overhead_benchmarks[SEND_OVERHEAD],
    //                  seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 0));
    // MEASURE_OVERHEAD(DO_NOP_RECV(0, 0),
    //                  results->overhead_benchmarks[RECV_OVERHEAD],
    //                  {});
    // MEASURE_OVERHEAD(DO_NOP_CALL_10(0, tag10),
    //                  results->overhead_benchmarks[CALL_10_OVERHEAD],
    //                  seL4_MessageInfo_t tag10 = seL4_MessageInfo_new(0, 0, 0, 10));
    // MEASURE_OVERHEAD(DO_NOP_REPLY_RECV_10(0, tag10, 0),
    //                  results->overhead_benchmarks[REPLY_RECV_10_OVERHEAD],
    //                  seL4_MessageInfo_t tag10 = seL4_MessageInfo_new(0, 0, 0, 10));
}

void run_bench(env_t *env, cspacepath_t result_ep_path, seL4_CPtr ep,
               const benchmark_params_t *params,
               ccnt_t *ret1, ccnt_t *ret2,
               helper_thread_t *client, helper_thread_t *server)
{

    timing_init();
    /* start processes */
    int error = benchmark_spawn_process(&server->process, &env->slab_vka, &env->vspace, NUM_ARGS,
                                        server->argv, 1);
    ZF_LOGF_IF(error, "Failed to spawn server\n");

    if (config_set(CONFIG_KERNEL_MCS)) { // && params->server_fn != IPC_RECV_FUNC) {
        /* wait for server to tell us its initialised */
        seL4_Wait(ep, NULL);

        if (params->passive) {
            /* convert server to passive */
            error = api_sc_unbind_object(server->process.thread.sched_context.cptr,
                                         server->process.thread.tcb.cptr);
            ZF_LOGF_IF(error, "Failed to convert server to passive");
        }
    }

    error = benchmark_spawn_process(&client->process, &env->slab_vka, &env->vspace, NUM_ARGS, client->argv, 1);
    ZF_LOGF_IF(error, "Failed to spawn client\n");

    /* get results */
    *ret1 = get_result(result_ep_path.capPtr);

    if (config_set(CONFIG_KERNEL_MCS) && /* params->server_fn != IPC_RECV_FUNC && */ params->passive) {
        /* convert server to active so it can send us the result */
        error = api_sc_bind(server->process.thread.sched_context.cptr,
                            server->process.thread.tcb.cptr);
        ZF_LOGF_IF(error, "Failed to convert server to active");
    }

    *ret2 = get_result(result_ep_path.capPtr);

    /* clean up - clean server first in case it is sharing the client's cspace and vspace */
    seL4_TCB_Suspend(client->process.thread.tcb.cptr);
    seL4_TCB_Suspend(server->process.thread.tcb.cptr);

    timing_destroy();
}

static env_t *env;

void CONSTRUCTOR(MUSLCSYS_WITH_VSYSCALL_PRIORITY) init_env(void)
{
    static size_t object_freq[seL4_ObjectTypeCount] = {
        [seL4_TCBObject] = 4,
        [seL4_EndpointObject] = 2,
#ifdef CONFIG_KERNEL_MCS
        [seL4_SchedContextObject] = 4,
        [seL4_ReplyObject] = 4
#endif
    };

    env = benchmark_get_env(
              sel4runtime_argc(),
              sel4runtime_argv(),
              sizeof(ipc_results_t),
              object_freq
          );
}



// void process_trace_points(kernel_log_entry_t *src_results, ipc_results_t *dst_results, int num_entries, int offset)
// {
//     ccnt_t temp[9] = {0};
//     for (int i = 0; i < num_entries; i++) {
//         temp[kernel_logging_entry_get_key(&src_results[i])] = MAX(temp[kernel_logging_entry_get_key(&src_results[i])], kernel_logging_entry_get_data(&src_results[i]));
//     }
//     for (int i = 0; i < 9; i++) {
//         dst_results->kernel_traces[i][offset] = temp[i];
//     }
    
// }

int main(int argc, char **argv)
{
    vka_object_t ep, result_ep;
    cspacepath_t ep_path, result_ep_path;

    ipc_results_t *results = (ipc_results_t *) env->results;

    /* allocate benchmark endpoint - the IPC's that we benchmark
       will be sent over this ep */
    if (vka_alloc_endpoint(&env->slab_vka, &ep) != 0) {
        ZF_LOGF("Failed to allocate endpoint");
    }
    vka_cspace_make_path(&env->slab_vka, ep.cptr, &ep_path);

    /* allocate result ep - the IPC threads will send their timestamps
       to this ep */
    if (vka_alloc_endpoint(&env->slab_vka, &result_ep) != 0) {
        ZF_LOGF("Failed to allocate endpoint");
    }
    vka_cspace_make_path(&env->slab_vka, result_ep.cptr, &result_ep_path);

    /* measure benchmarking overhead */
    measure_overhead(results);

    helper_thread_t client, server_thread, server_process;

    benchmark_shallow_clone_process(env, &client.process, seL4_MinPrio, 0, "client");
    benchmark_shallow_clone_process(env, &server_process.process, seL4_MinPrio, 0, "server process");
    benchmark_configure_thread_in_process(env, &client.process, &server_thread.process, seL4_MinPrio, 0, "server thread");

    client.ep = sel4utils_copy_path_to_process(&client.process, ep_path);
    client.result_ep = sel4utils_copy_path_to_process(&client.process, result_ep_path);

    server_process.ep = sel4utils_copy_path_to_process(&server_process.process, ep_path);
    server_process.result_ep = sel4utils_copy_path_to_process(&server_process.process, result_ep_path);

    server_thread.ep = client.ep;
    server_thread.result_ep = client.result_ep;

    sel4utils_create_word_args(client.argv_strings, client.argv, NUM_ARGS, client.ep, client.result_ep, 0);
    sel4utils_create_word_args(server_process.argv_strings, server_process.argv, NUM_ARGS,
                               server_process.ep, server_process.result_ep, SEL4UTILS_REPLY_SLOT);
    sel4utils_create_word_args(server_thread.argv_strings, server_thread.argv, NUM_ARGS,
                               server_thread.ep, server_thread.result_ep, SEL4UTILS_REPLY_SLOT);

    vka_object_t kernel_log_frame;
    if (vka_alloc_frame(&env->slab_vka, seL4_LargePageBits, &kernel_log_frame) != 0) {
        ZF_LOGF("Failed to allocate ipc buffer");
    }

    if (kernel_logging_set_log_buffer(kernel_log_frame.cptr) != 0) {
        ZF_LOGF("Failed to set kernel log buffer");
    }

    void *log_buffer = vspace_map_pages(&env->vspace, &kernel_log_frame.cptr, NULL, seL4_AllRights, 1, seL4_LargePageBits, 1);
    kernel_log_entry_t *kernel_log_buffer = (kernel_log_entry_t *)log_buffer;

    /* run the benchmark */
    seL4_CPtr auth = simple_get_tcb(&env->simple);
    ccnt_t start, end;
    for (int i = 0; i < RUNS; i++) {
        int j;
        ZF_LOGI("--------------------------------------------------\n");
        ZF_LOGI("Doing iteration %d\n", i);
        ZF_LOGI("--------------------------------------------------\n");
        for (j = 0; j < ARRAY_SIZE(benchmark_params); j++) {
            const struct benchmark_params *params = &benchmark_params[j];
            ZF_LOGI("%s\t: IPC duration (%s), client prio: %3d server prio %3d, %s vspace, %s, length %2d\n",
                    params->name,
                    params->direction == DIR_TO ? "client --> server" : "server --> client",
                    params->client_prio, params->server_prio,
                    params->same_vspace ? "same" : "diff",
                    (config_set(CONFIG_KERNEL_MCS) && params->passive) ? "passive" : "active", params->length);

            /* set up client for benchmark */
            int error = seL4_TCB_SetPriority(client.process.thread.tcb.cptr, auth, params->client_prio);
            ZF_LOGF_IF(error, "Failed to set client prio");
            client.process.entry_point = bench_funcs[params->client_fn];

            if (params->same_vspace) {
                error = seL4_TCB_SetPriority(server_thread.process.thread.tcb.cptr, auth, params->server_prio);
                assert(error == seL4_NoError);
                server_thread.process.entry_point = bench_funcs[params->server_fn];
            } else {
                error = seL4_TCB_SetPriority(server_process.process.thread.tcb.cptr, auth, params->server_prio);
                assert(error == seL4_NoError);
                server_process.process.entry_point = bench_funcs[params->server_fn];
            }

            run_bench(env, result_ep_path, ep_path.capPtr, params, &end, &start, &client,
                      params->same_vspace ? &server_thread : &server_process);

            if (end > start) {
                results->benchmarks[j][i] = end - start;
            } else {
                results->benchmarks[j][i] = start - end;
            }
        }
    }

    
    
    // kernel_log_entry_t kernel_log_buffer[1000];
    // if (kernel_logging_sync_log(log_buffer, kernel_log_buffer, 1000) != 1000)
    // {
    //     ZF_LOGF("Failed to sync kernel log");
    // }

    unsigned long events = kernel_logging_finalize_log();
    printf("%d events from this run\n", events);

    // process_trace_points(kernel_log_buffer, results, events, i);

    for (int i = 0; i < events; i++) {

        seL4_Word id = kernel_logging_entry_get_key(&kernel_log_buffer[i]);
        seL4_Word value = kernel_logging_entry_get_data(&kernel_log_buffer[i]);

        if (results->kernel_traces[id] < value) {
            results->kernel_traces[id] = value;
        }

        // results->kernel_traces[0][i] = value;
    }

    // TODO defs need to be freeing things here
    // vspace_unmap_pages(&env->vspace, log_buffer, 1, seL4_LargePageBits, VSPACE_PRESERVE);

    // vka_free_object(&env->slab_vka, &kernel_log_frame);

    /* done -> results are stored in shared memory so we can now return */
    benchmark_finished(EXIT_SUCCESS);
    return 0;
}
