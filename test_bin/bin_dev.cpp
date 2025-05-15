#include <mach/mach.h>
#include <mach/mach_host.h>
#include <iostream>
#include <thread>
#include <pthread.h>
#include <chrono>
#include <cstring>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <pthread.h>


#if defined(__arm64__)
#include <mach/arm/thread_status.h>
#endif

// clang++ -o bin_dev bin_dev.cpp -lpthread -arch x86_64 -arch arm64 
// clang++ -o bin_dev_x86_64 bin_dev.cpp -lpthread -arch x86_64 
// clang++ -o bin_dev_arm64 bin_dev.cpp -lpthread -arch arm64 
// Thread ID: 259, Name: , NameFlag: 0, User Time: 0s 2455μs, System Time: 0s 2972μs, CPU Usage: 0, Policy: 1, Run State: 3, Flags: 1, Suspend Count: 0, Sleep Time: 0
// Thread ID: 2563, Name: , NameFlag: 0, User Time: 0s 3254μs, System Time: 0s 4622μs, CPU Usage: 0, Policy: 1, Run State: 1, Flags: 0, Suspend Count: 0, Sleep Time: 0
// Thread ID: 3591, Name: , NameFlag: 3, User Time: 1s 276351μs, System Time: 0s 2132μs, CPU Usage: 0, Policy: 1, Run State: 3, Flags: 1, Suspend Count: 20, Sleep Time: 0
// Thread ID: 2819, Name: , NameFlag: 0, User Time: 1s 269062μs, System Time: 0s 8449μs, CPU Usage: 0, Policy: 1, Run State: 3, Flags: 1, Suspend Count: 20, Sleep Time: 0
void printThreads() {
    mach_msg_type_number_t threadCount;
    thread_act_t *threads;

    // 获取当前进程的线程
    if (task_threads(mach_task_self(), &threads, &threadCount) != KERN_SUCCESS) {
        std::cerr << "Failed to get threads." << std::endl;
        return;
    }
    std::cerr << "-----------printThreads-----------" << std::endl;

    thread_act_t threadsToTerminate[threadCount];
    int terminateCount = 0;

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        thread_info_data_t threadInfo;
        mach_msg_type_number_t threadInfoCount = THREAD_INFO_MAX;

        if (thread_info(threads[i], THREAD_BASIC_INFO, (thread_info_t)&threadInfo, &threadInfoCount) == KERN_SUCCESS) {
            thread_basic_info_t basicInfo = (thread_basic_info_t)&threadInfo;

            char threadName[256] = {0};
            pthread_t threadId = pthread_from_mach_thread_np(threads[i]);
            // On success, these functions return 0; on error, they return a nonzero error number.
            int nameFlag = pthread_getname_np(threadId, threadName, sizeof(threadName));
            std::cout << "THREAD_BASIC_INFO Thread ID: " << threads[i]
                      << ", Name: " << threadName
                      << ", NameFlag: " << nameFlag
                      << ", User Time: " << basicInfo->user_time.seconds << "s " << basicInfo->user_time.microseconds << "μs"
                      << ", System Time: " << basicInfo->system_time.seconds << "s " << basicInfo->system_time.microseconds << "μs"
                      << ", CPU Usage: " << basicInfo->cpu_usage
                      << ", Policy: " << basicInfo->policy
                      << ", Run State: " << basicInfo->run_state
                      << ", Flags: " << basicInfo->flags
                      << ", Suspend Count: " << basicInfo->suspend_count
                      << ", Sleep Time: " << basicInfo->sleep_time
                      << std::endl;
            
            // if (nameFlag!=0){
            //     threadsToTerminate[terminateCount++] = threads[i];
            //     #if defined(__arm64__) || defined(__aarch64__)
            //     if (i+1 < threadCount) {
            //         threadsToTerminate[terminateCount++] = threads[i+1];
            //     }
            //     #endif
            // }
        }


        // #if defined(__arm64__)
        // mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;
        // thread_state_flavor_t flavor = ARM_THREAD_STATE64;
        // arm_thread_state64_t threadState;
        // #else
        // mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;
        // thread_state_flavor_t flavor = x86_THREAD_STATE64;
        // x86_thread_state64_t threadState;
        // #endif

        
        // if (thread_get_state(threads[i], flavor, (thread_state_t)&threadState, &stateCount) == KERN_SUCCESS) {
        // #if defined(__arm64__)
        //     printf(
        //         "Thread ID: %u, PC: 0x%llx, SP: 0x%llx, PSR: 0x%x, X0: 0x%llx,"
        //         // " X1: 0x%llx, X2: 0x%llx, X3: 0x%llx, X4: 0x%llx, X5: 0x%llx, X6: 0x%llx, X7: 0x%llx, X8: 0x%llx, X9: 0x%llx, X10: 0x%llx, X11: 0x%llx, X12: 0x%llx, X13: 0x%llx, X14: 0x%llx, X15: 0x%llx, X16: 0x%llx, X17: 0x%llx, X18: 0x%llx, X19: 0x%llx, X20: 0x%llx, X21: 0x%llx, X22: 0x%llx, X23: 0x%llx, X24: 0x%llx, X25: 0x%llx, X26: 0x%llx, X27: 0x%llx, X28: 0x%llx, FP: 0x%llx, LR: 0x%llx"
        //         "\n", 
        //         threads[i],
        //         threadState.__pc, 
        //         threadState.__sp, 
        //         threadState.__cpsr, 
        //         threadState.__x[0]
        //         // ,threadState.__x[1], threadState.__x[2], threadState.__x[3], 
        //         // threadState.__x[4], threadState.__x[5], threadState.__x[6], threadState.__x[7], 
        //         // threadState.__x[8], threadState.__x[9], threadState.__x[10], threadState.__x[11], 
        //         // threadState.__x[12], threadState.__x[13], threadState.__x[14], threadState.__x[15], 
        //         // threadState.__x[16], threadState.__x[17], threadState.__x[18], threadState.__x[19], 
        //         // threadState.__x[20], threadState.__x[21], threadState.__x[22], threadState.__x[23], 
        //         // threadState.__x[24], threadState.__x[25], threadState.__x[26], threadState.__x[27], 
        //         // threadState.__x[28], threadState.__fp, threadState.__lr
        //         );

        //     if (threadState.__x[0] == 0xd13)
        //     {
        //         threadsToTerminate[terminateCount++] = threads[i];
        //     }
        // #else
        //     // 打印 x86_64 架构下的寄存器, 0xd13
        //     printf("Thread ID: %u, RIP: 0x%llx, RSP: 0x%llx, RFLAGS: 0x%llx, RAX: 0x%llx, "
        //            // "RBX: 0x%llx, RCX: 0x%llx, RDX: 0x%llx, RSI: 0x%llx, RDI: 0x%llx, RBP: 0x%llx, R8: 0x%llx, R9: 0x%llx, R10: 0x%llx, R11: 0x%llx, R12: 0x%llx, R13: 0x%llx, R14: 0x%llx, R15: 0x%llx"
        //            "\n", 
        //         threads[i], 
        //         threadState.__rip, threadState.__rsp, threadState.__rflags,threadState.__rax
        //         //, threadState.__rbx, threadState.__rcx, threadState.__rdx, 
        //         // threadState.__rsi, threadState.__rdi, threadState.__rbp, 
        //         // threadState.__r8, threadState.__r9, threadState.__r10, threadState.__r11, 
        //         // threadState.__r12, threadState.__r13, threadState.__r14, threadState.__r15
        //         );
            
        //     if (threadState.__rax == 0xd13)
        //     {
        //         threadsToTerminate[terminateCount++] = threads[i];
        //     }
            
        // #endif

        // }

        // // 获取 THREAD_IDENTIFIER_INFO
        // thread_identifier_info_data_t threadIdInfo;
        // mach_msg_type_number_t idInfoCount = THREAD_IDENTIFIER_INFO_COUNT;

        // if (thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&threadIdInfo, &idInfoCount) == KERN_SUCCESS) {
        //     std::cout << "THREAD_IDENTIFIER_INFO Thread ID: " << threads[i]
        //             << ", thread_handle: " << threadIdInfo.thread_handle
        //             << ", dispatch_qaddr: " << threadIdInfo.dispatch_qaddr
        //             << std::endl;
        // }

        
        // // 获取 THREAD_EXTENDED_INFO
        // thread_extended_info_data_t threadExtendedInfo;
        // mach_msg_type_number_t extendedInfoCount = THREAD_EXTENDED_INFO_COUNT;

        // if (thread_info(threads[i], THREAD_EXTENDED_INFO, (thread_info_t)&threadExtendedInfo, &extendedInfoCount) == KERN_SUCCESS) {
        // std::cout << "THREAD_EXTENDED_INFO Thread ID: " << threads[i]
        //           << ", User Time: " << threadExtendedInfo.pth_user_time << " ns"
        //           << ", System Time: " << threadExtendedInfo.pth_system_time << " ns" 
        //           << ", CPU Usage: " << threadExtendedInfo.pth_cpu_usage 
        //           << ", Policy: " << threadExtendedInfo.pth_policy 
        //           << ", Run State: " << threadExtendedInfo.pth_run_state 
        //           << ", Flags: " << threadExtendedInfo.pth_flags
        //           << ", Sleep Time: " << threadExtendedInfo.pth_sleep_time << " s" 
        //           << ", Current Priority: " << threadExtendedInfo.pth_curpri 
        //           << ", Priority: " << threadExtendedInfo.pth_priority 
        //           << ", Max Priority: " << threadExtendedInfo.pth_maxpriority
        //           << ", Thread Name: " << threadExtendedInfo.pth_name
        //           << std::endl;
        // }
    }

    for (int i = 0; i < terminateCount; i++) {
        std::cerr << "kill thread: " << threadsToTerminate[i] << std::endl;
        if (thread_suspend(threadsToTerminate[i]) != KERN_SUCCESS) {
            std::cerr << "Failed to suspend thread." << std::endl;
        }
        if (thread_terminate(threadsToTerminate[i]) != KERN_SUCCESS) {
            std::cerr << "Failed to terminate thread." << std::endl;
        }
    }

    // 释放线程数组
    vm_deallocate(mach_task_self(), (vm_address_t)threads, threadCount * sizeof(thread_act_t));
}

void* threadFunction(void* arg) {
    char name[256];
    snprintf(name, sizeof(name), "WorkerThread-%ld", (long)arg);
    // pthread_setname_np( name);

    while (true) {
        printThreads();
        std::this_thread::sleep_for(std::chrono::seconds(2));  // 每 2 秒刷新一次
    }
    return nullptr;
}

int main() {
    pthread_t thread;
    pthread_create(&thread, NULL, threadFunction, NULL);
    // 主线程可以做其他事情，或者等待子线程结束
    pthread_join(thread, NULL);
    return 0;
}