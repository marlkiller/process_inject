//
//  main.m
//  process_inject
//
//  Created by voidm on 2024/9/28.
//

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <pthread.h>
#include <mach-o/dyld_images.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <libgen.h>
#define CONFIG_FILE "cfg.data"

// === Unified log macros with color ===
#define COLOR_RESET   "\x1b[0m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_BLUE    "\x1b[34m"

#define LOG_INFO(fmt, ...)  printf(COLOR_BLUE  "[*] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_OK(fmt, ...)    printf(COLOR_GREEN "[+] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  printf(COLOR_YELLOW "[!] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)   fprintf(stderr, COLOR_RED "[×] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) do { LOG_ERR(fmt, ##__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

extern char **environ;

#ifdef __x86_64__

///Shellcode for the mach thread.
static const unsigned char mach_thread_code[] =
{
//    0xCC,
    0x55,                                           // 000000011F9B8001 push    rbp
    0x48, 0x89, 0xe5,                               // 000000011F9B8002 mov     rbp, rsp
    0x48, 0x89, 0xef,                               // 000000011F9B8005 mov     rdi, rbp
    0xff, 0xd0,                                     // 000000011F9B8008 call    rax                             ; _pthread_create_from_mach_thread
    0x48, 0xc7, 0xc0, 0x09, 0x03, 0x00, 0x00,       // 000000011F9B800A mov     rax, 309h                       ; 777
    0xe9, 0xfb, 0xff, 0xff, 0xff                    // 000000011F9B8011 jmp     loc_11F9B8011
};

///Shellcode for the posix thread.
static const unsigned char posix_thread_code[] =
{
//    0xCC,
    0x55,                                           // 00000001210EE001                 push    rbp
    0x48, 0x89, 0xe5,                               // 00000001210EE002                 mov     rbp, rsp
    0x48, 0x8b, 0x07,                               // 00000001210EE005                 mov     rax, [rdi]      ; dlopen
    0x48, 0x8b, 0x7f, 0xf8,                         // 00000001210EE008                 mov     rdi, [rdi-8]    ; xxx.dylib
    0xbe, 0x01, 0x00, 0x00, 0x00,                   // 00000001210EE00C                 mov     esi, 1
    0xff, 0xd0,                                     // 00000001210EE011                 call    rax             ; dlopen
    0xc9,                                           // 00000001210EE013                 leave
    0xc3                                            // 00000001210EE014                 retn
};

#define PTR_SIZE sizeof(void*)
#define STACK_SIZE 1024
#define MACH_CODE_SIZE sizeof(mach_thread_code)
#define POSIX_CODE_SIZE sizeof(posix_thread_code)
#else

//#define ARM_THREAD_STATE64 6
typedef struct
{
    __uint64_t __x[29]; /* General purpose registers x0-x28 */
    __uint64_t __fp;    /* Frame pointer x29 */
    __uint64_t __lr;    /* Link register x30 */
    __uint64_t __sp;    /* Stack pointer x31 */
    __uint64_t __pc;    /* Program counter */
    __uint32_t __cpsr;  /* Current program status register */
    __uint32_t __pad;   /* Same size for 32-bit or 64-bit clients */
}
__arm_thread_state64_t;
//#define ARM_THREAD_STATE64_COUNT ((mach_msg_type_number_t) \
//    (sizeof (__arm_thread_state64_t)/sizeof(uint32_t)))

///Shellcode for the mach thread.
unsigned char mach_thread_code[] =
{
//    "\x20\x8e\x38\xd4" //   brk 
    "\x80\x00\x3f\xd6" // 0x121858004: blr    x4    ;pthread_create_from_mach_thread
    "\x00\x00\x00\x14" // 0x121858008: b      0x121858008
};
#define MACH_CODE_SIZE sizeof(mach_thread_code)
#define STACK_SIZE 1024
#endif


///The function we will call through the mach thread.
int pthread_create_from_mach_thread(pthread_t *thread,
                                    const pthread_attr_t *attr,
                                    void *(*start_routine)(void *),
                                    void *arg);


#define kr(value) if (value != KERN_SUCCESS)\
{\
    LOG_ERR("Mach error: %s (line %d)", mach_error_string(value), __LINE__);\
    exit(value);\
}


bool is_dylib_loaded2(const task_t task,
                        const char* dylib_path)
{
    bool image_exists = false;
    mach_msg_type_number_t size = 0;
    
    mach_msg_type_number_t dataCnt = 0;
    vm_offset_t readData = 0;
    
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
    size = sizeof(struct dyld_all_image_infos);
    mach_vm_read(task, dyld_info.all_image_info_addr, size, &readData, &dataCnt);
    unsigned char* data = (unsigned char*)readData;
    struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)data;
    size = sizeof(struct dyld_image_info)*(infos -> infoArrayCount);
    mach_vm_read(task, (mach_vm_address_t)infos -> infoArray, size, &readData, &dataCnt);
    unsigned char* info_buf = (unsigned char*)readData;
    struct dyld_image_info* info = (struct dyld_image_info*)info_buf;
    
    for (int i = 0 ; i < (infos -> infoArrayCount) ; i++)
    {
        size = PATH_MAX;
        mach_vm_read(task, (mach_vm_address_t)info[i].imageFilePath, size, &readData, &dataCnt);
        unsigned char* foundpath = (unsigned char*)readData;
        if (foundpath)
        {
            // printf("Checking dylib: %s\n", foundpath);
            if (strcmp((const char*)(foundpath), dylib_path) == 0)
            {
                LOG_INFO("Dylib already loaded: %s", foundpath);
                image_exists = true;
                break;
            }
        }
    }
    return image_exists;
}

#ifdef __x86_64__

int inject_dylib_x86(pid_t pid, const char *lib){
    //Function addresses.
    const static void* pthread_create_from_mach_thread_address =
    (const void*)pthread_create_from_mach_thread;

    const static void* dlopen_address = (const void*)dlopen;

    vm_size_t path_length = strlen(lib);

    //Obtain the task port.
    task_t task;
    kr(task_for_pid(mach_task_self_, pid, &task));
    
    if (is_dylib_loaded2(task,lib)) {
        return -1;
    }

    
    mach_vm_address_t mach_code_mem = 0;
    mach_vm_address_t posix_code_mem = 0;
    mach_vm_address_t stack_mem = 0;
    mach_vm_address_t path_mem = 0;
    mach_vm_address_t posix_param_mem = 0;
    
    kr(mach_vm_allocate(task, &mach_code_mem, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    kr(mach_vm_allocate(task, &posix_code_mem, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    //Allocate the path variable and the stack.
    kr(mach_vm_allocate(task, &stack_mem, STACK_SIZE, VM_FLAGS_ANYWHERE));
    kr(mach_vm_allocate(task, &path_mem, path_length, VM_FLAGS_ANYWHERE));
    //Allocate the pthread parameter array.
    kr(mach_vm_allocate(task, &posix_param_mem, (PTR_SIZE * 2), VM_FLAGS_ANYWHERE));

    //Write the path into memory.
    kr(mach_vm_write(task, path_mem, (vm_offset_t)lib, (int)path_length));
    //Write the parameter array contents into memory. This array will be the pthread's parameter.
    //The address of dlopen() is the first parameter.
    kr(mach_vm_write(task, posix_param_mem, (vm_offset_t)&dlopen_address, PTR_SIZE));
    //The pointer to the dylib path is the second parameter.
    kr(mach_vm_write(task, (posix_param_mem - PTR_SIZE), (vm_offset_t)&path_mem, PTR_SIZE));
    //Write to both instructions, and mark them as readable, writable, and executable.
    //Do it for the mach thread instruction.
    kr(mach_vm_write(task, mach_code_mem, (vm_offset_t)&mach_thread_code, MACH_CODE_SIZE));
    //Do it for the pthread instruction.
    kr(mach_vm_write(task, posix_code_mem, (vm_offset_t)&posix_thread_code, POSIX_CODE_SIZE));
    
    kr(mach_vm_protect(task, mach_code_mem, MACH_CODE_SIZE, FALSE, VM_PROT_ALL));
    kr(mach_vm_protect(task, posix_code_mem, POSIX_CODE_SIZE, FALSE, VM_PROT_ALL));

    //The state and state count for launching the thread and reading its registers.
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    mach_msg_type_number_t state = x86_THREAD_STATE64;

    //Set all the registers to 0 so we can avoid setting extra registers to 0.
    x86_thread_state64_t regs;
    bzero(&regs, sizeof(regs));

    //Set the mach thread instruction pointer.
    regs.__rip = (__uint64_t)mach_code_mem;

    //Since the stack "grows" downwards, this is a usable stack pointer.
    regs.__rsp = (__uint64_t)(stack_mem + STACK_SIZE);

    //Set the function address, the 3rd parameter, and the 4th parameter.
    regs.__rax = (__uint64_t)pthread_create_from_mach_thread_address;
    regs.__rdx = (__uint64_t)posix_code_mem;
    regs.__rcx = (__uint64_t)posix_param_mem;



    //Initialize the thread.
    thread_act_t thread;
    kr(thread_create_running(task, state, (thread_state_t)(&regs), state_count, &thread));

    LOG_INFO("Monitoring register values for PID %d", pid);

    //Repeat check if a certain register has a certain value.
    for (;;)
    {
        mach_msg_type_number_t sc = state_count;
        kr(thread_get_state(thread, state, (thread_state_t)(&regs), &sc));
        if (regs.__rax == 777)
        {
            LOG_OK("Detected completion signal in RAX register");
            break;
        }
        // TODO  Sleep will cause the program to crash.
    }

    LOG_INFO("Cleaning up injection thread for PID %d", pid);
    kr(thread_suspend(thread));
    kr(thread_terminate(thread));

    kr(mach_vm_deallocate(task, stack_mem, STACK_SIZE));
    kr(mach_vm_deallocate(task, mach_code_mem, MACH_CODE_SIZE));
    
    LOG_OK("Successfully injected '%s' into PID %d", lib, pid);
    return 0;
}
#else
int inject_dylib_arm(pid_t pid, const char *lib){
    task_t task;
    kr(task_for_pid(mach_task_self_, pid, &task));
    
    if (is_dylib_loaded2(task,lib)) {
        return -1;
    }
    
    mach_vm_address_t remote_mach_code = 0;
    mach_vm_address_t remote_stack = 0;
    mach_vm_address_t remote_pthread_mem = 0;
    mach_vm_address_t remote_path = 0;
    
    kr(mach_vm_allocate(task, &remote_mach_code, MACH_CODE_SIZE, VM_FLAGS_ANYWHERE));
    kr(mach_vm_allocate(task, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE));
    kr(mach_vm_allocate(task, &remote_pthread_mem, 8, VM_FLAGS_ANYWHERE));
    kr(mach_vm_allocate(task, &remote_path, strlen(lib), VM_FLAGS_ANYWHERE));
    
    kr(mach_vm_write(task, remote_path, (vm_address_t)lib, (int)strlen(lib)));
    kr(mach_vm_write(task, remote_mach_code, (vm_address_t)mach_thread_code, MACH_CODE_SIZE));
    kr(mach_vm_protect(task, remote_mach_code, MACH_CODE_SIZE, FALSE, VM_PROT_READ|VM_PROT_EXECUTE));

    __arm_thread_state64_t regs;
    bzero(&regs, sizeof(regs));
    regs.__pc = remote_mach_code;
    regs.__sp = remote_stack + STACK_SIZE;
    

    // pthread_create_from_mach_thread
    const static void* pthread_create_from_mach_thread_address =
            (const void*)pthread_create_from_mach_thread;
    regs.__x[4] = (vm_address_t)pthread_create_from_mach_thread_address;
    regs.__x[0] = remote_pthread_mem;
    regs.__x[1] = 0;
    regs.__x[2] = (vm_address_t)dlopen;
    regs.__x[3] = remote_path;
    
    
    thread_act_t remote_thread;
    kr(thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&regs, ARM_THREAD_STATE64_COUNT, &remote_thread));
    LOG_INFO("Monitoring thread execution for PID %d", pid);


    sleep(1);
    
    LOG_INFO("Terminating injection thread for PID %d", pid);
    kr(thread_terminate(remote_thread));
    
        kr(mach_vm_deallocate(task, remote_stack, STACK_SIZE));
    kr(mach_vm_deallocate(task, remote_mach_code, MACH_CODE_SIZE));
    kr(mach_vm_deallocate(task, remote_path, strlen(lib)));
    kr(mach_vm_deallocate(task, remote_pthread_mem, 8));
    
    LOG_OK("Successfully injected '%s' into PID %d", lib, pid);
    return 0;
}
#endif

int inject_dylib(pid_t pid, const char *lib) {
    
#ifdef __x86_64__
    inject_dylib_x86(pid, lib);
#else
    inject_dylib_arm(pid, lib);
#endif
    return (0);
}


///Get the process ID of a process by its name.
pid_t find_pid_by_name2(const char* process_name)
{
    static pid_t pids[4096];
    int retpid = -1;
    const int count = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    const int proc_count = count/sizeof(pid_t);
    LOG_INFO("Scanning %d processes for target '%s'", proc_count, process_name);
    for (int i = 0; i < proc_count; i++)
    {
        struct proc_bsdinfo proc;
        const int st = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &proc, PROC_PIDTBSDINFO_SIZE);
        if (st == PROC_PIDTBSDINFO_SIZE)
        {
            // printf("Checking process: %s (PID: %d)\n", proc.pbi_name, proc.pbi_pid);

            if (strcmp(process_name, proc.pbi_name) == 0)
            {
                LOG_OK("Found target process: %s (PID: %d)", proc.pbi_name, proc.pbi_pid);
                retpid = pids[i];
                break;
            }
        }
    }
    return retpid;
}

pid_t find_pid_by_name(const char *process_name) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t size;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) == -1) {
        LOG_ERR("sysctl operation failed");
        return -1;
    }

    struct kinfo_proc *process_list = malloc(size);
    if (sysctl(mib, 4, process_list, &size, NULL, 0) == -1) {
        LOG_ERR("sysctl operation failed");
        free(process_list);
        return -1;
    }
    
    size_t process_count = size / sizeof(struct kinfo_proc);
    pid_t pid = -1;

    LOG_INFO("Scanning %zu processes for target '%s'", process_count, process_name);

    for (size_t i = 0; i < process_count; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        proc_pidpath(process_list[i].kp_proc.p_pid, path, sizeof(path));
        // printf("Checking process: %s (PID: %d)\n", path, process_list[i].kp_proc.p_pid);
        if (strstr(path, process_name) != NULL) {
            pid = process_list[i].kp_proc.p_pid;
            LOG_OK("Found target process: '%s' (PID: %d)", path, pid);
            break;
        }
    }

    if (pid == -1) {
        LOG_WARN("Process '%s' not found", process_name);
    }

    free(process_list);
    return pid;
}




int is_valid_dylib(const char *path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0 && S_ISREG(buffer.st_mode));
}



bool is_dylib_loaded(pid_t pid, const char *dylib_path) {
    char command[256];
    snprintf(command, sizeof(command), "lsof -p %d | grep '.dylib'", pid);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen");
        return false;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // printf("dylib: %s", buffer);
        if (strstr(buffer, dylib_path) != NULL) {
            LOG_INFO("Dylib already loaded: %s", buffer);
            pclose(fp);
            return true;
        }
    }

    pclose(fp);
    return false;
}

char* convertToAbsolutePath(const char *relativePath) {
    char *absolutePath = realpath(relativePath, NULL);
    if (!absolutePath) {
        perror("Error resolving absolute path");
        exit(EXIT_FAILURE);
    }
    return absolutePath;
}


// TODO: It seems that the timing is not very accurate ???
kern_return_t wait_for_dyld(pid_t pid) {
    kill(pid, SIGCONT);
    task_t task;
    kr(task_for_pid(mach_task_self(), pid, &task));
    
    task_dyld_info_data_t dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    int retries = 0;
    int MAX_RETRIES = 1000;
    while (retries < MAX_RETRIES) {
        kr(task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count));        

        if (dyld_info.all_image_info_addr != 0) {
            LOG_OK("dyld images are loaded. Address: %p", (void*)dyld_info.all_image_info_addr);
            return KERN_SUCCESS;
        }

        retries++;
        LOG_WARN("dyld images are not loaded yet. Retrying... (%d/%d)", retries, MAX_RETRIES);
        usleep(1000);  
    }

    LOG_ERR("Failed to load dyld images after %d retries", MAX_RETRIES);
    return KERN_FAILURE;
}
void get_executable_directory(char *buffer, size_t size) {
    char path[PATH_MAX];
    uint32_t path_size = sizeof(path);

    // Get the full path of the executable
    if (_NSGetExecutablePath(path, &path_size) == 0) {
        // Get the directory of the executable
        strncpy(buffer, dirname(path), size);
    } else {
        LOG_FATAL("Failed to get executable path");
        exit(EXIT_FAILURE);
    }
}
// Function to load configuration from the file
// eg:/Applications/Hopper Disassembler v4.app/Contents/MacOS/Hopper Disassembler v4|./libdylib_dobby_hook.dylib|-spawn
int load_config(const char *filename, char *arg1, char *arg2, char *arg3) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        LOG_ERR("Failed to open configuration file: %s", filename);
        return -1;
    }

    char line[1024];
    if (fgets(line, sizeof(line), file)) {
        // Remove trailing newline
        line[strcspn(line, "\n")] = 0;

        // Split the line into up to 3 parts using '|'
        char *token = strtok(line, "|");
        if (token) strncpy(arg1, token, 255);
        token = strtok(NULL, "|");
        if (token) {
            // Convert the second argument (dylib path) to an absolute path if it's relative
            if (token[0] != '/') {
                char absolute_path[PATH_MAX] = {0};
                get_executable_directory(absolute_path, sizeof(absolute_path));
                strncat(absolute_path, "/", sizeof(absolute_path) - strlen(absolute_path) - 1);
                strncat(absolute_path, token, sizeof(absolute_path) - strlen(absolute_path) - 1);
                strncpy(arg2, absolute_path, 255);
            } else {
                strncpy(arg2, token, 255);
            }
        }
        token = strtok(NULL, "|");
        if (token) strncpy(arg3, token, 255);
    } else {
        LOG_ERR("Configuration file is empty or invalid");
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        char config_path[PATH_MAX] = {0};
        char config_arg1[256] = {0};
        char config_arg2[256] = {0};
        char config_arg3[256] = {0};
        get_executable_directory(config_path, sizeof(config_path));
        strncat(config_path, "/" CONFIG_FILE, sizeof(config_path) - strlen(config_path) - 1);

        // Check if configuration file exists and load it
        if (access(config_path, F_OK) == 0) {
            LOG_INFO("Configuration file '%s' found. Loading...", CONFIG_FILE);
            if (load_config(config_path, config_arg1, config_arg2, config_arg3) == 0) {
                LOG_INFO("Loaded configuration: %s | %s | %s", config_arg1, config_arg2, config_arg3);
                // Override command-line arguments with config values
                argv[1] = config_arg1;
                argv[2] = config_arg2;
                if (strlen(config_arg3) > 0) {
                    argv[3] = config_arg3;
                    argc = 4; // Update argument count
                } else {
                    argc = 3;
                }
            } else {
                LOG_FATAL("Failed to load configuration file");
                return EXIT_FAILURE;
            }
        }

        if (argc < 2) {
            fprintf(stderr, "\n"
                           "process_inject: a macOS dylib injector by marlkiller @ GitHub\n\n"
                           "Usage: %s <target> <dylib> [flags]\n\n"
                           "Modes:\n"
                           "  <target> <dylib>         - Inject into running process by PID\n"
                           "  <target> <dylib> -name   - Inject into running process by name\n"
                           "  <app_path> <dylib> -spawn - Spawn new process and inject\n\n"
                           "Arguments:\n"
                           "  <target>    - Process ID or process name (with -name flag)\n"
                           "  <app_path>  - Full path to executable (with -spawn flag)\n"
                           "  <dylib>     - Full path to dynamic library to inject\n\n"
                           "Options:\n"
                           "  -name       - Treat <target> as process name instead of PID\n"
                           "  -spawn      - Launch new process in suspended state and inject\n\n"
                           "Examples:\n"
                           "  %s 1234 /path/to/library.dylib\n"
                           "  %s Safari /path/to/library.dylib -name\n"
                           "  %s /Applications/Calculator.app/Contents/MacOS/Calculator /path/to/library.dylib -spawn\n\n"
                           "Note: Injecting into root processes requires root privileges\n",
                           argv[0], argv[0], argv[0], argv[0]);
           return EXIT_FAILURE;
        }

        const char *process = argv[1];
        const char *dylib_path = argv[2];
        pid_t pid = atoi(process);

        if (dylib_path[0] != '/') {
           // Convert to absolute path if it's relative
           char *absoluteDylibPath = convertToAbsolutePath(dylib_path);
           dylib_path = absoluteDylibPath; // Update to the absolute path
        }
        
        if (!is_valid_dylib(dylib_path)) {
           LOG_FATAL("Invalid dylib path: %s", dylib_path);
           return EXIT_FAILURE;
        }
        if (argc > 3)
        {
            if (strcmp(argv[3], "-name") == 0)
            {
                pid = find_pid_by_name(process);
            }
            if (strcmp(argv[3], "-spawn") == 0)
            {
                posix_spawnattr_t attr;
                posix_spawnattr_init(&attr);
                short flags = POSIX_SPAWN_START_SUSPENDED;
                posix_spawnattr_setflags(&attr, flags);
                // File actions for redirecting output
                posix_spawn_file_actions_t file_actions;
                posix_spawn_file_actions_init(&file_actions);
                // posix_spawn_file_actions_addopen(&file_actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
                // posix_spawn_file_actions_addopen(&file_actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
                int spawn_result = posix_spawn(&pid, process, &file_actions, &attr, (char *const[]){(char *)process, NULL}, environ);
                // int spawn_result = posix_spawn(&pid, process, NULL, NULL, (char *const[]){(char *)process, NULL}, environ);
                posix_spawnattr_destroy(&attr);
                if (spawn_result != 0) {
                    LOG_FATAL("Failed to spawn process: %s", strerror(spawn_result));
                    return EXIT_FAILURE;
                }
                LOG_OK("Launched target process (PID: %d)", pid);
                // wait_for_dyld(pid);
                kill(pid, SIGCONT);
            }
        }
        else
        {
            pid = atoi(process);
        }
        
        if (pid <= 0) {
           LOG_FATAL("Invalid PID or process not found: %s", process);
           return EXIT_FAILURE;
        }

        LOG_INFO("Injection target: PID %d", pid);
        LOG_INFO("Dylib path: %s", dylib_path);
        inject_dylib(pid, dylib_path);
        // sleep(5);
        LOG_INFO("Injection completed. Press any key to exit...");
        getchar();
    }
    return 0;
}
