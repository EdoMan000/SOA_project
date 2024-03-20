/*
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 * 
 * This module is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * @file reference-monitor.c 
 * @brief This is the main source for the Linux Kernel Module which implements
 *       a reference monitor based on a set of file system paths
 *
 * @author Edoardo Manenti
 *
 * @date March, 2024
 */

#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/list.h> 
#include <linux/namei.h> 
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/apic.h>
#include <asm/io.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include "lib/include/scth.h"
#include "utils/include/sha256_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edoardo Manenti <manenti000@gmail.com>");
MODULE_DESCRIPTION("reference monitor");

#define MODNAME "REFMON"

//===================================
#define CURRENT_EUID current->cred->euid.val
#define RECONF_ENABLED 1
#define RECONF_DISABLED 0
#define MAX_PASSW_LEN 32

typedef enum {
        REFMON_ACTION_PROTECT,
        REFMON_ACTION_UNPROTECT
} refmon_action_t;

enum refmon_ops {
        REFMON_SET_OFF = 0,
        REFMON_SET_ON = 1,
        REFMON_SET_REC_OFF = 2,
        REFMON_SET_REC_ON = 3,
        REFMON_STATE_QUERY = 4
};

typedef enum state {
        ON,
        OFF
} state_t;

typedef struct _refmon_path {
        struct path actual_path;
        struct list_head list;
} refmon_path;

typedef struct _refmon {
        state_t state;
        spinlock_t lock;
        char *password_digest;  
        struct list_head protected_paths;           
} refmon;

typedef struct _file_audit_log {
        pid_t tgid;
        pid_t tid;
        uid_t uid;
        uid_t euid;
        char *program_path;
        char *hash;  
        struct list_head list;
} file_audit_log;

refmon reference_monitor;

//===================================

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0);

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0,0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define AUDIT if(1)

static int the_refmon_reconf = RECONF_DISABLED;// this can be configured at run time via the sys file system -> 1 means the reference monitor can be currently reconfigured
module_param(the_refmon_reconf,int,0660);

static unsigned char the_refmon_secret[MAX_PASSW_LEN]; // +1 for null terminator
module_param_string(the_refmon_secret, the_refmon_secret, MAX_PASSW_LEN, 0);

//==================================

typedef struct {
        char *kernel_passw;
        char *kernel_path;
        int status; 
} copied_strings_t;

/**
 * Copies user-space strings `passw` and `path` to kernel space.
 * 
 * Allocates kernel memory for the copies, ensuring null-termination and 
 * validating lengths are within bounds. Frees allocated memory on errors.
 * 
 * @param user_passw Pointer to user-space password string.
 * @param user_path Pointer to user-space path string.
 * @return A structure containing:
 *   - `kernel_passw`: Kernel-space copy of `user_passw`. Caller must free.
 *   - `kernel_path`: Kernel-space copy of `user_path`. Caller must free.
 *   - `status`: 0 on success; -EFAULT for invalid lengths; -ENOMEM for allocation failures.
 */

static copied_strings_t copy_strings_from_user(const char __user *user_passw, const char __user *user_path) {
        copied_strings_t result;
        unsigned long passw_len, path_len;

        result.kernel_passw = NULL;
        result.kernel_path = NULL;
        result.status = 0;

        passw_len = strnlen_user(user_passw, PAGE_SIZE);
        path_len = strnlen_user(user_path, PAGE_SIZE);

        if (passw_len == 0 || passw_len > PAGE_SIZE || path_len == 0 || path_len > PAGE_SIZE) {
                result.status = -EFAULT;
                return result;
        }

        result.kernel_passw = kmalloc(passw_len, GFP_KERNEL);
        result.kernel_path = kmalloc(path_len, GFP_KERNEL);
        if (!result.kernel_passw || !result.kernel_path) {
                result.status = -ENOMEM;
                goto clean_up;
        }

        if (copy_from_user(result.kernel_passw, user_passw, passw_len) != 0 || copy_from_user(result.kernel_path, user_path, path_len) != 0) {
                result.status = -EFAULT;
                goto clean_up;
        }

        result.kernel_passw[passw_len - 1] = '\0';
        result.kernel_path[path_len - 1] = '\0';

        return result;

clean_up:
        kfree(result.kernel_passw);
        kfree(result.kernel_path);
        result.kernel_passw = NULL;
        result.kernel_path = NULL;
        return result;
}


/**
 * Check if a given path is already protected.
 * 
 * @param kern_path_str A kernel-space string representing the path to check.
 * @return 1 if the path is protected, 0 otherwise. -1 is returned if given path couldn't be resolved.
 */
static int is_path_protected(const char *kern_path_str) {
        struct path path_obj;
        refmon_path *entry;
        int ret = 0;

        if (kern_path(kern_path_str, LOOKUP_FOLLOW, &path_obj)) {
                return -1;
        }

        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                if (path_obj.dentry == entry->actual_path.dentry && path_obj.mnt == entry->actual_path.mnt) {
                ret = 1;
                break;
                }
        }
        path_put(&path_obj);
        return ret;
}

/**
 * Retrieve the entry for a given path if it is protected.
 * 
 * @param kern_path_str A kernel-space string representing the path to check.
 * @return A pointer to the refmon_path entry if the path is protected, NULL otherwise.
 */
static refmon_path *get_protected_path_entry(const char *kern_path_str) {
        struct path path_obj;
        refmon_path *entry;

        if (kern_path(kern_path_str, LOOKUP_FOLLOW, &path_obj)) {
                return NULL;
        }

        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                if (path_obj.dentry == entry->actual_path.dentry && path_obj.mnt == entry->actual_path.mnt) {
                path_put(&path_obj); 
                return entry;
                }
        }

        path_put(&path_obj);
        return NULL;
}

//==================================
#define MAX_LOGMSG_LEN 256

enum log_level {
        LOG_ERR,
        LOG_INFO
};

static void log_message(enum log_level level, const char *fmt, ...) {
        va_list args;
        char *log_msg;
        const char *log_level_str;

        switch (level) {
                case LOG_ERR:
                log_level_str = KERN_ERR;
                break;
                case LOG_INFO:
                log_level_str = KERN_INFO;
                break;
                default:
                log_level_str = KERN_DEFAULT; 
                break;
        }

        va_start(args, fmt);

        char formatted_msg[MAX_LOGMSG_LEN];
        vsnprintf(formatted_msg, sizeof(formatted_msg), fmt, args);

        va_end(args);

        log_msg = kasprintf(GFP_KERNEL, "%s%s: %s", log_level_str, MODNAME, formatted_msg);

        if (log_msg) {
                printk("%s", log_msg);
                kfree(log_msg);
        } else {
                printk("%s%s: Log message allocation failed\n", log_level_str, MODNAME);
        }
}

//==================================
struct kretprobe_data {
	struct file * file;
};

static int entry_handler_security_file_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct kretprobe_data *)ri->data;
	data->file = (struct file *)regs->di;
	return 0;
}

static int handler_security_file_open(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct kretprobe_data *data = (struct kretprobe_data *)ri->data;
        struct file* file = data->file;

        if (file) {
                if (file->f_mode & FMODE_WRITE) {
                        refmon_path *entry;
                        struct path file_path = file->f_path;
                        char *file_path_buff = kmalloc(PATH_MAX, GFP_KERNEL);
                        if (!file_path_buff) {
                                log_message(LOG_ERR, "FAILED TO BLOCK ILLEGAL ACCESS! (Couldn't allocate buffer to store pathname.)\n", file_path);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
                                regs->ax = (unsigned long) -ENOMEM;
#else
                                regs_set_return_value(regs, -ENOMEM);
#endif
                                return 0;
                        }
                        char *pathname = d_path(&file_path, file_path_buff, PATH_MAX);
                        spin_lock(&reference_monitor.lock);
                        if(is_path_protected(pathname)){
                                log_message(LOG_INFO, "FILE '%s' WAS ACCESSED WHILE BEING PROTECTED! ABORTING OPERATION AND REGISTERING ILLEGAL ACCESS!\n", pathname);
                                spin_unlock(&reference_monitor.lock);
                                kfree(file_path_buff);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0)
                                regs->ax = (unsigned long) -EACCES;
#else
                                regs_set_return_value(regs, -EACCES);
#endif
                                return 0;
                        }
                        spin_unlock(&reference_monitor.lock);
                        kfree(file_path_buff);
                }
        }

        return 0; 
}


static struct kretprobe krp = {
        .kp.symbol_name     = "security_file_open",
        .handler            = handler_security_file_open,
        .entry_handler      = entry_handler_security_file_open,
        .data_size          = sizeof(struct kretprobe_data),
};

int register_my_kretprobe(void) {
        int ret;
        ret = register_kretprobe(&krp);
        if (ret < 0) {
                log_message(LOG_ERR, "Failed to register kretprobe: %d\n",  ret);
                return ret;
        }
        log_message(LOG_INFO, "Kprobe registered\n");
        return 0;
}

void unregister_my_kretprobe(void) {
        unregister_kretprobe(&krp);
        log_message(LOG_INFO, "kretprobe unregistered\n");
}

//==================================

static const char* state_to_string(state_t state, int opposite) {
        switch (state) {
                case ON:
                        if(opposite){
                                return "OFF";
                        }else{
                                return "ON";
                        }
                case OFF:
                        if(opposite){
                                return "ON";
                        }else{
                                return "OFF";
                        }
                default:
                        return "Unknown State";
        }
}

static void update_state(state_t new_state, int reconf){
        const char *state_str = state_to_string(new_state, 0);
        const char *opposite_state_str = state_to_string(new_state, 1);
        if(reference_monitor.state == new_state && the_refmon_reconf == reconf){
                if(reconf != RECONF_ENABLED){
                        log_message(LOG_INFO, "The reference monitor was already %s. Nothing done.\n", state_str);
                }else{
                        log_message(LOG_INFO, "The reference monitor was already REC-%s. Nothing done.\n", state_str);
                }
        }else{
                if (reference_monitor.state != new_state) {
                        if(new_state == ON){
                                register_my_kretprobe();
                        }else{
                                unregister_my_kretprobe();
                        }
                        reference_monitor.state = new_state;
                        if (the_refmon_reconf != reconf) {
                                the_refmon_reconf = reconf;
                                if(reconf != RECONF_ENABLED){
                                        log_message(LOG_INFO, "The reference monitor was REC-%s. It is now %s.\n", opposite_state_str, state_str);
                                }else{
                                        log_message(LOG_INFO, "The reference monitor was %s. It is now REC-%s.\n", opposite_state_str, state_str);
                                }
                        } else {
                                if(reconf != RECONF_ENABLED){
                                        log_message(LOG_INFO, "The reference monitor was %s. It is now %s.\n", opposite_state_str, state_str);
                                }else{
                                        log_message(LOG_INFO, "The reference monitor was REC-%s. It is now REC-%s.\n", opposite_state_str, state_str);
                                }
                        }
                } else {
                        the_refmon_reconf = reconf;
                        log_message(LOG_INFO, "The reference monitor was REC-%s. It is now %s.\n", state_str, state_str);
                }
        }
}

static void print_current_refmon_state(void){
        char *buf;
        char *pathname;
        struct path path;
        if (the_refmon_reconf != 1) {
                if (reference_monitor.state == ON) {
                        log_message(LOG_INFO, "Current state is ON.\n");
                } else {
                        log_message(LOG_INFO, "Current state is OFF.\n");
                }
        } else {
                if (reference_monitor.state == ON) {
                        log_message(LOG_INFO, "Current state is REC-ON.\n");
                } else {
                        log_message(LOG_INFO, "Current state is REC-OFF.\n");
                }
        }
        if (list_empty(&reference_monitor.protected_paths)) {
                log_message(LOG_INFO, "Currently there are no protected paths.\n");
        } else {
                log_message(LOG_INFO, "Listing all protected paths:\n");
                refmon_path *entry;
                list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                        path = entry->actual_path;
                        buf = (char *)__get_free_page(GFP_KERNEL);
                        if (!buf) {
                                log_message(LOG_ERR, "Failed to allocate memory for path buffer\n");
                                break;
                        }
                        pathname = d_path(&path, buf, PAGE_SIZE);
                        if (IS_ERR(pathname)) {
                                log_message(LOG_ERR, "Error converting path to string\n");
                        } else {
                                log_message(LOG_INFO, "Protected path: %s\n", pathname);
                        }
                        free_page((unsigned long)buf);
                }
        }

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _refmon_manage, int, code){
#else
asmlinkage long sys_refmon_manage(int code){
#endif
        int ret = 0;
        log_message(LOG_INFO, "sys_refmon_manage called from thread %d\n",current->pid);

        spin_lock(&reference_monitor.lock);

        if(CURRENT_EUID != 0){
                log_message(LOG_ERR, "Current EUID is not 0\n");
                ret = -1;
                goto exit;
        }
        switch (code)
        {
                case REFMON_SET_OFF:
                        update_state(OFF, 0);
                        break;
                case REFMON_SET_ON:
                        update_state(ON, 0);
                        break;
                case REFMON_SET_REC_OFF:
                        update_state(OFF, 1);
                        break;
                case REFMON_SET_REC_ON:
                        update_state(ON, 1);
                        break;
                case REFMON_STATE_QUERY:
                        print_current_refmon_state();
                        break;
                default:
                        log_message(LOG_ERR, "Provided code is unknown.\n");
                        ret = -EINVAL;
                        break;
        }
exit:
        spin_unlock(&reference_monitor.lock);
        return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(3, _refmon_reconfigure, refmon_action_t, action, char __user *, passw, char __user *, path){
#else
asmlinkage long sys_refmon_reconfigure(refmon_action_t action, char __user *passw, char __user *path){
#endif
        int ret = 0;
        pid_t curr_pid = current->pid;

        refmon_path *the_refmon_path;

        copied_strings_t copied = copy_strings_from_user(passw, path);
        if (copied.status != 0) {
                return copied.status;
        }

        char *kernel_passw = copied.kernel_passw;
        char *kernel_path = copied.kernel_path;

        char* action_str;
        switch (action) {
                case REFMON_ACTION_PROTECT:
                        action_str = "REFMON_ACTION_PROTECT";
                        break;
                case REFMON_ACTION_UNPROTECT:
                        action_str = "REFMON_ACTION_UNPROTECT";
                        break;
                default:
                        log_message(LOG_ERR, "sys_refmon_reconfigure(%s, %s, %s) called from thread %d.\n", "REFMON_ACTION_INVALID", kernel_passw, kernel_path, curr_pid);
                        kfree(kernel_passw);
                        kfree(kernel_path);
                        return -EINVAL;
        }
        log_message(LOG_INFO, "sys_refmon_reconfigure(%s, %s, %s) called from thread %d.\n", action_str, kernel_passw, kernel_path, curr_pid);

        spin_lock(&reference_monitor.lock);

        // Common checks
        if(CURRENT_EUID != 0) {
                log_message(LOG_ERR, "Current EUID is not 0.\n");
                ret = -1;
                goto exit;
        } else if (verify_password(kernel_passw, strlen(kernel_passw), reference_monitor.password_digest) != 0) {
                log_message(LOG_ERR, "Authentication failed.\n");
                ret = -1;
                goto exit;
        } else if (the_refmon_reconf != 1) {
                log_message(LOG_ERR, "Reconfiguration is not enabled.\n");
                ret = -1;
                goto exit;
        } else {
                // Action-specific logic
                switch (action) {
                case REFMON_ACTION_PROTECT:
                        switch (is_path_protected(kernel_path))
                        {
                                case 0:
                                        the_refmon_path = kmalloc(sizeof(*the_refmon_path), GFP_KERNEL);
                                        if (!the_refmon_path) {
                                                log_message(LOG_ERR, "Couldn't allocate memory for new refmon path.\n");
                                                ret = -1;
                                                goto exit;
                                        }
                                        kern_path(kernel_path, LOOKUP_FOLLOW, &the_refmon_path->actual_path);
                                        list_add(&the_refmon_path->list, &reference_monitor.protected_paths);
                                        log_message(LOG_INFO, "Starting to monitor new path '%s'\n", kernel_path);
                                        ret = 0;
                                        goto exit;
                                case 1:
                                        log_message(LOG_ERR, "Path '%s' is already protected. Nothing done...\n", kernel_path);
                                        ret = -1;
                                        goto exit;
                                default:
                                        log_message(LOG_ERR, "Path '%s' does not exist or is not a valid path. Nothing done...\n", kernel_path);
                                        ret = -1;
                                        goto exit;
                        }
                        break;
                case REFMON_ACTION_UNPROTECT:
                        switch (is_path_protected(kernel_path))
                        {
                                case 0:
                                        log_message(LOG_ERR, "Path '%s' does not show up as one of the monitored paths. Nothing done...\n", kernel_path);
                                        ret = -1;
                                        goto exit;
                                case 1:
                                        the_refmon_path = get_protected_path_entry(kernel_path);
                                        list_del(&the_refmon_path->list);
                                        path_put(&the_refmon_path->actual_path); 
                                        kfree(the_refmon_path);
                                        log_message(LOG_INFO, "Path '%s' won't be protected anymore.\n", kernel_path);
                                        ret = 0;
                                        goto exit;
                                default:
                                        log_message(LOG_ERR, "Path '%s' does not exist or is not a valid path. Nothing done...\n", kernel_path);
                                        ret = -1;
                                        goto exit;
                        }
                        break;
                default:
                        log_message(LOG_ERR, "Invalid action.\n");
                        ret = -EINVAL;
                        break;
                }
        }

exit:
        spin_unlock(&reference_monitor.lock);
        kfree(kernel_passw);
        kfree(kernel_path);
        return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_refmon_manage = (unsigned long) __x64_sys_refmon_manage;
long sys_refmon_reconfigure = (unsigned long) __x64_sys_refmon_reconfigure;
#else
#endif

int init_module(void) {
        int i;
        int ret;
        AUDIT
        log_message(LOG_INFO, "starting up!\n");

        //TODO vedere se necessario controllo sulla lunghezza eccessiva di the_refmon_secret

        //init reference monitor struct
        reference_monitor.state = ON; //scegliere se mettere off e spostare il settaggio delle kprobes
        spin_lock_init(&reference_monitor.lock);
        INIT_LIST_HEAD(&reference_monitor.protected_paths);
        reference_monitor.password_digest = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if(!reference_monitor.password_digest){
                log_message(LOG_ERR, "memory allocation failed for storing password digest\n");
                return -ENOMEM;
        }
        int sha_ret = compute_sha256(the_refmon_secret, strlen(the_refmon_secret), reference_monitor.password_digest);
        if (sha_ret){
                log_message(LOG_ERR, "password encryption failed\n");
                return sha_ret;
        }

        //hack syscall table
        if (the_syscall_table == 0x0){
                log_message(LOG_ERR, "cannot manage sys_call_table address set to 0x0\n");
                return -1;
        }
        
        log_message(LOG_INFO, "received sys_call_table address %px\n",(void*)the_syscall_table);
        log_message(LOG_INFO, "initializing - hacked entries %d\n",HACKED_ENTRIES);

        new_sys_call_array[0] = (unsigned long)sys_refmon_manage;
        new_sys_call_array[1] = (unsigned long)sys_refmon_reconfigure;
        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);
        if (ret != HACKED_ENTRIES){
                log_message(LOG_ERR, "could not hack %d entries (just %d)\n",HACKED_ENTRIES,ret);
                return -1;
        }
        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }
        protect_memory();
        log_message(LOG_INFO, "all new system-calls correctly installed on sys-call table\n");

        //TODO register kprobes
        register_my_kretprobe();
        log_message(LOG_INFO, "all kretprobes correctly registered\n");

        return 0;

}

void cleanup_module(void) {
        int i;
        log_message(LOG_INFO, "shutting down\n");

        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        log_message(LOG_INFO, "sys-call table restored to its original content\n");

        //TODO unnregister kprobes
        unregister_my_kretprobe();
        log_message(LOG_INFO, "all kretprobes correctly unregistered\n");
}


