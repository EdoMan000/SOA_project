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
// #define MAX_PATH_LEN 256
// #define MAX_PROGRAM_PATH_LEN 256
// #define MAX_PASSW_LEN 32

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

unsigned long new_sys_call_array[] = {0x0,0x0,0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

#define AUDIT if(1)

static int the_refmon_reconf = RECONF_DISABLED;// this can be configured at run time via the sys file system -> 1 means the reference monitor can be currently reconfigured
module_param(the_refmon_reconf,int,0660);

static unsigned char the_refmon_secret[32]; // +1 for null terminator
module_param_string(the_refmon_secret, the_refmon_secret, 32, 0);

//==================================

struct open_flags {
        int open_flag;
        umode_t mode;
        int acc_mode;
        int intent;
        int lookup_flags;
};

// struct filename {
// 	const char		*name;	/* pointer to actual string */
// 	const __user char	*uptr;	/* original userland pointer */
// 	int			refcnt;
// 	struct audit_names	*aname;
// 	const char		iname[];
// };

// struct file *do_filp_open(int dfd, struct filename *pathname,
// 		const struct open_flags *op)
// {
// 	struct nameidata nd;
// 	int flags = op->lookup_flags;
// 	struct file *filp;

// 	set_nameidata(&nd, dfd, pathname, NULL);
// 	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
// 	if (unlikely(filp == ERR_PTR(-ECHILD)))
// 		filp = path_openat(&nd, op, flags);
// 	if (unlikely(filp == ERR_PTR(-ESTALE)))
// 		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
// 	restore_nameidata();
// 	return filp;
// }

static int pre_handler_do_filp_open(struct kprobe *p, struct pt_regs *regs) {
        struct filename *pathname = (struct filename *)regs->si;
        struct open_flags *op = (struct open_flags *)regs->dx;
        struct path path_obj;
        refmon_path *entry;

        // Check if the file is being opened in write mode
        if (op && (op->open_flag & (O_WRONLY | O_RDWR))) {
                // Resolve the path to check against protected paths
                if (kern_path(pathname->name, LOOKUP_FOLLOW, &path_obj) == 0) {
                        spin_lock_irq(&reference_monitor.lock);
                        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                                if (path_obj.dentry == entry->actual_path.dentry && path_obj.mnt == entry->actual_path.mnt) {
                                        pr_err("%s: File '%s' ACCESSED WHILE BEING PROTECTED! ABORTING OPERATION AND REGISTERING ILLEGAL ACCESS!\n", MODNAME, pathname->name);
                                        op->open_flag &= ~(O_WRONLY | O_RDWR);
                                        op->open_flag |= O_RDONLY;
                                }
                        }
                        spin_unlock_irq(&reference_monitor.lock);
                        path_put(&path_obj);
                }
        }

        return 0; // Return 0 to proceed with the original function execution
}

static struct kprobe kp = {
    .symbol_name    = "do_filp_open",
    .pre_handler    = pre_handler_do_filp_open,
};

int register_my_kprobe(void) {
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("%s: Failed to register kprobe: %d\n", MODNAME,  ret);
        return ret;
    }
    pr_info("%s: Kprobe registered\n", MODNAME);
    return 0;
}

void unregister_my_kprobe(void) {
    unregister_kprobe(&kp);
    pr_info("%s: Kprobe unregistered\n", MODNAME);
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
                        pr_info("%s: The reference monitor was already %s. Nothing done.\n",MODNAME, state_str);
                }else{
                        pr_info("%s: The reference monitor was already REC-%s. Nothing done.\n",MODNAME, state_str);
                }
        }else{
                if (reference_monitor.state != new_state) {
                        if(new_state == ON){
                                register_my_kprobe();
                        }else{
                                unregister_my_kprobe();
                        }
                        reference_monitor.state = new_state;
                        if (the_refmon_reconf != reconf) {
                                the_refmon_reconf = reconf;
                                if(reconf != RECONF_ENABLED){
                                        pr_info("%s: The reference monitor was REC-%s. It is now %s.\n", MODNAME, opposite_state_str, state_str);
                                }else{
                                        pr_info("%s: The reference monitor was %s. It is now REC-%s.\n", MODNAME, opposite_state_str, state_str);
                                }
                        } else {
                                if(reconf != RECONF_ENABLED){
                                        pr_info("%s: The reference monitor was %s. It is now %s.\n", MODNAME, opposite_state_str, state_str);
                                }else{
                                        pr_info("%s: The reference monitor was REC-%s. It is now REC-%s.\n", MODNAME, opposite_state_str, state_str);
                                }
                        }
                } else {
                        the_refmon_reconf = reconf;
                        pr_info("%s: The reference monitor was REC-%s. It is now %s.\n", MODNAME, state_str, state_str);
                }
        }
}

static void print_current_refmon_state(void){
        char *buf;
        char *pathname;
        struct path path;
        if (the_refmon_reconf != 1) {
                if (reference_monitor.state == ON) {
                        pr_info("%s: Current state is ON.\n", MODNAME);
                } else {
                        pr_info("%s: Current state is OFF.\n", MODNAME);
                }
        } else {
                if (reference_monitor.state == ON) {
                        pr_info("%s: Current state is REC-ON.\n", MODNAME);
                } else {
                        pr_info("%s: Current state is REC-OFF.\n", MODNAME);
                }
        }
        if (list_empty(&reference_monitor.protected_paths)) {
                pr_info("%s: Currently there are no protected paths.\n", MODNAME);
        } else {
                pr_info("%s: Listing all protected paths:\n", MODNAME);
                refmon_path *entry;
                list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                        path = entry->actual_path;
                        buf = (char *)__get_free_page(GFP_KERNEL);
                        if (!buf) {
                                pr_err("%s: Failed to allocate memory for path buffer\n", MODNAME);
                                break;
                        }
                        pathname = d_path(&path, buf, PAGE_SIZE);
                        if (IS_ERR(pathname)) {
                                pr_err("%s: Error converting path to string\n", MODNAME);
                        } else {
                                pr_info("%s: Protected path: %s\n", MODNAME, pathname);
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
        AUDIT
        pr_info("%s: sys_refmon_manage called from thread %d\n",MODNAME,current->pid);

        spin_lock_irq(&reference_monitor.lock);

        if(CURRENT_EUID != 0){
                pr_err("%s: Current EUID is not 0\n", MODNAME);
                spin_unlock_irq(&reference_monitor.lock);
                return -1;
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
                        pr_err("%s: Provided code is unknown.\n",MODNAME);
                        spin_unlock_irq(&reference_monitor.lock);
                        return -EINVAL;
        }
        spin_unlock_irq(&reference_monitor.lock);
        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _refmon_protect, char __user *, passw, char __user *, new_path){
#else
asmlinkage long sys_refmon_protect(char __user *passw, char __user *new_path){
#endif
        pid_t curr_pid = current->pid;
        char *kern_passw = NULL;
        char *kern_new_path = NULL;
        char* err_msg;
        unsigned long passw_len, new_path_len;
        refmon_path *new_refmon_path;

        passw_len = strnlen_user(passw, PAGE_SIZE);
        new_path_len = strnlen_user(new_path, PAGE_SIZE);

        if (passw_len > PAGE_SIZE || new_path_len > PAGE_SIZE || passw_len == 0 || new_path_len == 0) {
                return -EFAULT;
        }

        kern_passw = kmalloc(passw_len, GFP_KERNEL);
        kern_new_path = kmalloc(new_path_len, GFP_KERNEL);
        if (!kern_passw || !kern_new_path) {
                kfree(kern_passw);
                kfree(kern_new_path);
                return -ENOMEM;
        }

        if (copy_from_user(kern_passw, passw, passw_len) != 0 || copy_from_user(kern_new_path, new_path, new_path_len) != 0) {
                kfree(kern_passw);
                kfree(kern_new_path);
                return -ENOMEM;
        }

        kern_passw[passw_len - 1] = '\0';
        kern_new_path[new_path_len - 1] = '\0';

        pr_info("%s: sys_refmon_protect(%s, %s) called from thread %d\n", MODNAME, kern_passw, kern_new_path, curr_pid);
        // pr_info("%s: PASSWORD: '%s' | LEN '%ld'\n",MODNAME, kern_passw, strlen(kern_passw));
        // print_hex_dump(KERN_DEBUG, "DIGEST", DUMP_PREFIX_NONE, 16, 1, reference_monitor.password_digest, sizeof(reference_monitor.password_digest), true);

        spin_lock_irq(&reference_monitor.lock);
        
        if(CURRENT_EUID != 0){
                err_msg = "Current EUID is not 0";
                goto operation_failed;
        }else if (verify_password(kern_passw, strlen(kern_passw), reference_monitor.password_digest)  != 0)
        {
                err_msg = "Authentication failed";
                goto operation_failed;
        }else if (the_refmon_reconf != 1) 
        {
                err_msg = "Reconfiguration is not enabled";
                goto operation_failed;
        }
        new_refmon_path = kmalloc(sizeof(*new_refmon_path), GFP_KERNEL);
        if (!new_refmon_path) {
                err_msg = "Couldn't allocate memory for new refmon path";
                goto operation_failed;
        }
        if (kern_path(kern_new_path, LOOKUP_FOLLOW, &new_refmon_path->actual_path)) 
        {
                err_msg = "Invalid path was given";
                kfree(new_refmon_path);
                goto operation_failed;
        }
        list_add(&new_refmon_path->list, &reference_monitor.protected_paths);
        AUDIT
        pr_info("%s: Starting to monitor new path '%s'\n", MODNAME, kern_new_path);

        kfree(kern_passw);
        kfree(kern_new_path);
        spin_unlock_irq(&reference_monitor.lock);
        return 0;

operation_failed:
        kfree(kern_passw);
        kfree(kern_new_path);
        spin_unlock_irq(&reference_monitor.lock);
        pr_err("%s: %s\n",MODNAME,err_msg);
        return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _refmon_unprotect, char __user *, passw, char __user *, old_path){
#else
asmlinkage long sys_refmon_unprotect(char __user *passw, char __user *old_path){
#endif
        pid_t curr_pid = current->pid;
        char *kern_passw = NULL;
        char *kern_old_path = NULL;
        char* err_msg;
        unsigned long passw_len, old_path_len;
        struct path path_obj;
        refmon_path *entry, *tmp;

	passw_len = strnlen_user(passw, PAGE_SIZE);
        old_path_len = strnlen_user(old_path, PAGE_SIZE);

        if (passw_len > PAGE_SIZE || old_path_len > PAGE_SIZE || passw_len == 0 || old_path_len == 0) {
                return -EFAULT;
        }

        kern_passw = kmalloc(passw_len, GFP_KERNEL);
        kern_old_path = kmalloc(old_path_len, GFP_KERNEL);
        if (!kern_passw || !kern_old_path) {
                kfree(kern_passw);
                kfree(kern_old_path);
                return -ENOMEM;
        }

        if (copy_from_user(kern_passw, passw, passw_len) != 0 || copy_from_user(kern_old_path, old_path, old_path_len) != 0) {
                kfree(kern_passw);
                kfree(kern_old_path);
                return -ENOMEM;
        }

        kern_passw[passw_len - 1] = '\0';
        kern_old_path[old_path_len - 1] = '\0';

        pr_info("%s: sys_refmon_unprotect(%s, %s) called from thread %d\n", MODNAME, kern_passw, kern_old_path, curr_pid);
        // pr_info("%s: PASSWORD: '%s' | LEN '%ld'\n",MODNAME, kern_passw, strlen(kern_passw));
        // print_hex_dump(KERN_DEBUG, "DIGEST", DUMP_PREFIX_NONE, 16, 1, reference_monitor.password_digest, sizeof(reference_monitor.password_digest), true);

        spin_lock_irq(&reference_monitor.lock);
        
        if(CURRENT_EUID != 0){
                err_msg = "Current EUID is not 0";
                goto operation_failed;
        }else if (verify_password(kern_passw, strlen(kern_passw), reference_monitor.password_digest)  != 0)
        {
                err_msg = "Authentication failed";
                goto operation_failed;
        }else if (the_refmon_reconf != 1) 
        {
                err_msg = "Reconfiguration is not enabled";
                goto operation_failed;
        }else if (kern_path(kern_old_path, LOOKUP_FOLLOW, &path_obj))
        {
                err_msg = "Invalid path was given";
                goto operation_failed;
        }

        list_for_each_entry_safe(entry, tmp, &reference_monitor.protected_paths, list) {
                if (path_obj.dentry == entry->actual_path.dentry && path_obj.mnt == entry->actual_path.mnt) {
                        list_del(&entry->list);
                        path_put(&entry->actual_path); 
                        pr_info("%s: Path '%s' won't be protected anymore\n", MODNAME, kern_old_path);
                        kfree(entry);
                        kfree(kern_passw);
                        kfree(kern_old_path);
                        spin_unlock_irq(&reference_monitor.lock);
                        return 0;
                }
        }

        pr_err("%s: Path '%s' does not show up as one of the monitored paths\n", MODNAME, kern_old_path);
        kfree(kern_passw);
        kfree(kern_old_path);
        path_put(&path_obj);
        spin_unlock_irq(&reference_monitor.lock);
        return -ENOENT;

operation_failed:
        kfree(kern_passw);
        kfree(kern_old_path);
        spin_unlock_irq(&reference_monitor.lock);
        pr_err("%s: %s\n",MODNAME,err_msg);
        return -1;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_refmon_manage = (unsigned long) __x64_sys_refmon_manage;
long sys_refmon_protect = (unsigned long) __x64_sys_refmon_protect;
long sys_refmon_unprotect = (unsigned long) __x64_sys_refmon_unprotect;
#else
#endif

int init_module(void) {
        int i;
        int ret;
        AUDIT
        pr_info("%s: starting up\n",MODNAME);

        //TODO vedere se necessario controllo sulla lunghezza eccessiva di the_refmon_secret

        //init reference monitor struct
        reference_monitor.state = ON; //scegliere se mettere off e spostare il settaggio delle kprobes
        spin_lock_init(&reference_monitor.lock);
        INIT_LIST_HEAD(&reference_monitor.protected_paths);
        reference_monitor.password_digest = kmalloc(32, GFP_KERNEL);
        if(!reference_monitor.password_digest){
                pr_err("%s: memory allocation failed for storing password digest\n",MODNAME);
                return -ENOMEM;
        }
        int sha_ret = compute_sha256(the_refmon_secret, strlen(the_refmon_secret), reference_monitor.password_digest);
        if (sha_ret){
                pr_err("%s: password encryption failed\n",MODNAME);
                return sha_ret;
        }
        pr_info("%s: starting up\n",MODNAME);
        // pr_info("%s: PASSWORD: '%s' | LEN '%d'\n", MODNAME, the_refmon_secret, strlen(the_refmon_secret));
        // print_hex_dump(KERN_DEBUG, "DIGEST", DUMP_PREFIX_NONE, 16, 1, reference_monitor.password_digest, sizeof(reference_monitor.password_digest), true);

        //hack syscall table
        if (the_syscall_table == 0x0){
                pr_err("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
                return -1;
        }
        AUDIT{
           pr_info("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
           pr_info("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
        }
        new_sys_call_array[0] = (unsigned long)sys_refmon_manage;
        new_sys_call_array[1] = (unsigned long)sys_refmon_protect;
        new_sys_call_array[2] = (unsigned long)sys_refmon_unprotect;
        ret = get_entries(restore,HACKED_ENTRIES,(unsigned long*)the_syscall_table,&the_ni_syscall);
        if (ret != HACKED_ENTRIES){
                pr_err("%s: could not hack %d entries (just %d)\n",MODNAME,HACKED_ENTRIES,ret);
                return -1;
        }
        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }
        protect_memory();
        AUDIT
        pr_info("%s: all new system-calls correctly installed on sys-call table\n",MODNAME);

        //TODO register kprobes
        register_my_kprobe();
        AUDIT
        pr_info("%s: all kprobes correctly registered\n",MODNAME);

        return 0;

}

void cleanup_module(void) {
        int i;
        AUDIT
        pr_info("%s: shutting down\n",MODNAME);

        unprotect_memory();
        for(i=0;i<HACKED_ENTRIES;i++){
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        AUDIT
        pr_info("%s: sys-call table restored to its original content\n",MODNAME);

        //TODO unnregister kprobes
        unregister_my_kprobe();
        AUDIT
        pr_info("%s: all kprobes correctly unregistered\n",MODNAME);
}


