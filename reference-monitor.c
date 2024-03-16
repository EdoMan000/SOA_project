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
// #define MAX_PATH_LEN 256
// #define MAX_PROGRAM_PATH_LEN 256
// #define MAX_PASSW_LEN 32

typedef struct _refmon_path {
    char *path;
    struct list_head list;
} refmon_path;

typedef struct _refmon {
    enum {
        ON,
        OFF
    } state;
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

static int enable_reconfiguration = 0;// this can be configured at run time via the sys file system -> 1 means the reference monitor can be currently reconfigured
module_param(enable_reconfiguration,int,0660);

// char the_refmon_secret[MAX_PASSW_LEN];
// memset(the_refmon_secret, 0, sizeof(the_refmon_secret));
// module_param_string(the_refmon_secret, the_refmon_secret, MAX_PASSW_LEN, 0);
static unsigned char the_refmon_secret[32]; // +1 for null terminator
module_param_string(the_refmon_secret, the_refmon_secret, 32, 0);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(1, _refmon_toggle, int, code){
#else
asmlinkage long sys_refmon_toggle(int code){
#endif
        AUDIT
        pr_info("%s: sys_refmon_toggle called from thread %d\n",MODNAME,current->pid);

        spin_lock(&reference_monitor.lock);

        if(CURRENT_EUID != 0){
                pr_err("%s: Current EUID is not 0\n", MODNAME);
                spin_unlock(&reference_monitor.lock);
                return -1;
        }
        switch (code)
        {
        case 0:
                if(reference_monitor.state != OFF){
                        //TODO disattiva kprobes
                        reference_monitor.state = OFF;
                        AUDIT
                        pr_info("%s: The reference monitor was turned OFF.\n",MODNAME);
                }else{
                        AUDIT
                        pr_info("%s: The reference monitor was already turned OFF. Nothing done.\n",MODNAME);
                }
                break;
        case 1:
                if(reference_monitor.state != ON){
                        //TODO attiva kprobes
                        reference_monitor.state = ON;
                        AUDIT
                        pr_info("%s: The reference monitor was turned ON.\n",MODNAME);
                }else{
                        AUDIT
                        pr_info("%s: The reference monitor was already turned ON. Nothing done.\n",MODNAME);
                }
                break;
        default:
                AUDIT
                pr_err("%s: Unrecognised state code, failed to update state.\n",MODNAME);
                spin_unlock(&reference_monitor.lock);
                return -1;
        }
        spin_unlock(&reference_monitor.lock);
        return 0;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _refmon_protect, char __user *, passw, char __user *, new_path){
#else
asmlinkage long sys_refmon_protect(char __user *passw, char __user *new_path){
#endif
	AUDIT
        pr_info("%s: sys_refmon_protect(%s, %s) called from thread %d\n",MODNAME,passw,new_path,current->pid);

        spin_lock(&reference_monitor.lock);
        
        char* err_msg;
        if(CURRENT_EUID != 0){
                err_msg = "Current EUID is not 0";
                goto operation_failed;
        }else if (verify_password(passw, strlen(passw), reference_monitor.password_digest)  != 0)
        {
                err_msg = "Authentication failed";
                goto operation_failed;
        }else if (enable_reconfiguration == 0) //TODO check atomic_read
        {
                err_msg = "Reconfiguration is not enabled";
                goto operation_failed;
        }
        // //TODO aggiungere caso di path non valido
        // // else if ()
        // // {
        // //         err_msg = "";
        // //         goto operation_failed;
        // // }
        
        // struct refmon_path *new_refmon_path = kmalloc(sizeof(struct refmon_path), GFP_KERNEL);
        // if (!new_refmon_path) {
        //         pr_err("%s: Memory allocation failed for new refmon_path\n",MODNAME);
        //         return -1;
        // }
        
        // new_refmon_path->path = new_path;
        // INIT_LIST_HEAD(&new_refmon_path->list);
        // list_add_tail(&new_refmon_path->list, &reference_monitor.protected_paths);

        spin_unlock(&reference_monitor.lock);
        AUDIT
        pr_info("%s: Starting to monitor new path '%s'\n", MODNAME, new_path);

        return 0;

operation_failed:
        spin_unlock(&reference_monitor.lock);
        pr_err("%s: %s\n",MODNAME,err_msg);
        return -1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
__SYSCALL_DEFINEx(2, _refmon_unprotect, char __user *, passw, char __user *, old_path){
#else
asmlinkage long sys_refmon_unprotect(char __user *passw, char __user *old_path){
#endif
	AUDIT
        pr_info("%s: sys_refmon_unprotect(%s, %s) called from thread %d\n",MODNAME,passw,old_path,current->pid);

        spin_lock(&reference_monitor.lock);
        
        char* err_msg;
        if(CURRENT_EUID != 0){
                err_msg = "Current EUID is not 0";
                goto operation_failed;
        }else if (verify_password(passw, strlen(passw), reference_monitor.password_digest) != 0)
        {
                err_msg = "Authentication failed";
                goto operation_failed;
        }else if (enable_reconfiguration == 0)//TODO check atomic_read
        {
                err_msg = "Reconfiguration is not enabled";
                goto operation_failed;
        }
        // //TODO aggiungere caso di path non valido
        // // else if ()
        // // {
        // //         err_msg = "";
        // //         goto operation_failed;
        // // }

        // struct refmon_path *entry, *tmp;

        // list_for_each_entry_safe(entry, tmp, &reference_monitor.protected_paths, list) {
        //         if (entry->path == old_path) {
        //                 list_del(&entry->list);
        //                 kfree(entry);

        //                 spin_unlock(&reference_monitor.lock);
        //                 AUDIT
        //                 pr_info("%s: Path '%s' will no longer be monitored\n", MODNAME, old_path);
        //                 return 0;
        //         }
        // }

        // AUDIT
        // pr_err("%s: Path '%s' does not show up as one of the monitored paths\n", MODNAME, old_path);

        spin_unlock(&reference_monitor.lock);
        return -1;

operation_failed:
        pr_err("%s: %s\n",MODNAME,err_msg);

        spin_unlock(&reference_monitor.lock);
        return -1;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
long sys_refmon_toggle = (unsigned long) __x64_sys_refmon_toggle;
long sys_refmon_protect = (unsigned long) __x64_sys_refmon_protect;
long sys_refmon_unprotect = (unsigned long) __x64_sys_refmon_unprotect;
#else
#endif

int init_module(void) {
        int i;
        int ret;
        AUDIT
        pr_info("%s: starting up\n",MODNAME);

        //TODO vedere se necessario controllo sulla lunghezza eccessiva
        if (the_refmon_secret == NULL){ 
                pr_err("%s: must insert a non-empty secret\n",MODNAME);
                return -1;
        }
        //init reference monitor struct
        reference_monitor.state = ON; //scegliere se mettere off e spostare il settaggio delle kprobes
        spin_lock_init(&reference_monitor.lock);
        INIT_LIST_HEAD(&reference_monitor.protected_paths);
        reference_monitor.password_digest = kmalloc( 32, GFP_KERNEL);
        int sha_ret = compute_sha256(the_refmon_secret, strlen(the_refmon_secret), reference_monitor.password_digest);
        if (sha_ret){
                pr_err("%s: password encryption failed\n",MODNAME);
                return sha_ret;
        }
        pr_info("%s: starting up\n",MODNAME);

        //hack syscall table
        if (the_syscall_table == 0x0){
                pr_err("%s: cannot manage sys_call_table address set to 0x0\n",MODNAME);
                return -1;
        }
        AUDIT{
           pr_info("%s: received sys_call_table address %px\n",MODNAME,(void*)the_syscall_table);
           pr_info("%s: initializing - hacked entries %d\n",MODNAME,HACKED_ENTRIES);
        }
        new_sys_call_array[0] = (unsigned long)sys_refmon_toggle;
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
        AUDIT
        pr_info("%s: all kprobes correctly unregistered\n",MODNAME);
}


