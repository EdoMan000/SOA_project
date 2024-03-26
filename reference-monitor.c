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
#include <linux/sched.h>
#include <linux/mount.h>    
#include <linux/dcache.h> 
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
        unsigned long inode;
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

static int the_refmon_reconf = RECONF_ENABLED;//starting as REC-OFF 
module_param(the_refmon_reconf,int,0660); //NB:] this can be configured at run time via the sys file system -> 1 means the reference monitor can be currently reconfigured

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
 * Check if a given inode corresponds to a protected file.
 * 
 * @param inode_num The inode number to check.
 * @return 1 if the inode is protected, 0 otherwise.
 */
static int is_inode_protected(unsigned long inode_num) {
        refmon_path *entry;

        list_for_each_entry(entry, &reference_monitor.protected_paths, list) {
                if (entry->inode == inode_num) {
                        return 1; 
                }
        }
        return 0; 
}

/**
 * Check if a given dentry corresponds to a protected file or it is situated in a protected path.
 * 
 * @param dentry The dentry to check.
 * @return 1 if the dentry or its path is protected, 0 otherwise.
 */
static int is_dentry_protected(struct dentry *dentry) {
        struct dentry *current_dentry = dentry;

        do {
                unsigned long inode_num = d_is_positive(current_dentry) ? d_inode(current_dentry)->i_ino : 0;

                if (inode_num && is_inode_protected(inode_num)) {
                        return 1; 
                }

                if (!IS_ROOT(current_dentry)) {
                        struct dentry *parent_dentry = dget_parent(current_dentry);

                        if (current_dentry != dentry) {
                                dput(current_dentry);
                        }

                        current_dentry = parent_dentry;
                }
        } while (!IS_ROOT(current_dentry));

        if (current_dentry != dentry) {
                dput(current_dentry);
        }

        return 0; 
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
struct krp_security_file_open_data {
	struct file * file;
};

static int entry_handler_security_file_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_file_open_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_file_open_data *)ri->data;
	data->file = (struct file *)regs->di;
	return 0;
}

static int handler_security_file_open(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_file_open_data *data = (struct krp_security_file_open_data *)ri->data;
        struct file* file = data->file;

        if (file) {
                if (file->f_mode & FMODE_WRITE) {
                        char *pathname;
                        char path_buf[PATH_MAX];
                        struct dentry *dentry = file->f_path.dentry;
                        pathname = dentry_path_raw(dentry, path_buf, PATH_MAX);
                        spin_lock(&reference_monitor.lock);
                        if(is_dentry_protected(dentry)){
                                log_message(LOG_INFO, "DENIED ACCESS TO FILE '%s' AS PATH IS BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", pathname);
                                spin_unlock(&reference_monitor.lock);
                                regs->ax = (unsigned long) -EACCES;
                                return 0;
                        }
                        spin_unlock(&reference_monitor.lock);
                }
        }
        return 0; 
}


static struct kretprobe krp_security_file_open = {
        .kp.symbol_name     = "security_file_open",
        .handler            = handler_security_file_open,
        .entry_handler      = entry_handler_security_file_open,
        .data_size          = sizeof(struct krp_security_file_open_data),
};

//==================================
struct krp_security_inode_rename_data {
        struct dentry *old_dentry;
        struct dentry *new_dentry;
};

static int entry_handler_security_inode_rename(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_inode_rename_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_inode_rename_data *)ri->data;
        data->old_dentry = (struct dentry *)regs->si;
        data->new_dentry = (struct dentry *)regs->cx;
	return 0;
}

static int handler_security_inode_rename(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_inode_rename_data *data = (struct krp_security_inode_rename_data *)ri->data;
        struct dentry *old_dentry = data->old_dentry;
        struct dentry *new_dentry = data->new_dentry;

        if (is_dentry_protected(old_dentry) || is_dentry_protected(new_dentry)) {
                char old_path_buf[PATH_MAX];
                char new_path_buf[PATH_MAX];
                char *old_pathname, *new_pathname;

                old_pathname = dentry_path_raw(old_dentry, old_path_buf, PATH_MAX);
                new_pathname = dentry_path_raw(new_dentry, new_path_buf, PATH_MAX);

                if (!IS_ERR(old_pathname) && !IS_ERR(new_pathname)) {
                        log_message(LOG_INFO, "DENIED RENAMING OF FILE/DIR FROM '%s' TO '%s' AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", old_pathname, new_pathname);
                } else {
                        log_message(LOG_INFO, "DENIED RENAMING OF FILE/DIR AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n");
                }
                regs->ax = (unsigned long) -EACCES;
                return 0;
        }

        return 0;
}


static struct kretprobe krp_security_inode_rename = {
        .kp.symbol_name     = "security_inode_rename",
        .handler            = handler_security_inode_rename,
        .entry_handler      = entry_handler_security_inode_rename,
        .data_size          = sizeof(struct krp_security_inode_rename_data),
};

//==================================
struct krp_security_inode_unlink_rmdir_data {
        struct dentry *dentry;
};

static int entry_handler_security_inode_unlink_rmdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_inode_unlink_rmdir_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_inode_unlink_rmdir_data *)ri->data;
        data->dentry = (struct dentry *)regs->si;
	return 0;
}

static int handler_security_inode_unlink_rmdir(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_inode_unlink_rmdir_data *data = (struct krp_security_inode_unlink_rmdir_data *)ri->data;
        struct dentry *dentry = data->dentry;

        if (is_dentry_protected(dentry)) {
                char path_buf[PATH_MAX];
                char *pathname;

                pathname = dentry_path_raw(dentry, path_buf, PATH_MAX);

                if (!IS_ERR(pathname)) {
                        log_message(LOG_INFO, "DENIED DELETION OF FILE/DIR '%s' AS PATH IS BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", pathname);
                } else {
                        log_message(LOG_INFO, "DENIED DELETION OF FILE/DIR AS PATH IS BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n");
                }
                regs->ax = (unsigned long) -EACCES;
                return 0;
        }

        return 0;
}


static struct kretprobe krp_security_inode_unlink = {
        .kp.symbol_name     = "security_inode_unlink",
        .handler            = handler_security_inode_unlink_rmdir,
        .entry_handler      = entry_handler_security_inode_unlink_rmdir,
        .data_size          = sizeof(struct krp_security_inode_unlink_rmdir_data),
};

static struct kretprobe krp_security_inode_rmdir = {
        .kp.symbol_name     = "security_inode_rmdir",
        .handler            = handler_security_inode_unlink_rmdir,
        .entry_handler      = entry_handler_security_inode_unlink_rmdir,
        .data_size          = sizeof(struct krp_security_inode_unlink_rmdir_data),
};

//==================================
struct krp_security_inode_create_mkdir_data {
        struct dentry *dentry;
};

static int entry_handler_security_inode_create_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_inode_create_mkdir_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_inode_create_mkdir_data *)ri->data;
        data->dentry = (struct dentry *)regs->si;
	return 0;
}

static int handler_security_inode_create_mkdir(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_inode_create_mkdir_data *data = (struct krp_security_inode_create_mkdir_data *)ri->data;
        struct dentry *dentry = data->dentry;

        if (is_dentry_protected(dentry)) {
                char path_buf[PATH_MAX];
                char *pathname;

                pathname = dentry_path_raw(dentry, path_buf, PATH_MAX);

                if (!IS_ERR(pathname)) {
                        log_message(LOG_INFO, "DENIED CREATION OF FILE/DIR '%s' AS PATH IS BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", pathname);
                } else {
                        log_message(LOG_INFO, "DENIED CREATION OF FILE/DIR AS PATH IS BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n");
                }
                regs->ax = (unsigned long) -EACCES;
                return 0;
        }

        return 0;
}


static struct kretprobe krp_security_inode_create = {
        .kp.symbol_name     = "security_inode_create",
        .handler            = handler_security_inode_create_mkdir,
        .entry_handler      = entry_handler_security_inode_create_mkdir,
        .data_size          = sizeof(struct krp_security_inode_create_mkdir_data),
};

static struct kretprobe krp_security_inode_mkdir = {
        .kp.symbol_name     = "security_inode_mkdir",
        .handler            = handler_security_inode_create_mkdir,
        .entry_handler      = entry_handler_security_inode_create_mkdir,
        .data_size          = sizeof(struct krp_security_inode_create_mkdir_data),
};

//==================================
struct krp_security_inode_link_data {
        struct dentry *old_dentry;
        struct dentry *new_dentry;
};

static int entry_handler_security_inode_link(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_inode_link_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_inode_link_data *)ri->data;
        data->old_dentry = (struct dentry *)regs->di;
        data->new_dentry = (struct dentry *)regs->dx;
	return 0;
}

static int handler_security_inode_link(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_inode_link_data *data = (struct krp_security_inode_link_data *)ri->data;
        struct dentry *old_dentry = data->old_dentry;
        struct dentry *new_dentry = data->new_dentry;

        if (is_dentry_protected(old_dentry) || is_dentry_protected(new_dentry)) {
                char old_path_buf[PATH_MAX];
                char new_path_buf[PATH_MAX];
                char *old_pathname, *new_pathname;

                old_pathname = dentry_path_raw(old_dentry, old_path_buf, PATH_MAX);
                new_pathname = dentry_path_raw(new_dentry, new_path_buf, PATH_MAX);

                if (!IS_ERR(old_pathname) && !IS_ERR(new_pathname)) {
                        log_message(LOG_INFO, "DENIED CREATION OF HARD-LINK '%s' TO FILE '%s' AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", new_pathname, old_pathname);
                } else {
                        log_message(LOG_INFO, "DENIED CREATION OF HARD-LINK TO FILE AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n");
                }
                regs->ax = (unsigned long) -EACCES;
                return 0;
        }

        return 0;
}


static struct kretprobe krp_security_inode_link = {
        .kp.symbol_name     = "security_inode_link",
        .handler            = handler_security_inode_link,
        .entry_handler      = entry_handler_security_inode_link,
        .data_size          = sizeof(struct krp_security_inode_link_data),
};

//==================================
struct krp_security_inode_symlink_data {
        struct dentry *dentry;
        char *old_name;
};

static int entry_handler_security_inode_symlink(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct krp_security_inode_symlink_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct krp_security_inode_symlink_data *)ri->data;
        data->dentry = (struct dentry *)regs->si;
        data->old_name = (char *)regs->dx;
	return 0;
}

static int handler_security_inode_symlink(struct kretprobe_instance *ri, struct pt_regs *regs) {
        struct krp_security_inode_symlink_data *data = (struct krp_security_inode_symlink_data *)ri->data;
        struct dentry *dentry = data->dentry;
        char *old_name = data->old_name;
        struct path path;

        int err = kern_path(old_name, LOOKUP_FOLLOW, &path);
        if (err == -ENOENT) {
                err = kern_path(strcat(old_name, "~"), LOOKUP_FOLLOW, &path);
        }
        if (err) {
                return 0; //don't care
        }

        struct dentry *target_file_dentry = path.dentry;
        dget(target_file_dentry);
        path_put(&path); 

        if (is_dentry_protected(dentry) || is_dentry_protected(target_file_dentry)) {
                char path_buf[PATH_MAX];
                char target_file_path_buf[PATH_MAX];
                char *pathname, *target_file_pathname;

                pathname = dentry_path_raw(dentry, path_buf, PATH_MAX);
                target_file_pathname = dentry_path_raw(target_file_dentry, target_file_path_buf, PATH_MAX);

                if (!IS_ERR(pathname) && !IS_ERR(target_file_pathname)) {
                        log_message(LOG_INFO, "DENIED CREATION OF SYMLINK '%s' TO FILE '%s' AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n", pathname, target_file_pathname);
                } else {
                        log_message(LOG_INFO, "DENIED CREATION OF SYMLINK TO FILE AS ONE OR BOTH PATHS ARE BEING PROTECTED! REGISTERING ILLEGAL ACCESS...\n");
                }
                regs->ax = (unsigned long) -EACCES;
                return 0;
        }
        return 0;
}


static struct kretprobe krp_security_inode_symlink = {
        .kp.symbol_name     = "security_inode_symlink",
        .handler            = handler_security_inode_symlink,
        .entry_handler      = entry_handler_security_inode_symlink,
        .data_size          = sizeof(struct krp_security_inode_symlink_data),
};
//=================================================

static struct kretprobe *my_kretprobes[] = {
        &krp_security_file_open,
        &krp_security_inode_rename,
        &krp_security_inode_unlink,
        &krp_security_inode_rmdir,
        &krp_security_inode_create,
        &krp_security_inode_mkdir,
        &krp_security_inode_link,
        &krp_security_inode_symlink,
};


void register_my_kretprobes(void) {
        for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
                int ret = register_kretprobe(my_kretprobes[i]);
                if (ret < 0) {
                        log_message(LOG_ERR, "kretprobe '%s' registration failed: %d\n", my_kretprobes[i]->kp.symbol_name, ret);
                } else {
                        log_message(LOG_INFO, "kretprobe '%s' registered\n", my_kretprobes[i]->kp.symbol_name);
                }
        }
}


void unregister_my_kretprobes(void) {
        for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
                unregister_kretprobe(my_kretprobes[i]);
                log_message(LOG_INFO, "kretprobe '%s' unregistered\n", my_kretprobes[i]->kp.symbol_name);
        }
}


void enable_my_kretprobes(void) {
        for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
                int ret = enable_kretprobe(my_kretprobes[i]);
                if (ret < 0) {
                        log_message(LOG_ERR, "Failed to enable kretprobe '%s': %d\n", my_kretprobes[i]->kp.symbol_name, ret);
                } else {
                        log_message(LOG_INFO, "Kretprobe '%s' enabled\n", my_kretprobes[i]->kp.symbol_name);
                }
        }
}


void disable_my_kretprobes(void) {
    for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
        disable_kretprobe(my_kretprobes[i]);
        log_message(LOG_INFO, "Kretprobe '%s' disabled\n", my_kretprobes[i]->kp.symbol_name);
    }
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
                                enable_my_kretprobes();
                        }else{
                                disable_my_kretprobes();
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
                        if(reconf != RECONF_ENABLED){
                                log_message(LOG_INFO, "The reference monitor was REC-%s. It is now %s.\n", state_str, state_str);
                        }else{
                                log_message(LOG_INFO, "The reference monitor was %s. It is now REC-%s.\n", state_str, state_str);
                        }
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
                                        the_refmon_path->inode = d_backing_inode(the_refmon_path->actual_path.dentry)->i_ino;
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
        log_message(LOG_INFO, "starting up!\n");

        //init reference monitor struct
        reference_monitor.state = OFF; //starting as REC-OFF
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
        register_my_kretprobes();
        log_message(LOG_INFO, "all kretprobes correctly registered\n");
        disable_my_kretprobes(); //starting as REC-OFF

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

        unregister_my_kretprobes();
        log_message(LOG_INFO, "all kretprobes correctly unregistered\n");
}
