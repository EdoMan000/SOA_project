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
#include <linux/ktime.h>
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
#include "utils/include/general_utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Edoardo Manenti <manenti000@gmail.com>");
MODULE_DESCRIPTION("reference monitor");

//==================================
//   M O D    C O N S T A N T S   ||
//==================================

#define MODNAME "REFMON"
#define CURRENT_EUID current->cred->euid.val
#define CURRENT_UID current->cred->uid.val
#define CURRENT_TGID current->tgid
#define CURRENT_TID current->pid
#define RECONF_ENABLED 1
#define RECONF_DISABLED 0
#define MAX_PASSW_LEN 32
#define AUDIT if(1)
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array)/sizeof(unsigned long))
#define LOG_FILE_PATH "/tmp/refmon_log/the-refmon-log"

//==================================
//  S T R U C T S   &   V A R S   ||
//==================================

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
        const char *description;
        const char *path1;
        const char *path2;
        pid_t tgid;
        pid_t tid;
        uid_t uid;
        uid_t euid;
        char *program_pathname;
        struct work_struct the_work;
} file_audit_log;


refmon reference_monitor;

unsigned long the_ni_syscall;

unsigned long new_sys_call_array[] = {0x0,0x0};
int restore[HACKED_ENTRIES] = {[0 ... (HACKED_ENTRIES-1)] -1};

//==================================
//   M O D U L E    P A R A M S   ||
//==================================

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0);

static int the_refmon_reconf = RECONF_ENABLED;//starting as REC-OFF 
module_param(the_refmon_reconf,int,0660); //NB:] this can be configured at run time via the sys file system -> 1 means the reference monitor can be currently reconfigured

static unsigned char the_refmon_secret[MAX_PASSW_LEN]; 
module_param_string(the_refmon_secret, the_refmon_secret, MAX_PASSW_LEN, 0);

//==================================
//   D E F E R R E D    W O R K   ||
//==================================

/**
 * @brief Performs deferred writing of illegal accesses to protected files/dirs.
 *
 *      This function is designed to run in the context of a workqueue. It takes the
 *      content prepared in a file_audit_log structure and writes it to a specified
 *      log file. The function handles formatting of the log entry, computing a hash
 *      of the program content, and writing the formatted log entry to the file. This
 *      process is done in a deferred manner to minimize the impact on the main execution
 *      flow of the program.
 *
 * @param work Pointer to the work_struct embedded in a file_audit_log structure.
 *             This structure contains all necessary information to generate the log entry.
 *
 * NB:] The log entry includes the process and thread IDs, user IDs, program pathname,
 *      and a SHA-256 hash of the program's content. If any step in the process fails,
 *      appropriate error messages are logged using the logging facilities.
 */
static void write_audit_log(struct work_struct *work) {
        file_audit_log *log = container_of(work, file_audit_log, the_work);
        struct file *file;
        char *log_entry;
        char hash_hex[SHA256_DIGEST_SIZE * 2 + 1];
        loff_t pos = 0; 
        ssize_t read_size;
        char *program_content;
        loff_t program_size;
        struct timespec64 ts;
        struct tm tm;
        char timestamp[9]; // HH:MM:SS\0
        int len;

        unsigned char *computed_hash = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if(!computed_hash){
                log_message(LOG_ERR, "Couldn't allocate memory to store computed hash of program content during deferred work...\n\tDESC was: '%s'\n", log->description);
                return;
        }
        //read the program content
        file = filp_open(log->program_pathname, O_RDONLY, 0);
        if (IS_ERR(file)) {
                log_message(LOG_ERR, "Couldn't open file to read from program during deferred work...\n\tDESC was: '%s'\n", log->description);
                goto cleanup;
        }
        program_size = vfs_llseek(file, 0, SEEK_END);
        if (program_size < 0) {
                log_message(LOG_ERR, "Failed to seek to the end of the program during deferred work...\n\tDESC was: '%s'\n", log->description);
                filp_close(file, NULL);
                goto cleanup;
        }
        vfs_llseek(file, 0, SEEK_SET);
        program_content = kmalloc(program_size + 1, GFP_KERNEL);
        if (!program_content) {
                log_message(LOG_ERR, "Failed to allocate memory for program content during deferred work...\n\tDESC was: '%s'\n", log->description);
                filp_close(file, NULL);
                goto cleanup;
        }
        read_size = kernel_read(file, program_content, program_size, &pos);
        if (read_size < 0) {
                log_message(LOG_ERR, "Failed to read program content during deferred work...\n\tDESC was: '%s'\n", log->description);
                filp_close(file, NULL);
                goto cleanup;
        } else {
                filp_close(file, NULL);
                program_content[read_size] = '\0';
        }
        if (compute_sha256(program_content, program_size, computed_hash)) {
                log_message(LOG_ERR, "Couldn't compute sha256 of program content during deferred work...\n\tDESC was: '%s'\n", log->description);
                goto cleanup;
        }
        // Compute hash hex string
        bin2hex(hash_hex, computed_hash, SHA256_DIGEST_SIZE);
        hash_hex[SHA256_DIGEST_SIZE * 2] = '\0';
        // Get current timestamp
        ktime_get_real_ts64(&ts);
        time64_to_tm(ts.tv_sec, 1, &tm); // Assuming UTC+1 time, hence the offset is 1
        snprintf(timestamp, sizeof(timestamp), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

        char paths[PATH_MAX*2 + 64];
        if (strcmp(log->description, "DENIED WRITE_ON") == 0) {
                len = snprintf(paths, sizeof(paths), "FILE: %s\n", log->path1);
        } else if (strcmp(log->description, "DENIED RENAMING") == 0) {
                len = snprintf(paths, sizeof(paths), "FILE(old name): %s\nFILE(new name): %s\n", log->path1, log->path2);
        } else if (strcmp(log->description, "DENIED DELETION") == 0) {
                len = snprintf(paths, sizeof(paths), "FILE: %s\n", log->path1);
        } else if (strcmp(log->description, "DENIED CREATION") == 0) {
                len = snprintf(paths, sizeof(paths), "FILE: %s\n", log->path1);
        } else if (strcmp(log->description, "DENIED HARD-LNK") == 0) {
                len = snprintf(paths, sizeof(paths), "HARD LINK: %s\nFILE: %s\n", log->path1, log->path2);
        } else if (strcmp(log->description, "DENIED SYMB-LNK") == 0) {
                len = snprintf(paths, sizeof(paths), "SYMBOLIC LINK: %s\nFILE: %s\n", log->path1, log->path2);
        }
        //-----------------
        len = snprintf(NULL, 0,
                "\n===========================================================================\n"
                "[*] %s                                       | at %s [*]\n"
                "===========================================================================\n"
                "TGID: %d, TID: %d, UID: %u, EUID: %u\n"
                "%s"
                "PROGRAM: %s\n"
                "HASH(hex): %s\n"
                "===========================================================================\n",
                log->description, timestamp, log->tgid, log->tid, log->uid, log->euid, 
                paths, log->program_pathname, hash_hex) + 1; // +1 for '\0'
        log_entry = kmalloc(len, GFP_KERNEL);
        if (!log_entry) {
                log_message(LOG_ERR, "Failed to allocate memory for log entry during deferred work...\n\tDESC was: '%s'\n", log->description);
                goto cleanup;
        }
        snprintf(log_entry, len,
                "\n===========================================================================\n"
                "[*] %s                                       | at %s [*]\n"
                "===========================================================================\n"
                "TGID: %d, TID: %d, UID: %u, EUID: %u\n"
                "%s"
                "PROGRAM: %s\n"
                "HASH(hex): %s\n"
                "===========================================================================\n",
                log->description, timestamp, log->tgid, log->tid, log->uid, log->euid, 
                paths, log->program_pathname, hash_hex);
        // Write to the log file
        file = filp_open(LOG_FILE_PATH, O_WRONLY | O_APPEND, 0);
        if (!IS_ERR(file)) {
                ssize_t written = kernel_write(file, log_entry, len - 1, &file->f_pos);
                if (written < 0) {
                        log_message(LOG_ERR, "Failed to write to log file...\n\tDESC was: '%s'\n", log->description);
                }
                filp_close(file, NULL);
        } else {
                log_message(LOG_ERR, "Couldn't open file to write the log to...\n\tDESC was: '%s'| err: %d\n", log->description, file);
        }

cleanup:
        if(computed_hash) kfree(computed_hash);
        if(program_content) kfree(program_content);
        if (log->program_pathname) kfree(log->program_pathname);
        if (log_entry) kfree(log_entry);
        if(log) kfree(log);
}

/**
 * @brief Retrieves the full pathname of the current executable file.
 *
 * @return A pointer to a dynamically allocated string containing the full pathname,
 *         or NULL on error. The caller is responsible for freeing this memory with kfree.
 */
char *get_current_exe_path(void) {
        char *buf, *pathname = NULL;

        buf = (char *)__get_free_page(GFP_KERNEL);
        if (!buf) {
                log_message(LOG_ERR, "get_current_exe_path: Failed to allocate memory for path buffer to submit deferred work\n");
                return NULL;
        }

        pathname = d_path(&current->mm->exe_file->f_path, buf, PAGE_SIZE);
        if (IS_ERR(pathname)) {
                pr_err("get_current_exe_path: Error converting path to string to submit deferred work\n");
                free_page((unsigned long)buf);
                return NULL;
        }
        pathname = kstrdup(pathname, GFP_KERNEL);

        free_page((unsigned long)buf);

        return pathname; 
}

/**
 * @brief Schedules a work item to asynchronously write audit log entries for illegal accesses to protected files/dirs.
 *
 *      Initializes a file_audit_log structure with details of the audit event, including
 *      descriptions of the event, paths involved, process and user identifiers, and the
 *      pathname of the program executing the operation. It then schedules a deferred
 *      work task to compute the hash of the program content and write this data into an audit log file.
 *
 * NB:] This approach allows the logging operation to be performed outside the critical
 *      execution path, reducing potential performance impact on the system.
 *
 * @param description A brief description of the audit event.
 * @param path1 The primary path involved in the audit event (e.g. file path being accessed).
 * @param path2 The secondary path involved in the event (e.g. destination path in a move operation), if applicable.
 *
 * NB:] The memory for the file_audit_log structure and any dynamic strings it contains (such as pathname)
 *      is allocated here and must be freed by the `write_audit_log` function after logging is complete.
 */
void submit_audit_log_work(const char *description, const char *path1, const char *path2) {
        file_audit_log *log;

        log = kzalloc(sizeof(*log), GFP_KERNEL);
        if (!log){
                log_message(LOG_ERR, "Couldn't allocate log to submit deferred work...\n\tDESC was: '%s'\n", description);
                return;
        }
        log->description = description;
        log->path1 = path1;
        log->path2 = path2;
        log->tgid = CURRENT_TGID;
        log->tid = CURRENT_TID;
        log->uid = CURRENT_UID;
        log->euid = CURRENT_EUID;
        char *pathname = get_current_exe_path();
        if(pathname == NULL){
                log_message(LOG_ERR, "Couldn't get_current_exe_path to submit deferred work...\n\tDESC was: '%s'\n", description);
                return;
        }
        log->program_pathname = pathname;

        __INIT_WORK(&log->the_work, write_audit_log, (unsigned long)&log->the_work);
        schedule_work(&log->the_work);
}

//==================================
//  M A N A G I N G    P A T H S  ||
//==================================

/**
 * @brief Checks if a given path is already protected.
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
 * @brief Checks if a given inode corresponds to a protected file.
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
 * @brief Checks if a given dentry corresponds to a protected file or it is situated in a protected path.
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
 * @brief Retrieves the entry for a given path if it is protected.
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
//      K R E T P R O B E S       ||
//==================================

/**
 * @brief Kretprobe for security_file_open.
 * 
 *      Intercepts attempts to open files to enforce write protection on protected paths.
 *      It checks if the opened file is designated for writing and is located within a protected path,
 *      blocking the operation if so and logging the event.
 * 
 * NB:] existing symbolic or hard links to files are automatically managed because the check 
 *      is done on the inode of the protected file, triggering the probing in any case.
 */

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
                                pathname = kstrdup(pathname, GFP_KERNEL);
                                submit_audit_log_work("DENIED WRITE_ON", pathname, NULL);
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
/**
 * @brief Kretprobe for security_inode_rename.
 * 
 *      Monitors file or directory rename operations. If either the source or destination paths
 *      are protected, the rename operation is blocked and the event is logged.
 *      This ensures that protected resources cannot be bypassed through renaming.
 */

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
                        old_pathname = kstrdup(old_pathname, GFP_KERNEL);
                        new_pathname = kstrdup(new_pathname, GFP_KERNEL);
                        submit_audit_log_work("DENIED RENAMING", old_pathname, new_pathname);
                } else {
                        submit_audit_log_work("DENIED RENAMING", NULL, NULL);
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
/**
 * @brief Kretprobes for security_inode_unlink and security_inode_rmdir.
 * 
 *      These handlers intercept file deletion and directory removal operations, respectively.
 *      If the target is protected, the operation is denied and the event is recorded,
 *      ensuring the integrity of protected paths.
 */

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
                        pathname = kstrdup(pathname, GFP_KERNEL);
                        submit_audit_log_work("DENIED DELETION", pathname, NULL);
                } else {
                        submit_audit_log_work("DENIED DELETION", NULL, NULL);
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
/**
 * @brief Kretprobes for security_inode_create and security_inode_mkdir.
 * 
 *      These handle file creation and directory making operations. When a creation operation
 *      occurs within a protected directory, it is intercepted and blocked to preserve the
 *      secure state of the whole protected directory content.
 */

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
                        pathname = kstrdup(pathname, GFP_KERNEL);
                        submit_audit_log_work("DENIED CREATION", pathname, NULL);
                } else {
                        submit_audit_log_work("DENIED CREATION", NULL, NULL);
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
/**
 * @brief Kretprobe for security_inode_link.
 * 
 *      Watches for hard link creation operations involving protected files.
 *      If the source file or the link target directory is protected, the operation is blocked
 *      and the event is logged.
 */

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
                        //HARD_LINK -> new_pathname 1
                        //FILE -> old_pathname 2
                        old_pathname = kstrdup(old_pathname, GFP_KERNEL);
                        new_pathname = kstrdup(new_pathname, GFP_KERNEL);
                        submit_audit_log_work("DENIED HARD-LNK", new_pathname, old_pathname);
                } else {
                        submit_audit_log_work("DENIED HARD-LNK", NULL, NULL);
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
/**
 * @brief Kretprobe for security_inode_symlink.
 * 
 *      Monitors symbolic link creation, preventing links that reference or are placed within
 *      protected paths. This is mainly to avoid altering the content of a protected directory
 *      by creating symlinks, secondly to avoid indirect access to protected files through symlinks.
 * 
 * NB:] existing symlinks are a don't care because any write operation on them would still be
 *      intercepted by security_file_open probing.
 */

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
                        //SYM-LINK -> pathname FILE -> target_file_pathname
                        pathname = kstrdup(pathname, GFP_KERNEL);
                        target_file_pathname = kstrdup(target_file_pathname, GFP_KERNEL);
                        submit_audit_log_work("DENIED SYMB-LNK", pathname, target_file_pathname);
                } else {
                        submit_audit_log_work("DENIED SYMB-LNK", NULL, NULL);
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

/**
 * @brief Registers all the kretprobes used by the module.
 *
 *      This function iterates through the array of kretprobe pointers defined globally,
 *      attempting to register each. It logs the outcome of each registration attempt.
 */
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

/**
 * @brief Unregisters all the kretprobes used by the module.
 *
 *      This function iterates through the array of kretprobe pointers defined globally,
 *      attempting to unregister each. It logs the outcome of each unregistration attempt.
 */
void unregister_my_kretprobes(void) {
        for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
                unregister_kretprobe(my_kretprobes[i]);
                log_message(LOG_INFO, "kretprobe '%s' unregistered\n", my_kretprobes[i]->kp.symbol_name);
        }
}

/**
 * @brief Enables all the kretprobes used by the module.
 *
 *      This function iterates through the array of kretprobe pointers defined globally,
 *      attempting to enable each. It logs the outcome of each enable attempt.
 */
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

/**
 * @brief Disables all the kretprobes used by the module.
 *
 *      This function iterates through the array of kretprobe pointers defined globally,
 *      attempting to disable each. It logs the outcome of each disable attempt.
 */
void disable_my_kretprobes(void) {
    for (int i = 0; i < ARRAY_SIZE(my_kretprobes); i++) {
        disable_kretprobe(my_kretprobes[i]);
        log_message(LOG_INFO, "Kretprobe '%s' disabled\n", my_kretprobes[i]->kp.symbol_name);
    }
}

//==================================
//  I N T E R N A L    U T I L S  ||
//==================================

/**
 * @brief Converts the state of the reference monitor to a string representation.
 *
 * @param state The current state of the reference monitor.
 * @param opposite If non-zero, returns the opposite of the current state as a string.
 * @return The string representation of the current (or opposite) state, default message if unknown.
 */
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

/**
 * @brief Updates the state of the reference monitor and logs the change.
 *
 *      This function changes the state of the reference monitor based on the provided
 *      new state and reconfiguration flag. It also logs the change.
 *
 * @param new_state The new state to set.
 * @param reconf The reconfiguration flag, indicating if reconfiguration is enabled.
 */
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

/**
 * @brief Prints the current state of the reference monitor and the list of protected paths.
 *
 *      This function logs the current state of the reference monitor and iterates through
 *      the list of protected paths, logging each.
 */
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

//==================================
//    S Y S T E M    C A L L S    ||
//==================================

/**
 * @brief Manages the operational state of the reference monitor.
 * 
 *      This system call enables or disables the reference monitor and its reconfiguration capabilities.
 *
 * @param cmd The command code indicating the desired operation. Valid commands include enabling/disabling the reference monitor and enabling/disabling reconfiguration.
 * @return 0 on success, negative error code on failure.
 */
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

/**
 * @brief Dynamically reconfigures protected paths within the reference monitor.
 * 
 *      Allows for the addition or removal of paths from the protection list of the reference monitor.
 * NB:] Authentication with a pre-defined password is required to authorize reconfiguration actions.
 *
 * @param password A user-space string containing the password for authentication.
 * @param path A user-space string specifying the path to add or remove from the protected list.
 * @param action Specifies the action to be taken: adding or removing a path. Specified by refmon_action_t struct.
 * @return 0 on success, negative error code on failure.
 */
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

//==================================
//  I N I T   &   C L E A N U P   ||
//==================================

/**
 * @brief Initialization function for the reference monitor module.
 * 
 *      Sets up the reference monitor structure, computes the password digest and stores it, 
 *      hacks the syscall table to insert custom system calls, and registers kretprobes. 
 * 
 * NB:] It starts with the reference monitor in REC-OFF state, allowing for post-load configuration.
 */
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

/**
 * @brief Cleanup function for the reference monitor module.
 * 
 *      Restores the original system call table, unregisters kretprobes, and performs necessary cleanup.
 *      Ensures a clean removal of the module without leaving residual effects on the system.
 */
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
