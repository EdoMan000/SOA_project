#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <linux/kernel.h> 
#include <linux/vmalloc.h> 
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h> 
#include <linux/uaccess.h>

#define MODNAME "REFMON"
#define MAX_LOGMSG_LEN 256

enum log_level {
    LOG_ERR,
    LOG_INFO
};

void log_message(enum log_level level, const char *fmt, ...);



typedef struct {
        char *kernel_passw;
        char *kernel_path;
        int status; 
} copied_strings_t;

copied_strings_t copy_strings_from_user(const char __user *user_passw, const char __user *user_path);

#endif // GENERAL_UTILS_H
