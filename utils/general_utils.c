#include "include/general_utils.h"

/**
 * @brief Prints a formatted log message with a specific log level.
 * 
 * @param level: The log level for the message, using enum log_level.
 * @param fmt: The format string for the message.
 * @param ...: Additional arguments for the format string.
 *
 *  This function formats a log message and prints it to the kernel log
 *  with a specified log level. It supports dynamic message length and
 *  cleans up memory automatically.
 */
void log_message(enum log_level level, const char *fmt, ...) {
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

/**
 * @brief Copies user-space strings `passw` and `path` to kernel space.
 * 
 * @param user_passw Pointer to user-space password string.
 * @param user_path Pointer to user-space path string.
 * @return A structure containing:
 *   - `kernel_passw`: Kernel-space copy of `user_passw`. Caller must free.
 *   - `kernel_path`: Kernel-space copy of `user_path`. Caller must free.
 *   - `status`: 0 on success; -EFAULT for invalid lengths; -ENOMEM for allocation failures.
 */
copied_strings_t copy_strings_from_user(const char __user *user_passw, const char __user *user_path) {
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
