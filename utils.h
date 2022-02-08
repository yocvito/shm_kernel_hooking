#ifndef __UTILS_H__
#define __UTILS_H__

#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/unistd.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <linux/fcntl.h>
#include <asm/processor.h>

#include <linux/mutex.h>

#define LOGFILE                 "/var/tmp/.shmlogs"

/**
 * All needed infos about process who called suspicious mmap
 * 
 */
typedef struct __mapper_process {
    struct task_struct *task;
    void __user *address;
    size_t size;
}  mapper_process;

/** UTILS **/
static int (*__access_remote_vm_)(struct task_struct *, struct mm_struct *, unsigned long, void*, int, unsigned int);

static char*
get_memory(mapper_process *mp)
{
    int ret, i;
    char *kbuf, *tmp;
    size_t curlen;
    void *addr;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    int npages = mp->size / PAGE_SIZE;
    if (npages == 0)
        npages = 1;
    struct page *pages[npages];
    
    if (!mp)
        return NULL;

    mm = get_task_mm(mp->task);
    if (!mm) 
        return NULL;

    kbuf = kzalloc(mp->size + 1, GFP_KERNEL);
    if (!kbuf)
        goto end;

    if (__access_remote_vm_(mp->task, mm,(unsigned long) mp->address, kbuf, mp->size, FOLL_FORCE) <= 0)
    {
        mmput(mm);
        return (void*) -1;
    }
/*
    down_read(&mm->mmap_sem);
    vma = mm->mmap;
    while ( vma && !(vma->vm_start <= mp->address && mp->address < vma->vm_end ) )
        vma = vma->vm_next;

    if (vma && (vma->vm_flags & VM_READ) )
    {
        ret = get_user_pages_remote(mp->task, mm, vma->vm_start, npages, FOLL_FORCE, pages, NULL);
        if (ret > 0)
        {
            curlen = 0;
            for (i=0; i<npages; i++)
            {
                tmp = kbuf + curlen;
                addr = kmap(pages[i]);
                
                strncat(tmp, addr, mp->size-curlen);

                kunmap(pages[i]);
                put_page(pages[i]);
            }
        }
    }
    else if (!vma)
        kbuf = (void*) -1;

    up_read(&mm->mmap_sem);
*/
end:
    mmput(mm);

    return kbuf;
}



struct cred oldcreds;
static DEFINE_MUTEX(creds_lock);
void 
enter_root_ctx(void)
{
    struct cred *creds;
    
    if (mutex_lock_interruptible(&creds_lock) < 0)
        return;
    

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
log_msg(unsigned char *msg)
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
    char *finalstr;

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