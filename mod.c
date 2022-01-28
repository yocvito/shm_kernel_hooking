#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/ipc.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/string.h>

#include <linux/time.h>

#include <linux/uio.h>
#include <linux/mman.h>

// for scheduling dumping task
#include <linux/workqueue.h>
#include <linux/sched.h>


#include "utils.h"

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
#define PTREGS_SYSCALL_STUBS    1
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name)      ("__x64_sys_" name)
#else
#define SYSCALL_NAME(name)      ("sys_" name)
#endif

#define LOGGING_WAITING_TIMER   10
struct timespec64 last = { 0 };
static DEFINE_MUTEX(log_lock);
int onexit = 0;
static struct workqueue_struct *queue;
static struct work_struct Task;
static int dumping_routine(void*);
static DECLARE_DELAYED_WORK(task, dumping_routine);



// for now only track 1 shared memory area (last one created)
int g_shmid = -1;
long g_size = -1;
char __user * g_addr = NULL;

// mmap
char * __user * user_addrs = NULL;
size_t *sizes = NULL;
int max_addrs = 10;
int nb_addrs = 0;

/*****************
 ***   HOOKS   ***
 *****************/
#ifdef PTREGS_SYSCALL_STUBS
// HOOKS FOR KERNEL VERSION >= 4.17.0
static asmlinkage int (*orig_shmget) (const struct pt_regs*);
static asmlinkage void* (*orig_shmat) (const struct pt_regs*);
static asmlinkage int (*orig_shmdt) (const struct pt_regs*);
static asmlinkage void* (*orig_mmap)(const struct pt_regs*);
static asmlinkage int (*orig_munmap)(const struct pt_regs*);
static asmlinkage int (*orig_clone)(const struct pt_regs*);

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
        printk(KERN_INFO "Shared memory attached for shmid=%d on addr %lx\n", shmid, (unsigned long)g_addr);
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
        mem_print_hexa(kbuf, g_size, 0);
        printk(KERN_INFO "Strings in memory:\n");
        mem_print_strings(kbuf, g_size, 0);

        g_addr = NULL;

        kfree(kbuf);
    }
    return orig_shmdt(regs);
}

asmlinkage void *
hook_mmap(const struct pt_regs *regs)
{
    void __user *addr = orig_mmap(regs);
    if (addr != NULL)
    {
        int prot = regs->dx;
        int flags = regs->r10;
        size_t length = regs->si;
        //printk(KERN_INFO "Hooking succesfull mmap !\naddr=%lx\nprot=%d\nflags=%d\nlength=%lu\n", (unsigned long) addr, prot, flags, length);
        if ((prot & PROT_EXEC) && (flags & MAP_ANONYMOUS))
        {
            if (!mutex_trylock(&log_lock))
                return addr;
            printk(KERN_INFO "Suspicious mmap detected !! PROT_EXEC and MAP_ANON set\n");
            // add user addr
            if (nb_addrs >= max_addrs)
            {
                void* tmp = krealloc(user_addrs, (max_addrs * 2) * sizeof(char *__user*), GFP_KERNEL);
                if (!tmp)
                    return addr;
                user_addrs = tmp;
                tmp = krealloc(sizes, max_addrs * 2 * sizeof(size_t), GFP_KERNEL);
                if (!tmp)
                    return addr;
                sizes = tmp;
                max_addrs *= 2;
            }
            user_addrs[nb_addrs] = addr;
            sizes[nb_addrs++] = length;
            mutex_unlock(&log_lock);
        }
    }
    return addr;
}

asmlinkage int
hook_munmap(const struct pt_regs *regs)
{
    void __user *addr = regs->di;
    // remove addr
    if (!mutex_trylock(&log_lock))
        goto munmapcall;
    int i;
    for (i=0; i<nb_addrs; i++)
    {
        if (addr == user_addrs[i])
        {
            char *kbuf;
            long err;
            kbuf = kzalloc(sizes[i]+1, GFP_KERNEL);
            if (!kbuf)
                goto desalloc;

            printk(KERN_INFO "Shared memory dump of size %lu on user address %lx\n", sizes[i], user_addrs[i]);
            if ((err = copy_from_user(kbuf, user_addrs[i], sizes[i])) > 0)
                printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) user_addrs[i]);
            else
            {
                mem_print_hexa(kbuf, sizes[i], 1);
                mem_print_strings(kbuf, sizes[i], 1);
            }
            kfree(kbuf);
            
desalloc:
            printk(KERN_INFO "Removing user address %lx from suspicious mmap table\n", (unsigned long)addr);
            if (i == nb_addrs-1)
            {
                user_addrs[i] = 0;
                sizes[i] = 0;
            }
            else
            {
                shift_array_left(user_addrs, sizeof (char __user *), nb_addrs, i);
                shift_array_left(sizes, sizeof (size_t), nb_addrs, i);
            }
            nb_addrs--;
            if (nb_addrs <= max_addrs/4)
            {
                void* tmp = krealloc(user_addrs, (max_addrs/2) * sizeof(char *__user*), GFP_KERNEL);
                if (!tmp)
                    goto munmapcall; 
                user_addrs = tmp;
                tmp = krealloc(sizes, (max_addrs/2) * sizeof(size_t), GFP_KERNEL);
                if (!tmp)
                    goto munmapcall; 
                sizes = tmp;
                max_addrs /= 2;
            }
            break;
        }
    }
    mutex_unlock(&log_lock);
munmapcall:
    return orig_munmap(regs);
}

asmlinkage ssize_t
hook_clone(const struct pt_regs *regs)
{
    struct timespec64 cur;
    ktime_get_ts64(&cur);
    cur.tv_sec -= last.tv_sec;
    cur.tv_nsec -= last.tv_nsec;
    printk(KERN_INFO "Clone hooked !\nTimer triggered in %lld\n", LOGGING_WAITING_TIMER-(cur.tv_sec));
    if (cur.tv_sec >= LOGGING_WAITING_TIMER)
    {
        if (!mutex_trylock(&log_lock))
            goto clonecall;

        printk(KERN_INFO "Trying to dump memory areas !\n");
        char *kbuf;
        long err;
        int i;
        for (i=0; i<nb_addrs; i++)
        {
            kbuf = kzalloc(sizes[i]+1, GFP_KERNEL);
            if (!kbuf)
                goto clonecall;

            /**
             * Switch current page table to corresponding user process page table regarding user_addr
             ********
             * TODO
             ********
             */

            printk(KERN_INFO "Shared memory dump of size %lu on user address %lx\n", sizes[i], user_addrs[i]);
            if ((err = copy_from_user(kbuf, user_addrs[i], sizes[i])) > 0)
                printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) user_addrs[i]);

            /**
             * Restore original page table
             ********
             * TODO
             ********
             */

            if (err == 0)
            {
                mem_print_hexa(kbuf, sizes[i], 1);
                mem_print_strings(kbuf, sizes[i], 1);
            }

            kfree(kbuf);
        }

        ktime_get_ts64(&last);
        mutex_unlock(&log_lock);
    }
clonecall:
    return orig_clone(regs);
}


#else
// HOOKS FOR KERNEL VERSION < 4.17.0
static asmlinkage int (*orig_shmget) (key_t, size_t, int);
static asmlinkage void* (*orig_shmat) (int, void __user *, int);
static asmlinkage int (*orig_shmdt) (const void __user *);
static asmlinkage void* (*orig_mmap)(void *, size_t , int, int, int, off_t);
static asmlinkage int (*orig_munmap)(void *, size_t);
static asmlinkage int (*orig_clone)(unsigned long, unsigned long, int __user *, unsigned long, int __user *);

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
        mem_print_hexa(kbuf, g_size, 0);            // output to console rather than /var/tmp/.shmlogs
        printk(KERN_INFO "Strings in memory:\n");
        mem_print_strings(kbuf, g_size, 0);

        g_addr = NULL;

        kfree(kbuf);
    }
    return orig_shmdt(shmaddr);
}


asmlinkage void *
hook_mmap(void *suggested, size_t length, int prot, int flags, int fd, off_t offset)
{
    void __user *addr = orig_mmap(regs);
    if (addr != NULL)
    {
        printk(KERN_INFO "Hooking succesfull mmap !\naddr=%lx\nprot=%d\nflags=%d\nlength=%lu\n", (unsigned long) addr, prot, flags, length);
        if ((prot & PROT_EXEC) && (flags & MAP_ANONYMOUS))
        {
            // add user addr
            if (nb_addrs >= max_addrs)
            {
                void* tmp = krealloc(user_addrs, (max_addrs * 2) * sizeof(char *__user*), GFP_KERNEL);
                if (!tmp)
                    return addr;
                user_addrs = tmp;
                tmp = krealloc(sizes, max_addrs * 2 * sizeof(size_t), GFP_KERNEL);
                if (!tmp)
                    return addr;
                sizes = tmp;
                max_addrs *= 2;
            }
            user_addrs[nb_addrs] = addr;
            sizes[nb_addrs++] = length;
        }
    }
    return addr;
}

asmlinkage int
hook_munmap(void *addr, size_t length)
{
// remove addr
    int i;
    for (i=0; i<nb_addrs; i++)
    {
        if (addr == user_addrs[i])
        {
            if (i == nb_addrs-1)
            {
                user_addrs[i] = 0;
                sizes[i] = 0;
            }
            else
            {
                shift_array_left(user_addrs, sizeof (char __user *), nb_addrs, i);
                shift_array_left(sizes, sizeof (size_t), nb_addrs, i);
            }
            nb_addrs--;
            if (nb_addrs <= max_addrs/4)
            {
                void* tmp = krealloc(user_addrs, (max_addrs/2) * sizeof(char *__user*), GFP_KERNEL);
                if (!tmp)
                    goto munmapcall; 
                user_addrs = tmp;
                tmp = krealloc(sizes, (max_addrs/2) * sizeof(size_t), GFP_KERNEL);
                if (!tmp)
                    goto munmapcall; 
                sizes = tmp;
                max_addrs /= 2;
            }
            break;
        }
    }
munmapcall:
    return orig_munmap(addr, length);
}

asmlinkage ssize_t
hook_clone(unsigned long fn, unsigned long stack, int __user *a, unsigned long b, int __user *c)
{
    printk(KERN_INFO "Clone hooked !\n");
    struct timespec64 cur;
    ktime_get_ts64(&cur);
    cur.tv_sec -= last.tv_sec;
    cur.tv_nsec -= last.tv_nsec;
    if (cur.tv_sec >= LOGGING_WAITING_TIMER && g_addr != NULL)
    {
        if (!mutex_trylock(&log_lock))
            goto clonecall;

        char *kbuf;
        long err;
        int i;
        for (i=0; i<nb_addrs; i++)
        {
            kbuf = kzalloc(sizes[i], GFP_KERNEL);
            if (!kbuf)
                goto clonecall;

            printk(KERN_INFO "Shared memory dump on user address %lx\n", user_addrs[i]);
            if ((err = copy_from_user(kbuf, user_addrs[i], sizes[i])) > 0)
                printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) user_addrs[i]);

            mem_print_hexa(kbuf, sizes[i], 1);
            mem_print_strings(kbuf, sizes[i], 1);

            kfree(kbuf);
        }

        ktime_get_ts64(&last);
        mutex_unlock(&log_lock);
    }
clonecall:
    return orig_clone(fn, stack, a, b, c);
}

#endif

static void
dumping_routine(void *args)
{
    if (!mutex_trylock(&log_lock))
            goto end;

    char *kbuf;
    long err;
    int i;
    printk(KERN_INFO, "Dumping anonymous mmap from task\n");
    for (i=0; i<nb_addrs; i++)
    {
        kbuf = kzalloc(sizes[i], GFP_KERNEL);
        if (!kbuf)
            goto end;

        printk(KERN_INFO "Shared memory dump on user address %lx\n", user_addrs[i]);
        if ((err = copy_from_user(kbuf, user_addrs[i], sizes[i])) > 0)
            printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) user_addrs[i]);

        mem_print_hexa(kbuf, sizes[i], 1);
        mem_print_strings(kbuf, sizes[i], 1);

        kfree(kbuf);
    }

    mutex_unlock(&log_lock);
        
end:
    if (onexit != 1)
        queue_delayed_work(queue, &task, LOGGING_WAITING_TIMER);
}

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

/**************************
 * MODULE LOADER/UNLOADER *
 **************************/
unsigned long *st = NULL;
int __init module_load(void)
{
    mutex_init(&creds_lock);
    mutex_init(&log_lock);

    user_addrs = kzalloc(max_addrs * sizeof(char __user *), GFP_KERNEL);
    if (!user_addrs)
        return -ENOMEM;

    sizes = kzalloc(max_addrs * sizeof(size_t), GFP_KERNEL);
    if(!sizes)
    {
        kfree(user_addrs);
        return -ENOMEM;
    }

    st = get_syscall_table_addr();
    if (!st)
    {
        kfree(user_addrs);
        kfree(sizes);
        return -1;
    }

    queue = create_workqueue("dumping task workqueue");
    if (!queue)
    {
        kfree(user_addrs);
        kfree(sizes);
        return -ENOMEM;
    }

    orig_shmget = st[__NR_shmget];
    orig_shmat = st[__NR_shmat];
    orig_shmdt = st[__NR_shmdt];
    orig_mmap = st[__NR_mmap];
    orig_munmap = st[__NR_munmap];
    orig_clone = st[__NR_clone];

    printk(KERN_INFO "mmap: hook=%lx && orig=%lx\n", hook_mmap, orig_mmap);
    
    unprotect_memory();
    st[__NR_shmget] = (unsigned long) hook_shmget;
    st[__NR_shmat] = (unsigned long) hook_shmat;
    st[__NR_shmdt] = (unsigned long) hook_shmdt;
    st[__NR_mmap] = (unsigned long) hook_mmap;
    st[__NR_munmap] = (unsigned long) hook_munmap;
    st[__NR_clone] = (unsigned long) hook_clone;
    protect_memory();
    printk (KERN_INFO "Hooks installed !\n");

    queue_delayed_work(queue, &task, LOGGING_WAITING_TIMER);

    return 0;
}

void __exit module_unload(void)
{
    unprotect_memory();
    st[__NR_shmget] = (unsigned long) orig_shmget;
    st[__NR_shmat] = (unsigned long) orig_shmat;
    st[__NR_shmdt] = (unsigned long) orig_shmdt;
    st[__NR_mmap] = (unsigned long) orig_mmap;
    st[__NR_munmap] = (unsigned long) orig_munmap;
    st[__NR_clone] = (unsigned long) orig_clone;
    protect_memory();
    onexit = 1;
	cancel_delayed_work(&task);
	flush_workqueue(queue);
	destroy_workqueue(queue);
    mutex_destroy(&creds_lock);
    mutex_destroy(&log_lock);
    kfree(user_addrs);
    kfree(sizes);

    printk(KERN_INFO "Original shmget/shmat/shmdt syscalls restored\n");
}

module_init(module_load);
module_exit(module_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yocvito");
MODULE_DESCRIPTION("another funny module");
MODULE_VERSION("0.01");