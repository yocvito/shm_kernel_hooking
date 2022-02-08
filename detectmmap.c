#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
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
#include <linux/jiffies.h>

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

#define LOGGING_WAITING_TIMER           10
#define LOGGING_WAITING_TIMER_JIFFIES   msecs_to_jiffies(LOGGING_WAITING_TIMER *1000)

#ifndef MAP_FAILED
    #define MAP_FAILED (void*) -1
#endif



static DEFINE_MUTEX(log_lock);
static int onexit = 0;
static struct workqueue_struct *queue;
static struct delayed_work task;
static void dumping_routine(struct work_struct *);
static DECLARE_DELAYED_WORK(task, dumping_routine);

static int max_susproc = 10;
static int nb_susproc = 0;
static mapper_process *suspicious_processes;
#define sp_task(i)        suspicious_processes[i].task
#define sp_addr(i)        suspicious_processes[i].address
#define sp_size(i)        suspicious_processes[i].size


#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage void* (*orig_mmap)(const struct pt_regs*);
static asmlinkage int (*orig_munmap)(const struct pt_regs*);

asmlinkage void *
hook_mmap(const struct pt_regs *regs)
{
    void __user *addr = orig_mmap(regs);
    if (addr != MAP_FAILED)
    {
        int prot = regs->dx;
        int flags = regs->r10;
        size_t length = regs->si;
        if ((prot & PROT_EXEC) && (flags & MAP_ANONYMOUS))
        {
            if (!mutex_trylock(&log_lock))
                return addr;
            printk(KERN_INFO "Suspicious mmap detected !! PROT_EXEC and MAP_ANON set\n");
            if (nb_susproc >= max_susproc)
            {
                void *tmp = krealloc(suspicious_processes, (max_susproc * 2) * sizeof(mapper_process), GFP_KERNEL);
                if (!tmp)
                    goto endStoring;
                suspicious_processes = tmp;
                max_susproc *= 2;
            }
            sp_addr(nb_susproc) = addr;
            sp_size(nb_susproc) = length;
            sp_task(nb_susproc++) = current;

endStoring:
            mutex_unlock(&log_lock);
        }
    }
    return addr;
}

asmlinkage int
hook_munmap(const struct pt_regs *regs)
{
    int i;
    void __user *addr = (void*) regs->di;

    // remove addr
    if (!mutex_trylock(&log_lock))
        return orig_munmap(regs);
    for (i=0; i<nb_susproc; i++)
    {
        if (addr == sp_addr(i))
        {
            char *kbuf;
            long err;
        
            kbuf = kzalloc(sp_size(i)+1, GFP_KERNEL);
            if (!kbuf)
                goto desalloc;
            printk(KERN_INFO "Shared memory dump of size %lu on user address %lx\n", sp_size(i), (unsigned long)sp_addr(i));
            if ((err = copy_from_user(kbuf, sp_addr(i), sp_size(i))) > 0)
                printk(KERN_INFO "Error: cannot copied %ld bytes from user addr 0x%lx\n", err, (unsigned long) sp_addr(i));
            else
            {
                mem_print_hexa(kbuf, sp_size(i), 1);
                mem_print_strings(kbuf, sp_size(i), 1);
            }

            kfree(kbuf);

desalloc:
            printk(KERN_INFO "Removing user address %lx from suspicious mmap table\n", (unsigned long)addr);
            if (i == nb_susproc-1)
                memset(&suspicious_processes[i], 0, sizeof(mapper_process));
            else
                shift_array_left(suspicious_processes, sizeof (mapper_process), nb_susproc, i);
            nb_susproc--;
            if (nb_susproc <= max_susproc/4)
            {
                void* tmp = krealloc(suspicious_processes, (max_susproc/2) * sizeof(mapper_process), GFP_KERNEL);
                if (!tmp)
                    goto end; 
                suspicious_processes = tmp;
                max_susproc /= 2;
            }
            break;
        }

    }
end:
    mutex_unlock(&log_lock);
    return orig_munmap(regs);
}

#else


#endif

static void
dumping_routine(struct work_struct *args )
{
    char *kbuf;
    int i;

    mutex_lock(&log_lock);

    printk(KERN_INFO "Dumping anonymous mmap from task\n");
    for (i=0; i<nb_susproc  ; i++)
    {
        kbuf = get_memory(&suspicious_processes[i]);
        if (!kbuf)
        {
            printk(KERN_INFO "Unable to get mm_struct from task or fail alloc\n");
            goto end;
        }
        if (kbuf == (void*) -1)
        {
            printk(KERN_INFO "Unable to read from vma !\n");
            goto end;
        }
        mem_print_hexa(kbuf, sp_size(i), 1);
        mem_print_strings(kbuf, sp_size(i), 1);
        printk(KERN_INFO "Successfully dump memory !\n");

        kfree(kbuf);
    }

        
end:
    mutex_unlock(&log_lock);
    if (onexit != 1)
        queue_delayed_work(queue, &task, LOGGING_WAITING_TIMER_JIFFIES);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
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
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif

    st = (unsigned long *) kallsyms_lookup_name("sys_call_table");

    return st;
}


unsigned long *st = NULL;
static int __init module_load(void)
{
    mutex_init(&creds_lock);
    mutex_init(&log_lock);

    suspicious_processes = kzalloc(max_susproc * sizeof(mapper_process), GFP_KERNEL);
    if (!suspicious_processes)
        return -ENOMEM;

    st = get_syscall_table_addr();
    if (!st)
    {
        kfree(suspicious_processes);
        return -1;
    }

    __access_remote_vm_ = kallsyms_lookup_name("__access_remote_vm");
    if (__access_remote_vm_ == NULL)
    {
        kfree(suspicious_processes);
        return -1;
    }

    queue = create_workqueue("dumping task workqueue");
    if (!queue)
    {
        kfree(suspicious_processes);
        return -ENOMEM;
    }

    orig_mmap = st[__NR_mmap];
    orig_munmap = st[__NR_munmap];
    
    unprotect_memory();
    st[__NR_mmap] = (unsigned long) hook_mmap;
    st[__NR_munmap] = (unsigned long) hook_munmap;
    protect_memory();
    printk (KERN_INFO "Hooks installed !\n");

    queue_delayed_work(queue, &task, LOGGING_WAITING_TIMER_JIFFIES);

    return 0;
}

static void __exit module_unload(void)
{
    unprotect_memory();
    st[__NR_mmap] = (unsigned long) orig_mmap;
    st[__NR_munmap] = (unsigned long) orig_munmap;
    protect_memory();
    onexit = 1;
	cancel_delayed_work(&task);
	flush_workqueue(queue);
	destroy_workqueue(queue);
    mutex_destroy(&creds_lock);
    mutex_destroy(&log_lock);
    if (suspicious_processes)
        kfree(suspicious_processes);

    printk(KERN_INFO "Original syscalls restored\n");
}

module_init(module_load);
module_exit(module_unload);

MODULE_LICENSE("GPL");