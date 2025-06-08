#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/sysinfo.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/cpumask.h>

#define DEVICE_NAME "kfetch"
#define CLASS_NAME  "kfetch_class"

/* Máscaras de informação */
#define KFETCH_RELEASE    (1 << 0)
#define KFETCH_NUM_CPUS   (1 << 1)
#define KFETCH_CPU_MODEL  (1 << 2)
#define KFETCH_MEM        (1 << 3)
#define KFETCH_UPTIME     (1 << 4)
#define KFETCH_NUM_PROCS  (1 << 5)
#define KFETCH_FULL_INFO  ((1 << 6) - 1)

/* Códigos ANSI */
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static int            major_number;
static struct class  *kfetch_class  = NULL;
static struct device *kfetch_device = NULL;
static struct cdev   kfetch_cdev;
static DEFINE_MUTEX( kfetch_mutex );

static int  info_mask     = KFETCH_FULL_INFO;
static char *kfetch_buffer;

static int     kfetch_open(struct inode*, struct file*);
static int     kfetch_release(struct inode*, struct file*);
static ssize_t kfetch_read(struct file*, char __user*, size_t, loff_t*);
static ssize_t kfetch_write(struct file*, const char __user*, size_t, loff_t*);
static void    build_info_buffer(void);

static const struct file_operations fops = {
    .owner   = THIS_MODULE,
    .open    = kfetch_open,
    .release = kfetch_release,
    .read    = kfetch_read,
    .write   = kfetch_write,
};

static int __init kfetch_init(void)
{
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0)
        return major_number;

    kfetch_class = class_create(CLASS_NAME);
    if (IS_ERR(kfetch_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(kfetch_class);
    }

    kfetch_device = device_create(kfetch_class, NULL,
                                  MKDEV(major_number, 0),
                                  NULL, DEVICE_NAME);
    if (IS_ERR(kfetch_device)) {
        class_destroy(kfetch_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(kfetch_device);
    }

    cdev_init(&kfetch_cdev, &fops);
    cdev_add(&kfetch_cdev, MKDEV(major_number, 0), 1);

    mutex_init(&kfetch_mutex);
    kfetch_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kfetch_buffer)
        return -ENOMEM;

    pr_info("kfetch: módulo carregado\n");
    return 0;
}

static void __exit kfetch_exit(void)
{
    kfree(kfetch_buffer);
    mutex_destroy(&kfetch_mutex);

    cdev_del(&kfetch_cdev);
    device_destroy(kfetch_class, MKDEV(major_number, 0));
    class_destroy(kfetch_class);
    unregister_chrdev(major_number, DEVICE_NAME);

    pr_info("kfetch: módulo descarregado\n");
}

static int kfetch_open(struct inode *inodep, struct file *filep)
{
    if (!mutex_trylock(&kfetch_mutex)) {
        pr_alert("kfetch: dispositivo ocupado\n");
        return -EBUSY;
    }
    return 0;
}

static int kfetch_release(struct inode *inodep, struct file *filep)
{
    mutex_unlock(&kfetch_mutex);
    return 0;
}

static ssize_t kfetch_write(struct file *filep,
                            const char __user *buffer,
                            size_t len,
                            loff_t *offset)
{
    int user_mask;

    if (len < sizeof(int))
        return -EINVAL;
    if (copy_from_user(&user_mask, buffer, sizeof(int)))
        return -EFAULT;

    info_mask = user_mask;
    return sizeof(int);
}

static ssize_t kfetch_read(struct file *filep,
                           char __user *buffer,
                           size_t len,
                           loff_t *offset)
{
    size_t data_len;

    if (*offset > 0)
        return 0;

    build_info_buffer();
    data_len = strlen(kfetch_buffer);

    if (copy_to_user(buffer, kfetch_buffer, data_len))
        return -EFAULT;

    *offset += data_len;
    return data_len;
}

static void build_info_buffer(void)
{
    struct new_utsname *uts = utsname();
    struct sysinfo si;
    struct timespec64 uptime;
    unsigned int online_cpus, total_cpus;
    unsigned long free_mem, total_mem;
    unsigned int num_procs = 0;
    struct task_struct *task;
    size_t pos = 0, i, host_len;
    char sep[256];

    /* coleta de dados */
    si_meminfo(&si);
    ktime_get_boottime_ts64(&uptime);

    memset(kfetch_buffer, 0, PAGE_SIZE);

    /* 1) Logo “K T L” em ASCII art (ciano) */
    pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
        ANSI_COLOR_CYAN
        " _  __   _____   _     \n"
        "| |/ /  |_   _| | |    \n"
        "| ' /     | |   | |    \n"
        "| . \\     | |   | |____\n"
        "|_|\\_\\    |_|   |______|\n"
        ANSI_COLOR_RESET);

    /* 2) Hostname (sempre em amarelo) */
    host_len = strlen(uts->nodename);
    pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                     ANSI_COLOR_YELLOW "%s\n" ANSI_COLOR_RESET,
                     uts->nodename);

    /* 3) Separador dinâmico (amarelo) */
    if (host_len >= sizeof(sep))
        host_len = sizeof(sep) - 1;
    for (i = 0; i < host_len; ++i)
        sep[i] = '-';
    sep[host_len] = '\0';
    pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                     ANSI_COLOR_YELLOW "%s\n" ANSI_COLOR_RESET,
                     sep);

    /* 4) Linhas conforme máscara (labels em amarelo) */
    if (info_mask & KFETCH_RELEASE)
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "Kernel:  " ANSI_COLOR_RESET "%s\n",
                         uts->release);

    if (info_mask & KFETCH_CPU_MODEL)
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "CPU:     " ANSI_COLOR_RESET "%s\n",
                         boot_cpu_data.x86_model_id);

    if (info_mask & KFETCH_NUM_CPUS) {
        online_cpus = num_online_cpus();
        total_cpus  = num_possible_cpus();
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "CPUs:    " ANSI_COLOR_RESET "%u / %u\n",
                         online_cpus, total_cpus);
    }

    if (info_mask & KFETCH_MEM) {
        free_mem  = (si.freeram  * si.mem_unit) >> 20;
        total_mem = (si.totalram * si.mem_unit) >> 20;
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "Mem:     " ANSI_COLOR_RESET "%lu MB / %lu MB\n",
                         free_mem, total_mem);
    }

    if (info_mask & KFETCH_NUM_PROCS) {
        rcu_read_lock();
        for_each_process(task)
            num_procs++;
        rcu_read_unlock();
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "Proc:    " ANSI_COLOR_RESET "%u\n",
                         num_procs);
    }

    if (info_mask & KFETCH_UPTIME) {
        pos += scnprintf(kfetch_buffer + pos, PAGE_SIZE - pos,
                         ANSI_COLOR_YELLOW "Uptime:  " ANSI_COLOR_RESET "%llu mins\n",
                         (unsigned long long)(uptime.tv_sec / 60));
    }
}

module_init(kfetch_init);
module_exit(kfetch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo do kernel para exibir informações via /dev/kfetch com logo KTL colorido");