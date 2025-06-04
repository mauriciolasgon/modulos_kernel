#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/hashtable.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <trace/events/syscalls.h>



/*
---------------------------------
    DATA STRUCTURES
---------------------------------
*/

typdef struct {
    pid_t pid;
    char comm[TASK_COMM_LEN];
    int cpu_usage;
    int memory_usage;
    unsigned long io_read;
    unsigned long io_write;
    int network_usage;
    int syscall_count;
    // Outros campos podem ser adicionados conforme necessário
} process_info_t;

static struct task_struct *monitor_thread;

/*
--------------------------------
    HOOK REGISTRATION
--------------------------------
*/

/*
--------------------------------
    USER INTERFACE
--------------------------------
*/

/*
 * Handler do tracepoint sys_enter: dispara em toda entrada de syscall.
 * A assinatura deve ser:
 *   void (*handler)(void *ignore, struct pt_regs *regs, long id)
 * que corresponde ao prototype exigido por register_trace_sys_enter().
 *
 * 'id' é o número da syscall. Aqui incrementamos o contador e imprimimos mensagem.
 */
static void trace_sys_enter_handler(void *ignore, struct pt_regs *regs, long id)
{
    pid_t pid = current->pid;
    long syscall_nr = id;

    syscall_count++;
    printk(KERN_INFO "trace_sys_enter: PID %d chamou syscall número %ld\n",
           pid, syscall_nr);
}

/* Função que a thread executa periodicamente */
static int monitor_func(void *data)
{
    struct task_struct *task;

    while (!kthread_should_stop()) {
        pr_info("=== Monitorando processos ===\n");
        printk(KERN_INFO "Número de syscalls chamadas: %d\n", syscall_count);
        for_each_process(task) {
            /* Agora apenas imprimimos PID e nome (sem usar 'state', que pode não existir) */
            pr_info("PID: %d | Nome: %s | IO : \n",
                    task->pid, task->comm, task->ioc);
        }
        msleep(5000);
    }

    return 0;
}

/* Inicialização do módulo */
static int __init monitor_init(void)
{
    int ret;

    pr_info("Iniciando monitor de processos...\n");

    /* Registrar handler no tracepoint sys_enter */
    ret = register_trace_sys_enter(trace_sys_enter_handler, NULL);
    if (ret < 0) {
        pr_err("monitor: falha ao registrar trace_sys_enter (err=%d)\n", ret);
        return ret;
    }

    /* Criar a thread de monitoramento */
    monitor_thread = kthread_run(monitor_func, NULL, "monitor_proc_thread");
    if (IS_ERR(monitor_thread)) {
        pr_alert("monitor: erro ao criar thread de monitoramento\n");
        unregister_trace_sys_enter(trace_sys_enter_handler, NULL);
        return PTR_ERR(monitor_thread);
    }

    pr_info("monitor: módulo carregado com sucesso\n");
    return 0;
}

/* Finalização do módulo */
static void __exit monitor_exit(void)
{
    pr_info("Finalizando monitor de processos...\n");

    if (monitor_thread)
        kthread_stop(monitor_thread);

    unregister_trace_sys_enter(trace_sys_enter_handler, NULL);

    pr_info("monitor: módulo descarregado\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo que monitora syscalls usando trace_sys_enter e lista processos");
