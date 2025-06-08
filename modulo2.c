#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/fdtable.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>


#define NR_SYSCALLS (sizeof(syscall_names) / sizeof(syscall_names[0]))
#define BUF_SIZE 128 // Tamanho do buffer para armazenar dados do processo
#define MAX_SYSCALLS 256 // Número máximo de syscalls que podemos monitorar
#define HASH_entries 8 // Número de bits para a tabela hash (2^8 = 256 entradas)




static int current_count = 0;

DEFINE_HASHTABLE(proc_table, HASH_entries); // Tabela que armazena syscalls de 256 processos
static spinlock_t table_lock;

/* Funções */
static void cleanup_zombie_entries(void);
static struct proc_data* verify_hash_entry(pid_t pid);
static struct proc_data* hash_add_entry(pid_t pid);
static void net_create_workhandler(struct work_struct *work);
static int avaliar_processo(struct task_struct *task);
static void ler_io_info(pid_t pid);
static bool is_network_syscall(const char *sname);
static int net_monitor_thread(void *data);
static void monitor_func(struct work_struct *work);
static ssize_t pd_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos);
struct proc_data* hash_add_entry(pid_t pid);
static const char *classify_risk(int score);
static int handler_pre(struct kprobe *p, struct pt_regs *regs);
static void cleanup_all_entries(void);


/* Structs */

static struct task_struct *monitor_thread;

static struct proc_dir_entry *proc_entry;

static struct delayed_work monitor_wq;

struct proc_data {
    pid_t pid;
    unsigned long syscall_count;
    u64 bytes_sent;
    u64 bytes_received;
    bool read_flag;
    struct net *net_ns;
    struct task_struct *net_thread;
    /* I/O */
    unsigned int io_read_count;
    unsigned int io_write_count;

    /* Um work dedicado para esse PID */
    struct work_struct net_work;

    struct proc_dir_entry *file;
    char buf[BUF_SIZE]; // Buffer para armazenar dados do processo

    struct hlist_node hash_node;
};
static struct kprobe *probes;

static struct workqueue_struct *net_create_wq;

static const struct proc_ops proc_fops = {
    .proc_read  = pd_read,
};

static const char * const syscall_names[] = {
    "__x64_sys_execve",     // execve
    "__x64_sys_openat",     // openat (open é chamado via openat)
    "__x64_sys_chmod",      // chmod
    "__x64_sys_fchmod",     // fchmod
    "__x64_sys_chown",      // chown
    "__x64_sys_mknod",      // mknod
    "__x64_sys_setuid",     // setuid
    "__x64_sys_setgid",     // setgid
    "__x64_sys_setresuid",  // setresuid
    "__x64_sys_setresgid",  // setresgid
    "__x64_sys_socket",     // socket
    "__x64_sys_connect",    // connect
    "__x64_sys_bind",       // bind
    "__x64_sys_accept",     // accept
    "__x64_sys_ptrace",     // ptrace
    "__x64_sys_prctl",      // prctl
    "__x64_sys_capget",     // capget
    "__x64_sys_capset" ,     // capset
    "__x64_sys_execveat",   // execveat
};

static int __init monitor_init(void)
{
    int ret;


    probes = kcalloc(NR_SYSCALLS, sizeof(struct kprobe), GFP_KERNEL);
    if (!probes) {
        printk(KERN_ERR "proc_sec_monitor: falha ao alocar memória para kprobes\n");
        return -ENOMEM;
    }

    // Para cada nome de syscall, configuramos o kprobe e o registramos
    for (int i = 0; i < NR_SYSCALLS; i++) {
        probes[i].symbol_name = syscall_names[i];    // atribui nome da syscall
        probes[i].pre_handler  = handler_pre;        // atribui handler de pré-execução
        ret = register_kprobe(&probes[i]);
        if (ret < 0) {
            printk(KERN_ERR "proc_sec_monitor: falha ao registrar kprobe para %s (erro %d)\n",
                   syscall_names[i], ret);
            // Em caso de erro, desfaz todos os que foram registrados até agora
            while (--i >= 0) {
                unregister_kprobe(&probes[i]);
            }
            kfree(probes);
            return ret;
        }
        printk(KERN_INFO "proc_sec_monitor: registrado kprobe para %s\n", syscall_names[i]);
    }

    // Criar entrada /proc/modulo2
    proc_entry = proc_mkdir("avaliador", NULL);
    if (!proc_entry)
    {
        pr_alert("Erro ao criar entrada /proc/modulo2\n");
        int i = 0;

        while (probes[i].symbol_name) {
            unregister_kprobe(&probes[i]);
            printk(KERN_INFO "Unregistered kprobe for %s\n", probes[i].symbol_name);
            i++;
        }

        return -ENOMEM;
    }

    // Iniciar thread de monitoramento
    net_create_wq = alloc_workqueue("net_create_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!net_create_wq) {
        pr_err("Falha ao criar workqueue net_create_wq\n");
        return -ENOMEM;
    }
    

    INIT_DELAYED_WORK(&monitor_wq, monitor_func);

    /* Agenda para rodar apenas uma vez após 5 segundos */
    schedule_delayed_work(&monitor_wq, msecs_to_jiffies(5000));

    return 0;
}

static void __exit monitor_exit(void)
{
    pr_info("Finalizando monitor de processos...\n");
    if (monitor_thread)
        kthread_stop(monitor_thread);

    if (proc_entry)
        proc_remove(proc_entry);
    int i = 0;
   
    while (probes[i].symbol_name) {
        unregister_kprobe(&probes[i]);
        printk(KERN_INFO "Unregistered kprobe for %s\n", probes[i].symbol_name);
        i++;
    }

    cancel_delayed_work_sync(&monitor_wq);
    flush_workqueue(net_create_wq);
    destroy_workqueue(net_create_wq);
    cleanup_all_entries();
    kfree(probes);

    pr_info("Kprobes removidos\n");
}



static ssize_t pd_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
    struct proc_data *info = (struct proc_data *)pde_data(file_inode(file));

    return simple_read_from_buffer(ubuf, count, ppos,
                                   info->buf, strlen(info->buf));
}


static void cleanup_all_entries(void)
{
    int bkt, i, cnt = 0;
    struct proc_data *entry;
    struct hlist_node *tmp;
    struct proc_data **to_remove;
    unsigned long flags;
    char name[16];



    /* 1) Reserve um array para coletar os ponteiros sem usar a pilha */
    spin_lock_irqsave(&table_lock, flags);
    if (current_count > MAX_SYSCALLS)
        cnt = MAX_SYSCALLS;
    else
        cnt = current_count;
    spin_unlock_irqrestore(&table_lock, flags);

    to_remove = kmalloc_array(cnt, sizeof(*to_remove), GFP_KERNEL);
    if (!to_remove)
        return;

    /* 2) Sob lock, retire da hash e armazene em to_remove[] */
    spin_lock_irqsave(&table_lock, flags);
    cnt = 0;
    hash_for_each_safe(proc_table, bkt, tmp, entry, hash_node) {
        hash_del(&entry->hash_node);
        to_remove[cnt++] = entry;
        current_count--;
    }
    spin_unlock_irqrestore(&table_lock, flags);

    /* 3) Agora, fora do lock, remova o arquivo em procfs e libere cada struct */
    pr_alert("Aqui");
    for (i = 0; i < cnt; i++) {
        entry = to_remove[i];
        snprintf(name, sizeof(name), "%d", entry->pid);
        remove_proc_entry(name, proc_entry);  /* pode dormir */
        cancel_work_sync(&entry->net_work);    /* garante que não haja work pendente */
        kfree(entry);
    }

    kfree(to_remove);

    /* 4) Finalmente remova o diretório raiz */
    remove_proc_entry("avaliador", NULL);
}


struct proc_data* hash_add_entry(pid_t pid){

 
    /* Adiciona uma nova entrada na tabela hash */
    struct proc_data *entry;
    /* Protege leitura/inserção concorrente */
    spin_lock(&table_lock);

    entry = verify_hash_entry(pid);
    if (entry != NULL) {
        //pr_warn("proc_sec_monitor: já existe uma entrada para PID %d\n", pid);
        spin_unlock(&table_lock);
        return entry;
    }
    if (current_count >= MAX_SYSCALLS) {
        //pr_warn("proc_sec_monitor: tabela cheia; não é possível adicionar PID %d\n", pid);
        /* Simplesmente retorna sem inserir */
        spin_unlock(&table_lock);
        return entry;
    }

    
    /* Cria nova entrada */
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    
    if (!entry) {
        //pr_err("proc_sec_monitor: falha ao alocar memória para PID %d\n", pid);
        return NULL;
    }
    
    entry->pid = pid;
    entry->syscall_count = 0; /* Inicializa contagem de syscalls */
    entry->read_flag = false;  /* Inicialmente não “lido” */
    INIT_WORK(&entry->net_work, net_create_workhandler);
    /* monta o nome do arquivo: por exemplo “1234” ou “1234.txt” */

    entry->file = NULL; // Inicializa como NULL, será criado mais tarde
    /* Insere na hash: a chave é o PID */
    hash_add(proc_table, &entry->hash_node, entry->pid);
    current_count++;
    spin_unlock(&table_lock);
    
    //pr_info("proc_sec_monitor: inserido PID %d (syscall %s)\n",pid, p->symbol_name);
    
    return entry;
}

static const char *classify_risk(int score)
{
    if (score >= 7)
        return "ALTO";
    else if (score >= 4)
        return "MÉDIO";
    else
        return "BAIXO";
}

static int avaliar_processo(struct task_struct *task)
{
    int score = 0;
    pid_t pid = task->pid;
    struct proc_data *entry;

    /* 1) Score original */
    if (__kuid_val(task->cred->uid) == 0)
        score += 2;
    if (task->exit_state == EXIT_ZOMBIE)
        score += 2;
    if (task->signal && task->signal->nr_threads > 100)
        score += 2;

    unsigned long cpu_time = task->utime + task->stime;
    if (cpu_time > 100000000)
        score += 3;
    else if (cpu_time > 50000000)
        score += 2;
    else if (cpu_time > 10000000)
        score += 1;

    if (task->signal && task->signal->tty == NULL)
        score += 1;

    if (strstr(task->comm, "backdoor") ||
        strstr(task->comm, "nc")      ||
        strstr(task->comm, "ssh")     ||
        strstr(task->comm, "crypto"))
        score += 3;

    /* 2) Atualiza read_flag e busca a entry na hash */
    spin_lock(&table_lock);
    hash_for_each_possible(proc_table, entry, hash_node, pid) {
        if (entry->pid == pid) {
            entry->read_flag = true;
            break;
        }
    }
    spin_unlock(&table_lock);

    if (!entry)
        return score;

    /* 3) Ajusta score com base em métricas de rede */
    const u64 NET_HIGH = 10 * 1024 * 1024;  // 10 MB
    const u64 NET_MED  =  1 * 1024 * 1024;  // 1 MB

    if (entry->bytes_sent + entry->bytes_received > NET_HIGH)
        score += 4;
    else if (entry->bytes_sent + entry->bytes_received > NET_MED)
        score += 2;

    /* 4) Ajusta score com base em métricas de I/O de disco */
    const unsigned int IO_HIGH = 1000;  // número de FDs abertos
    const unsigned int IO_MED  =  100;

    if (entry->io_read_count + entry->io_write_count > IO_HIGH)
        score += 3;
    else if (entry->io_read_count + entry->io_write_count > IO_MED)
        score += 1;

    /* 3) Avalia uso de syscalls */
    const unsigned long SC_HIGH = 50000;   // 50 000 chamadas
    const unsigned long SC_MED  =  5000;   // 5 000 chamadas

    if (entry->syscall_count > SC_HIGH)
        score += 3;
    else if (entry->syscall_count > SC_MED)
        score += 1;

    return score;
}


static void ler_io_info(pid_t pid)
{
    struct proc_data *entry;
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fds;
    int i, max_fds;
    unsigned int count_read = 0, count_write = 0;

    /* Inicia seção RCU para buscar a task */
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_info("ler_io_info: processo com PID %d não encontrado.\n", pid);
        return;
    }

    /* Protege acesso a task->files */
    task_lock(task);
    files = rcu_dereference(task->files);
    if (!files) {
        task_unlock(task);
        rcu_read_unlock();
        pr_info("ler_io_info: nenhum files_struct para PID %d.\n", pid);
        return;
    }

    /* Bloqueia tabela de file descriptors */
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (fdt) {
        max_fds = fdt->max_fds;
        fds     = fdt->fd;
        for (i = 0; i < max_fds; i++) {
            struct file *f = fds[i];
            if (!f)
                continue;

            if (f->f_mode & FMODE_READ)
                count_read++;
            if (f->f_mode & FMODE_WRITE)
                count_write++;
        }
    }
    spin_unlock(&files->file_lock);

    /* Libera lock da task e RCU */
    task_unlock(task);
    rcu_read_unlock();
    spin_lock(&table_lock);
    hash_for_each_possible(proc_table, entry, hash_node, pid) {
        if (entry->pid == pid){
            entry->io_read_count +=count_read;
            entry->io_write_count +=count_write; 
            break;
        }
    }
    spin_unlock(&table_lock);
    /* Loga resultados */
    pr_info("ler_io_info: PID %d | arquivos abertos => leitura: %u, escrita: %u\n",
            pid, count_read, count_write);
}

static int net_monitor_thread(void *data)
{
    struct proc_data *entry = data;
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    int i;
    u64 total_sent = 0;
    u64 total_received = 0;
    u64 local_sent, local_received;

    /* Busca a task correspondente ao PID */
    rcu_read_lock();
    task = pid_task(find_vpid(entry->pid), PIDTYPE_PID);
    if (!task || task->exit_state == EXIT_ZOMBIE || task->exit_state == EXIT_DEAD) {
        rcu_read_unlock();
        goto update_and_print;
    }

    /* Atualiza namespace de rede se houver mudança */
    if (entry->net_ns != task->nsproxy->net_ns)
        entry->net_ns = task->nsproxy->net_ns;

    /* Obtém tabela de file descriptors */
    files = rcu_dereference(task->files);
    if (!files) {
        rcu_read_unlock();
        goto update_and_print;
    }

    fdt = files_fdtable(files);
    if (!fdt) {
        rcu_read_unlock();
        goto update_and_print;
    }

    /* Itera sobre todos os descritores para somar estatísticas de rede */
    for (i = 0; i < fdt->max_fds; i++) {
        struct file *f = rcu_dereference(fdt->fd[i]);
        struct socket *sock;
        struct sock *sk;

        if (!f || !S_ISSOCK(file_inode(f)->i_mode))
            continue;

        sock = f->private_data;
        if (!sock)
            continue;

        sk = sock->sk;
        if (!sk)
            continue;

        /* IPv4 e IPv6: TCP e UDP */
        if (sk->sk_protocol == IPPROTO_TCP) {
            struct tcp_sock *tp = tcp_sk(sk);
            total_received += tp->bytes_received;
            total_sent     += tp->bytes_acked;
        } else if (sk->sk_protocol == IPPROTO_UDP) {
            total_received += atomic_read(&sk->sk_rmem_alloc);
        }
    }
    rcu_read_unlock();

update_and_print:
    /* Atualiza counters compartilhados sob lock e captura para impressão */
    spin_lock(&table_lock);
    entry->bytes_sent     += total_sent;
    entry->bytes_received += total_received;
    local_sent    = entry->bytes_sent;
    local_received = entry->bytes_received;
    spin_unlock(&table_lock);

    /* Imprime valores atualizados */
    pr_info("Network monitor (thread): PID %d -> sent=%llu recv=%llu\n",
            entry->pid, local_sent, local_received);

    return 0;
}



static void net_create_workhandler(struct work_struct *work)
{
    struct proc_data *entry;
    struct task_struct *thr;

    /* 1) Recupera entry a partir do work */
    entry = container_of(work, struct proc_data, net_work);

    /* 2) Primeiro, faz uma seção crítica mínima para marcar “criação em andamento” */
    spin_lock(&table_lock);
    if (entry->net_thread == NULL) {
        /* Marcamos que já iniciamos a criação, 
           atribuindo um valor de “sentinela” que nunca será um kthread válido */
        entry->net_thread = ERR_PTR(-EINPROGRESS);
    } else {
        /* Se já não for NULL (pode ser sentinel, ou kthread válido),
           apenas saímos: nada a fazer */
        spin_unlock(&table_lock);
        return;
    }
    spin_unlock(&table_lock);

    /* 3) Fora do spinlock, chamamos KTHREAD_RUN de fato (contexto de processo) */
    thr = kthread_run(net_monitor_thread, entry, "net_mon_%d", entry->pid);
    if (IS_ERR(thr)) {
        pr_err("Falha ao criar thread de rede p/ PID %d\n", entry->pid);
        thr = NULL;
    } else {
        pr_info("Thread de rede criada para PID %d\n", entry->pid);
    }

    /* 4) Volta a segurar o spinlock para gravar o ponteiro real ou NULL em entry->net_thread */
    spin_lock(&table_lock);
    entry->net_thread = thr;  /* thr pode ser NULL em caso de erro, ou ponteiro válido */
    spin_unlock(&table_lock);
}




static void monitor_func(struct work_struct *work)
{
    struct task_struct *task;
    struct proc_data *entry;

    /* Mesmo laço de monitor_func */
    for_each_process(task) {
        if (task->exit_state == EXIT_ZOMBIE || task->exit_state == EXIT_DEAD)
            continue;
        if (strstr(task->comm, "systemd") || strstr(task->comm, "dbus"))
            continue;

        entry=hash_add_entry((pid_t)task->pid);
            
        if(entry != NULL && entry->file == NULL){
            char name[16];
            snprintf(name, sizeof(name), "%d", task->pid);
            entry->file = proc_create_data(name, 0666, proc_entry, &proc_fops, entry);
        
            if (!entry->file) {
                pr_err("Não foi possível criar /proc/avaliador/%s\n", name);
            }
        }
            /* Se já existe uma entrada, apenas atualiza o buffer */
        /* cria /proc/avaliador/<pid> — supondo que proc_entry aponte para /proc/avaliador */

        if (__kuid_val(task->cred->uid) != 0) {
            ler_io_info(task->pid);
        }
        int score = avaliar_processo(task);
        const char *nivel = classify_risk(score);

        if (entry != NULL) {
            snprintf(entry->buf, BUF_SIZE,
                " Score: %d |  Risco %s\n", score, nivel);
        }
        
        pr_info("PID: %d | Nome: %s | Score: %d | Risco: %s\n",task->pid, task->comm, score, nivel);


    }

    /* Limpa entradas de zumbis */
    cleanup_zombie_entries();

    /* Reagendar o work para daqui a 5 segundos */
    schedule_delayed_work(&monitor_wq, msecs_to_jiffies(5000));
}




static void cleanup_zombie_entries(void)
{
    int bkt, i;
    struct proc_data *entry;
    struct hlist_node *tmp;
    struct proc_data **to_remove;
    int remove_count = 0;
    unsigned long flags;
    char name[16];

    /* aloca array temporário fora da pilha */
    to_remove = kmalloc_array(MAX_SYSCALLS,
                              sizeof(*to_remove),
                              GFP_KERNEL);
    if (!to_remove)
        return;

    /* 1) coleta, sob RCU, as entradas que devem ser removidas */
    rcu_read_lock();
    hash_for_each_safe(proc_table, bkt, tmp, entry, hash_node) {
        struct task_struct *task =
            pid_task(find_vpid(entry->pid), PIDTYPE_PID);

        if ((!task ||
             task->exit_state == EXIT_ZOMBIE ||
             task->exit_state == EXIT_DEAD)
            && entry->read_flag)
        {
            if (remove_count < MAX_SYSCALLS)
                to_remove[remove_count++] = entry;
        }
    }
    rcu_read_unlock();

    /* 2) para cada entry marcada, remove do procfs, da hash e libera memória */
    for (i = 0; i < remove_count; i++) {
        entry = to_remove[i];

        /* remove do /proc/avaliador – pode dormir */
        snprintf(name, sizeof(name), "%d", entry->pid);
        pr_alert("Removendo PID %d de /proc/avaliador\n", entry->pid);
        remove_proc_entry(name, proc_entry);
        

        /* remove da hash e ajusta contador sob lock */
        spin_lock_irqsave(&table_lock, flags);
        hash_del(&entry->hash_node);
        current_count--;
        spin_unlock_irqrestore(&table_lock, flags);

        /* libera o próprio struct */
        kfree(entry);
    }

    /* libera o array temporário */
    kfree(to_remove);
}



static bool is_network_syscall(const char *sname)
{
    return (!strcmp(sname, "__x64_sys_socket")   ||
            !strcmp(sname, "__x64_sys_connect")  ||
            !strcmp(sname, "__x64_sys_bind")     ||
            !strcmp(sname, "__x64_sys_accept"));
}

struct proc_data* verify_hash_entry(pid_t pid){
    struct proc_data *entry;
        /* Verifica se já existe uma entrada para este PID */
    hash_for_each_possible(proc_table, entry, hash_node, pid) {
        if (entry->pid == pid) {
            
            return entry;
        }
    }
    return NULL;
}


// Kprobe handler 
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = current->pid;
    struct proc_data *entry;

    /* Protege leitura/inserção concorrente */

    entry=hash_add_entry(pid);

    spin_lock(&table_lock);
    if(entry != NULL){
        entry->syscall_count++; /* Incrementa contagem de syscalls */
    }else{
        spin_unlock(&table_lock);
        return 0;
    }
    /* 4) Se a syscall atual é de rede e não há thread ativa, cria uma nova thread */
    if (is_network_syscall(p->symbol_name) && !entry->net_thread) {
        /* “Kick” o work para eventualmente criar a thread em contexto de kworker */
        queue_work(net_create_wq,  &entry->net_work);
    }
    spin_unlock(&table_lock);
    return 0;
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo que monitora processos com kprobes em __x64_sys_execve e __x64_sys_execveat");