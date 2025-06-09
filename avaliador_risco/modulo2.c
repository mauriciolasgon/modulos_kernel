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

// Define o número de syscalls monitoradas (tamanho do array syscall_names)
#define NR_SYSCALLS (sizeof(syscall_names) / sizeof(syscall_names[0]))
#define BUF_SIZE 128 // Tamanho do buffer para armazenar dados do processo
#define MAX_SYSCALLS 256 // Máximo de syscalls que podem ser monitoradas
#define HASH_entries 8 // Número de bits da tabela hash (2^8 = 256 entradas)

static int current_count = 0;

// Define uma tabela hash para armazenar dados dos processos monitorados
DEFINE_HASHTABLE(proc_table, HASH_entries);
static spinlock_t table_lock; // Spinlock para proteger a tabela hash

/* Declarações das funções usadas */
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

/* Estruturas de dados */

// Thread responsável pelo monitoramento
static struct task_struct *monitor_thread;

// Entrada do procfs para exposição dos dados
static struct proc_dir_entry *proc_entry;

// Trabalho diferido para agendamento periódico de monitoramento
static struct delayed_work monitor_wq;

// Estrutura que armazena informações de cada processo monitorado
struct proc_data {
    pid_t pid;                  // PID do processo
    unsigned long syscall_count; // Contador de syscalls feitas pelo processo
    u64 bytes_sent;             // Bytes enviados (rede)
    u64 bytes_received;         // Bytes recebidos (rede)
    bool read_flag;             // Flag para controle interno
    struct net *net_ns;         // Namespace de rede do processo
    struct task_struct *net_thread; // Thread para monitorar rede

    unsigned int io_read_count;  // Contagem de operações de leitura
    unsigned int io_write_count; // Contagem de operações de escrita

    struct work_struct net_work; // Trabalho associado para monitoramento de rede

    struct proc_dir_entry *file; // Entrada procfs específica para o processo
    char buf[BUF_SIZE];          // Buffer para armazenar dados temporários

    struct hlist_node hash_node; // Nó para inserção na tabela hash
};

static struct kprobe *probes; // Array de kprobes para monitoramento das syscalls

static struct workqueue_struct *net_create_wq; // Workqueue para criação de trabalhos de rede

// Operações da entrada /proc para leitura dos dados (função pd_read)
static const struct proc_ops proc_fops = {
    .proc_read  = pd_read,
};

// Array com nomes das syscalls que serão monitoradas via kprobes
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
    "__x64_sys_capset" ,    // capset
    "__x64_sys_execveat",   // execveat
};

/* Função de inicialização do módulo */
static int __init monitor_init(void)
{
    int ret;

    // Aloca memória para array de kprobes para cada syscall que será monitorada
    probes = kcalloc(NR_SYSCALLS, sizeof(struct kprobe), GFP_KERNEL);
    if (!probes) {
        printk(KERN_ERR "proc_sec_monitor: falha ao alocar memória para kprobes\n");
        return -ENOMEM;
    }

    // Para cada syscall, configura o kprobe com o nome e o handler, e registra
    for (int i = 0; i < NR_SYSCALLS; i++) {
        probes[i].symbol_name = syscall_names[i];    // Define o nome da syscall a monitorar
        probes[i].pre_handler  = handler_pre;        // Define a função a ser chamada antes da syscall
        ret = register_kprobe(&probes[i]);           // Registra o kprobe no kernel
        if (ret < 0) {
            printk(KERN_ERR "proc_sec_monitor: falha ao registrar kprobe para %s (erro %d)\n",
                   syscall_names[i], ret);
            // Caso falhe, desfaz registro dos kprobes já registrados
            while (--i >= 0) {
                unregister_kprobe(&probes[i]);
            }
            kfree(probes);
            return ret;
        }
        printk(KERN_INFO "proc_sec_monitor: registrado kprobe para %s\n", syscall_names[i]);
    }

    // Cria diretório /proc/avaliador para expor os dados do monitor
    proc_entry = proc_mkdir("avaliador", NULL);
    if (!proc_entry)
    {
        pr_alert("Erro ao criar entrada /proc/avaliador\n");

        // Remove kprobes em caso de falha
        int i = 0;
        while (probes[i].symbol_name) {
            unregister_kprobe(&probes[i]);
            printk(KERN_INFO "Unregistered kprobe for %s\n", probes[i].symbol_name);
            i++;
        }
        return -ENOMEM;
    }

    // Cria uma workqueue para lidar com trabalhos de rede assincronamente
    net_create_wq = alloc_workqueue("net_create_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!net_create_wq) {
        pr_err("Falha ao criar workqueue net_create_wq\n");
        return -ENOMEM;
    }

    // Inicializa um trabalho diferido (delayed_work) para a função monitor_func
    INIT_DELAYED_WORK(&monitor_wq, monitor_func);

    // Agenda o trabalho diferido para executar após 5 segundos (5000 ms)
    schedule_delayed_work(&monitor_wq, msecs_to_jiffies(5000));

    return 0;
}

/* Função chamada na remoção do módulo */
static void __exit monitor_exit(void)
{
    pr_info("Finalizando monitor de processos...\n");

    // Para a thread de monitoramento, caso esteja rodando
    if (monitor_thread)
        kthread_stop(monitor_thread);

    // Remove a entrada do /proc criada
    if (proc_entry)
        proc_remove(proc_entry);

    // Desregistra todos os kprobes registrados
    int i = 0;
    while (probes[i].symbol_name) {
        unregister_kprobe(&probes[i]);
        printk(KERN_INFO "Unregistered kprobe for %s\n", probes[i].symbol_name);
        i++;
    }

    // Cancela o trabalho diferido e destrói a workqueue criada
    cancel_delayed_work_sync(&monitor_wq);
    flush_workqueue(net_create_wq);
    destroy_workqueue(net_create_wq);

    // Limpa todos os dados da tabela hash de processos monitorados
    cleanup_all_entries();

    // Libera memória dos kprobes
    kfree(probes);

    pr_info("Kprobes removidos\n");
}

// Função para ler dados do arquivo /proc associado a um processo
static ssize_t pd_read(struct file *file, char __user *ubuf,
                       size_t count, loff_t *ppos)
{
    // Obtém o ponteiro para a estrutura proc_data armazenada na entrada /proc
    struct proc_data *info = (struct proc_data *)pde_data(file_inode(file));

    // Copia dados do buffer interno para o espaço do usuário, controlando a posição e tamanho
    return simple_read_from_buffer(ubuf, count, ppos,
                                   info->buf, strlen(info->buf));
}

// Função para limpar todas as entradas armazenadas na tabela hash
static void cleanup_all_entries(void)
{
    int bkt, i, cnt = 0;
    struct proc_data *entry;
    struct hlist_node *tmp;
    struct proc_data **to_remove; // Array para armazenar entradas para remoção
    unsigned long flags;
    char name[16];

    // 1) Sob lock, determina quantas entradas existem para liberar memória dinamicamente
    spin_lock_irqsave(&table_lock, flags);
    if (current_count > MAX_SYSCALLS)
        cnt = MAX_SYSCALLS;
    else
        cnt = current_count;
    spin_unlock_irqrestore(&table_lock, flags);

    // Aloca array para armazenar temporariamente os ponteiros das entradas
    to_remove = kmalloc_array(cnt, sizeof(*to_remove), GFP_KERNEL);
    if (!to_remove)
        return;

    // 2) Sob lock, remove todas as entradas da tabela hash e salva no array para remoção
    spin_lock_irqsave(&table_lock, flags);
    cnt = 0;
    hash_for_each_safe(proc_table, bkt, tmp, entry, hash_node) {
        hash_del(&entry->hash_node);
        to_remove[cnt++] = entry;
        current_count--;
    }
    spin_unlock_irqrestore(&table_lock, flags);

    // 3) Fora do lock, remove as entradas do /proc e libera memória de cada struct
    pr_alert("Aqui");
    for (i = 0; i < cnt; i++) {
        entry = to_remove[i];
        snprintf(name, sizeof(name), "%d", entry->pid);
        remove_proc_entry(name, proc_entry);  // Remove entrada no /proc (pode dormir)
        cancel_work_sync(&entry->net_work);   // Garante que o work associado não esteja em execução
        kfree(entry);                         // Libera memória da struct
    }

    kfree(to_remove);

    // 4) Remove o diretório raiz do /proc "avaliador"
    remove_proc_entry("avaliador", NULL);
}

// Função que adiciona uma nova entrada para um PID na tabela hash
struct proc_data* hash_add_entry(pid_t pid){
    struct proc_data *entry;

    // Protege acesso concorrente à tabela hash
    spin_lock(&table_lock);

    // Verifica se já existe entrada para o PID
    entry = verify_hash_entry(pid);
    if (entry != NULL) {
        spin_unlock(&table_lock);
        return entry;
    }

    // Se tabela cheia, não adiciona nova entrada
    if (current_count >= MAX_SYSCALLS) {
        spin_unlock(&table_lock);
        return entry;
    }

    // Aloca nova estrutura para o processo, com inicialização zerada
    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        // Falha ao alocar memória
        return NULL;
    }

    // Inicializa campos
    entry->pid = pid;
    entry->syscall_count = 0; // Nenhuma syscall ainda
    entry->read_flag = false;  // Não foi lida ainda

    // Inicializa work struct que será usado para operações de rede associadas
    INIT_WORK(&entry->net_work, net_create_workhandler);

    entry->file = NULL; // Ainda não criou arquivo /proc específico para este PID

    // Insere a estrutura na tabela hash usando o PID como chave
    hash_add(proc_table, &entry->hash_node, entry->pid);
    current_count++;
    spin_unlock(&table_lock);

    return entry;
}

// Função para classificar risco baseado em uma pontuação
static const char *classify_risk(int score)
{
    if (score >= 7)
        return "ALTO";
    else if (score >= 4)
        return "MÉDIO";
    else
        return "BAIXO";
}

// Função para avaliar um processo e calcular um score de risco
static int avaliar_processo(struct task_struct *task)
{
    int score = 0;
    pid_t pid = task->pid;
    struct proc_data *entry;

    // 1) Pontos baseados em propriedades do processo
    if (__kuid_val(task->cred->uid) == 0)       // Processo root ganha +2
        score += 2;
    if (task->exit_state == EXIT_ZOMBIE)        // Zombie +2
        score += 2;
    if (task->signal && task->signal->nr_threads > 100) // Muitos threads +2
        score += 2;

    // Tempo de CPU usado: mais tempo, maior o score
    unsigned long cpu_time = task->utime + task->stime;
    if (cpu_time > 100000000)
        score += 3;
    else if (cpu_time > 50000000)
        score += 2;
    else if (cpu_time > 10000000)
        score += 1;

    // Se não associado a tty, +1 ponto
    if (task->signal && task->signal->tty == NULL)
        score += 1;

    // Palavras suspeitas no nome do processo aumentam score
    if (strstr(task->comm, "backdoor") ||
        strstr(task->comm, "nc")      ||
        strstr(task->comm, "ssh")     ||
        strstr(task->comm, "crypto"))
        score += 3;

    // 2) Atualiza a flag read_flag da entrada na tabela hash
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

    // 3) Ajusta score com base no tráfego de rede
    const u64 NET_HIGH = 10 * 1024 * 1024;  // 10 MB
    const u64 NET_MED  =  1 * 1024 * 1024;  // 1 MB

    if (entry->bytes_sent + entry->bytes_received > NET_HIGH)
        score += 4;
    else if (entry->bytes_sent + entry->bytes_received > NET_MED)
        score += 2;

    // 4) Ajusta score baseado na quantidade de operações I/O
    const unsigned int IO_HIGH = 1000;  // Número alto de FDs abertos
    const unsigned int IO_MED  =  100;

    if (entry->io_read_count + entry->io_write_count > IO_HIGH)
        score += 3;
    else if (entry->io_read_count + entry->io_write_count > IO_MED)
        score += 1;

    // 5) Ajusta score baseado no número de syscalls feitas
    const unsigned long SC_HIGH = 50000;   // 50 mil chamadas
    const unsigned long SC_MED  =  5000;   // 5 mil chamadas

    if (entry->syscall_count > SC_HIGH)
        score += 3;
    else if (entry->syscall_count > SC_MED)
        score += 1;

    return score;
}

// Função para ler informações de I/O (leitura/escrita) para determinado PID
static void ler_io_info(pid_t pid)
{
    struct proc_data *entry;
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fds;
    int i, max_fds;
    unsigned int count_read = 0, count_write = 0;

    // Inicia seção RCU para buscar a task_struct do processo
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_info("ler_io_info: processo com PID %d não encontrado.\n", pid);
        return;
    }

    // Protege o acesso ao objeto files da task
    task_lock(task);
    files = rcu_dereference(task->files);
    if (!files) {
        task_unlock(task);
        rcu_read_unlock();
        pr_info("ler_io_info: nenhum files_struct para PID %d.\n", pid);
        return;
    }

    // Bloqueia a tabela de file descriptors para leitura segura
    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    if (fdt) {
        max_fds = fdt->max_fds;
        fds     = fdt->fd;
        for (i = 0; i < max_fds; i++) {
            struct file *f = fds[i];
            if (!f)
                continue;

            // Conta se o FD está aberto para leitura
            if (f->f_mode & FMODE_READ)
                count_read++;
            // Conta se o FD está aberto para escrita
            if (f->f_mode & FMODE_WRITE)
                count_write++;
        }
    }
    spin_unlock(&files->file_lock);

    // Libera locks adquiridos
    task_unlock(task);
    rcu_read_unlock();

    // Atualiza a entrada da hash para este PID com as contagens
    spin_lock(&table_lock);
    hash_for_each_possible(proc_table, entry, hash_node, pid) {
        if (entry->pid == pid){
            entry->io_read_count += count_read;
            entry->io_write_count += count_write; 
            break;
        }
    }
    spin_unlock(&table_lock);

    // Loga resultado no kernel log
    pr_info("ler_io_info: PID %d | arquivos abertos => leitura: %u, escrita: %u\n",
            pid, count_read, count_write);
}

// Função que monitora estatísticas de rede de um processo em uma thread kernel
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

    // Busca a task (processo) pelo PID armazenado na entry
    rcu_read_lock();
    task = pid_task(find_vpid(entry->pid), PIDTYPE_PID);
    // Se o processo não existe ou está morto (zumbi ou dead), sai
    if (!task || task->exit_state == EXIT_ZOMBIE || task->exit_state == EXIT_DEAD) {
        rcu_read_unlock();
        goto update_and_print;
    }

    // Atualiza o namespace de rede do processo, se mudou (útil para containers/netns)
    if (entry->net_ns != task->nsproxy->net_ns)
        entry->net_ns = task->nsproxy->net_ns;

    // Obtém a estrutura files do processo (descritores abertos)
    files = rcu_dereference(task->files);
    if (!files) {
        rcu_read_unlock();
        goto update_and_print;
    }

    // Obtém a tabela de file descriptors
    fdt = files_fdtable(files);
    if (!fdt) {
        rcu_read_unlock();
        goto update_and_print;
    }

    // Itera pelos file descriptors para somar bytes enviados e recebidos por sockets
    for (i = 0; i < fdt->max_fds; i++) {
        struct file *f = rcu_dereference(fdt->fd[i]);
        struct socket *sock;
        struct sock *sk;

        // Ignora descritores não socket
        if (!f || !S_ISSOCK(file_inode(f)->i_mode))
            continue;

        sock = f->private_data;
        if (!sock)
            continue;

        sk = sock->sk;
        if (!sk)
            continue;

        // Soma estatísticas TCP (bytes recebidos e bytes confirmados enviados)
        if (sk->sk_protocol == IPPROTO_TCP) {
            struct tcp_sock *tp = tcp_sk(sk);
            total_received += tp->bytes_received;
            total_sent     += tp->bytes_acked;
        }
        // Para UDP, soma memória alocada para recepção (não é perfeito, mas um indicativo)
        else if (sk->sk_protocol == IPPROTO_UDP) {
            total_received += atomic_read(&sk->sk_rmem_alloc);
        }
    }
    rcu_read_unlock();

update_and_print:
    // Atualiza os contadores da struct entry protegidos por spinlock
    spin_lock(&table_lock);
    entry->bytes_sent     += total_sent;
    entry->bytes_received += total_received;
    local_sent    = entry->bytes_sent;
    local_received = entry->bytes_received;
    spin_unlock(&table_lock);

    // Loga a atividade de rede do processo
    pr_info("Network monitor (thread): PID %d -> sent=%llu recv=%llu\n",
            entry->pid, local_sent, local_received);

    return 0;
}

// Handler para o workqueue que cria uma thread para monitorar rede
static void net_create_workhandler(struct work_struct *work)
{
    struct proc_data *entry;
    struct task_struct *thr;

    // Recupera a entry do work_struct (container_of)
    entry = container_of(work, struct proc_data, net_work);

    // Protege criação concorrente da thread de rede
    spin_lock(&table_lock);
    if (entry->net_thread == NULL) {
        // Marca que está criando a thread (sentinela ERR_PTR)
        entry->net_thread = ERR_PTR(-EINPROGRESS);
    } else {
        // Se já existe thread ou está em criação, sai
        spin_unlock(&table_lock);
        return;
    }
    spin_unlock(&table_lock);

    // Cria a thread de monitoramento de rede no kernel
    thr = kthread_run(net_monitor_thread, entry, "net_mon_%d", entry->pid);
    if (IS_ERR(thr)) {
        pr_err("Falha ao criar thread de rede p/ PID %d\n", entry->pid);
        thr = NULL;
    } else {
        pr_info("Thread de rede criada para PID %d\n", entry->pid);
    }

    // Atualiza ponteiro da thread na struct entry, protegendo com spinlock
    spin_lock(&table_lock);
    entry->net_thread = thr;
    spin_unlock(&table_lock);
}

// Função principal que monitora todos os processos no sistema
static void monitor_func(struct work_struct *work)
{
    struct task_struct *task;
    struct proc_data *entry;

    // Percorre todos os processos do sistema
    for_each_process(task) {
        // Ignora processos zumbis e mortos
        if (task->exit_state == EXIT_ZOMBIE || task->exit_state == EXIT_DEAD)
            continue;
        // Ignora processos systemd e dbus (exemplo para reduzir ruído)
        if (strstr(task->comm, "systemd") || strstr(task->comm, "dbus"))
            continue;

        // Tenta adicionar ou obter uma entrada na tabela hash para o PID
        entry = hash_add_entry((pid_t)task->pid);

        // Se entrou pela primeira vez, cria arquivo /proc/avaliador/<pid>
        if(entry != NULL && entry->file == NULL){
            char name[16];
            snprintf(name, sizeof(name), "%d", task->pid);
            entry->file = proc_create_data(name, 0666, proc_entry, &proc_fops, entry);
            if (!entry->file) {
                pr_err("Não foi possível criar /proc/avaliador/%s\n", name);
            }
        }

        // Se não é root, atualiza informações de I/O
        if (__kuid_val(task->cred->uid) != 0) {
            ler_io_info(task->pid);
        }

        // Avalia o processo e classifica risco
        int score = avaliar_processo(task);
        const char *nivel = classify_risk(score);

        // Atualiza buffer para /proc/<pid> com score e risco
        if (entry != NULL) {
            snprintf(entry->buf, BUF_SIZE,
                " Score: %d |  Risco %s\n", score, nivel);
        }

        // Loga dados básicos do processo monitorado
        pr_info("PID: %d | Nome: %s | Score: %d | Risco: %s\n",
                task->pid, task->comm, score, nivel);
    }

    // Limpa entradas de processos zumbis da hash e do /proc
    cleanup_zombie_entries();

    // Reagenda esse work para rodar de novo em 5 segundos
    schedule_delayed_work(&monitor_wq, msecs_to_jiffies(5000));
}

// Remove entradas da hash de processos que já morreram e foram lidos
static void cleanup_zombie_entries(void)
{
    int bkt, i;
    struct proc_data *entry;
    struct hlist_node *tmp;
    struct proc_data **to_remove;
    int remove_count = 0;
    unsigned long flags;
    char name[16];

    // Aloca array para armazenar temporariamente as entradas a remover
    to_remove = kmalloc_array(MAX_SYSCALLS,
                              sizeof(*to_remove),
                              GFP_KERNEL);
    if (!to_remove)
        return;

    // Coleta entradas de processos zumbis que já foram “lidas”
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

    // Para cada entry, remove do procfs, da hash e libera memória
    for (i = 0; i < remove_count; i++) {
        entry = to_remove[i];
        snprintf(name, sizeof(name), "%d", entry->pid);
        pr_alert("Removendo PID %d de /proc/avaliador\n", entry->pid);
        remove_proc_entry(name, proc_entry);

        spin_lock_irqsave(&table_lock, flags);
        hash_del(&entry->hash_node);
        current_count--;
        spin_unlock_irqrestore(&table_lock, flags);

        kfree(entry);
    }

    // Libera array temporário
    kfree(to_remove);
}

// Verifica se uma syscall é relacionada à rede (socket, connect, bind, accept)
static bool is_network_syscall(const char *sname)
{
    return (!strcmp(sname, "__x64_sys_socket")   ||
            !strcmp(sname, "__x64_sys_connect")  ||
            !strcmp(sname, "__x64_sys_bind")     ||
            !strcmp(sname, "__x64_sys_accept"));
}

// Verifica se já existe uma entrada para o PID na hash e retorna ela
struct proc_data* verify_hash_entry(pid_t pid){
    struct proc_data *entry;
    hash_for_each_possible(proc_table, entry, hash_node, pid) {
        if (entry->pid == pid) {
            return entry;
        }
    }
    return NULL;
}

// Handler chamado antes de cada syscall monitorada (via kprobe)
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t pid = current->pid;
    struct proc_data *entry;

    // Tenta adicionar ou obter entrada para o PID atual
    entry = hash_add_entry(pid);

    spin_lock(&table_lock);
    if(entry != NULL){
        // Incrementa contador de syscalls
        entry->syscall_count++;
    } else {
        spin_unlock(&table_lock);
        return 0;
    }

    // Se a syscall é de rede e não há thread de monitoramento, agenda criação
    if (is_network_syscall(p->symbol_name) && !entry->net_thread) {
        queue_work(net_create_wq,  &entry->net_work);
    }
    spin_unlock(&table_lock);
    return 0;
}

// Macros do módulo kernel
module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo que monitora processos com kprobes em __x64_sys_execve e __x64_sys_execveat");
