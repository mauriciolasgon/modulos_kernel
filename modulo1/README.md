# 🧠 kfetch_mod — Módulo de Kernel Linux para Informações do Sistema com Arte ASCII

O `kfetch_mod` é um módulo de kernel Linux desenvolvido para exibir informações detalhadas do sistema via dispositivo de caractere `/dev/kfetch`. Ele inclui uma arte ASCII colorida com o logo "KTL" e exibe dados como a versão do kernel, modelo da CPU, memória, uptime, entre outros, de acordo com uma máscara configurável.

---

## 🛠️ Funcionalidades

- ✅ Arte ASCII com o logo “KTL” (iniciais dos membros do grupo, colorida com ANSI)
- ✅ Informações configuráveis do sistema:
  - Versão do kernel
  - Modelo da CPU
  - Número de CPUs online / total
  - Memória RAM livre / total
  - Tempo de atividade (uptime)
  - Número total de processos
- ✅ Controle de concorrência com `mutex`
- ✅ Comunicação via dispositivo `/dev/kfetch`
- ✅ Leitura segura e personalizada
- ✅ Escrita de máscara com `write()` (formato `int`)

---

### Compilar o módulo

```bash
make

sudo insmod kfetch_mod.ko

sudo dmesg | tail

sudo cat /dev/kfetch

```
