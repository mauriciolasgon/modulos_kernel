# 🧠 Monitoramento de Processos com Kprobes no Kernel Linux

Este projeto implementa dois módulos de kernel Linux que atuam no monitoramento de processos e análise de comportamento com foco em segurança. Utiliza kprobes para interceptar chamadas de sistema sensíveis e avaliar o nível de risco de processos em execução.

---

## 📁 Estrutura do Projeto

### 🛠️ Modulo 2 - Funcionalidades
- Análise de risco de processos com base em critérios como UID, uso de CPU, uso de memória etc...
- Leitura de arquivos abertos para identificar comportamento de I/O.
- Avaliação da quantidade de bytes enviados e recebidos por processo.
- Thread no kernel para varredura contínua.
- Interface `/proc` para exibir processos monitorados e seus níveis de risco.

---

## 🚀 Como Usar

1. Compile os módulos:
   ```bash
   make

2. Carregue o módulo:
   ```bash
   sudo insmod modulo2.ko

3. Acesse a interface /proc
   ```bash
   cat /proc/avaliador/<pid>
