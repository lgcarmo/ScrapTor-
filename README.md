# ScrapForeverTor
# Scrap Forever (Tor Edition)

Scrap Forever é uma ferramenta de coleta contínua que descobre novas URLs, persiste todos os metadados em SQLite e mantém o estado do crawler por meio de checkpoints, permitindo retomar investigações sempre que necessário. Foi criada para apoiar pesquisas em surface e deep web, com suporte nativo ao Tor e a proxies personalizados.

## Recursos principais

- **Coleta contínua com threads**: processa lotes de URLs em paralelo, segue links (`href` e URLs absolutas) e mantém fila/controle de duplicados.
- **Suporte a Tor e proxies**: configura o `socket` para SOCKS5, testa conectividade com domínios `.onion` e aceita proxies HTTP/HTTPS.
- **Persistência detalhada**: registra status HTTP, títulos, IPs, CNAME, servidores, cabeçalhos, tecnologias detectadas, tempo de resposta e tamanho do conteúdo em `scrap_data.db`.
- **Checkpoint/restore**: salva fila, URLs processadas, argumentos de execução e caminho do arquivo de saída em `scrap_checkpoint.pkl`. Com `--restore`, retomamos do ponto exato, sem reprover `-t` ou `-o`.
- **Filtro Deep Only**: quando ativado, ignora automaticamente URLs da surface web, concentrando-se em domínios `.onion`, `.i2p` e equivalentes.
- **Relatórios automáticos**: ao finalizar, gera `all_urls.txt`, imprime estatísticas do banco e fecha o arquivo de saída utilizado durante a execução.

## Pré-requisitos

- Python 3.8+
- Dependências do sistema:
  - `libffi-dev`, `libssl-dev` (para Tor/socks, dependendo da distro)
  - Pacotes Python instalados via `pip`: `requests`, `urllib3`, `beautifulsoup4`, `dnspython`, `python-whois`, `pysocks`
- Tor configurado localmente (opcional, necessário para `--tor`)

Instale as dependências Python:

```bash
pip install requests urllib3 beautifulsoup4 dnspython python-whois pysocks
```
## Uso rápido
Coleta inicial
```python3 scrap_forever_Tor.py \
  -t https://example.com \
  -o discovered_urls.txt \
  --db dados.sqlite
  ```
### Argumentos principais:
```
-t: URL inicial a ser processada.
-o: caminho do arquivo onde cada URL consumida será registrada.
--db: arquivo SQLite (padrão scrap_data.db).
-n: número de threads concorrentes (padrão 10).
--delay: pausa entre requisições por thread (padrão 1s).
--max-urls: limite de URLs a processar (0 = ilimitado).
--deep-only: restringe a domínios deep web.
--no-checkpoint: desativa gravação de checkpoints.
```

### Usando Tor
```bash python3 scrap_forever_Tor.py \
  -t http://onion-address.onion \
  -o saida.txt \
  --tor \
  --tor-port 9050
  ```
  
Certifique-se de que o serviço Tor esteja ativo na porta especificada. A ferramenta testa conectividade via check.torproject.org.

### Retomada com checkpoint
Ao finalizar ou a cada lote (ou múltiplos de 10 URLs), o programa salva scrap_checkpoint.pkl. Para retomar sem reescrever os parâmetros:

``` bash 
python3 scrap_forever_Tor.py --restore
O caminho do arquivo de saída original é restaurado automaticamente em modo append. Caso deseje sobrescrever, forneça um novo -o.
```
### Dicas e boas práticas
** Combine --max-urls com --delay para controlar o ritmo de coleta.
** Ative --no-checkpoint quando quiser rodadas rápidas sem persistência de estado.
** Ao investigar deep web, rode a ferramenta dentro de um ambiente seguro (VPN, VM endurecida etc.).
** Use o banco SQLite para análises subsequentes, exportando filtros via SQL (por exemplo, todas as URLs com status_code = 200 ou is_deep_web = 1).
