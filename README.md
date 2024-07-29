Infiltrator é uma ferramenta de análise de segurança que examina URLs em busca de vulnerabilidades comuns em websites. Ela verifica a presença de falhas de segurança como XSS (Cross-Site Scripting), IDOR (Insecure Direct Object References), redirecionamentos inseguros, injeções de SQL, injeções de comandos e exposição de dados sensíveis.

Como usar:

Abra o terminal.

Execute o comando com a URL e as opções desejadas. Use os seguintes comandos:

Para realizar uma verificação rápida de todas as vulnerabilidades:

bash
Copiar código
python3 Infiltrator.py -f https://example.com
Para verificar todas as vulnerabilidades específicas:

bash
Copiar código
python3 Infiltrator.py -a https://example.com
Para verificar vulnerabilidades específicas, use uma ou mais das seguintes opções:

XSS (Cross-Site Scripting):
bash
Copiar código
python3 Infiltrator.py -c https://example.com
IDOR (Insecure Direct Object References):
bash
Copiar código
python3 Infiltrator.py -d https://example.com
Redirecionamento aberto (Open Redirect):
bash
Copiar código
python3 Infiltrator.py -r https://example.com
SQL Injection:
bash
Copiar código
python3 Infiltrator.py -s https://example.com
Command Injection:
bash
Copiar código
python3 Infiltrator.py -m https://example.com
Exposição de dados sensíveis:
bash
Copiar código
python3 Infiltrator.py -e https://example.com
Opções disponíveis:

-f, --fast: Realiza uma verificação rápida de todas as vulnerabilidades.
-a, --all: Verifica todas as vulnerabilidades específicas.
-c, --check-xss: Verifica vulnerabilidades de XSS (Cross-Site Scripting).
-d, --check-idor: Verifica vulnerabilidades de IDOR (Insecure Direct Object References).
-r, --check-redirects: Verifica vulnerabilidades de redirecionamento aberto (Open Redirect).
-s, --check-sql: Verifica vulnerabilidades de SQL Injection.
-m, --check-command: Verifica vulnerabilidades de Command Injection.
-e, --check-data: Verifica exposição de dados sensíveis.
Ao executar o comando, a ferramenta irá analisar a URL fornecida e exibir um relatório no terminal com as vulnerabilidades encontradas e exemplos de exploração.
