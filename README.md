Infiltrator - Ferramenta de Verificação de Vulnerabilidades
Descrição
Infiltrator é uma ferramenta de verificação de vulnerabilidades desenvolvida para testar e identificar possíveis falhas de segurança em páginas da web. A ferramenta realiza uma análise de segurança automatizada em URLs fornecidas, buscando por uma variedade de vulnerabilidades comuns, incluindo:

Cross-Site Scripting (XSS)
Insecure Direct Object References (IDOR)
Open Redirects
SQL Injection
Command Injection
Exposição de Dados Sensíveis
Funcionalidades
Verificação XSS: Testa URLs para identificar se o site está vulnerável a ataques de Cross-Site Scripting.
Verificação IDOR: Testa URLs para identificar possíveis referências inseguras a objetos diretos.
Verificação de Redirecionamentos Abertos: Verifica se a aplicação permite redirecionamentos para URLs externas não confiáveis.
Verificação de SQL Injection: Testa URLs para identificar possíveis vulnerabilidades de injeção de SQL.
Verificação de Command Injection: Verifica se há possibilidade de injeção de comandos no sistema.
Verificação de Exposição de Dados Sensíveis: Identifica se dados sensíveis estão expostos nas páginas analisadas.

Como Usar

git clone https://github.com/vtkzkk/-Infiltrator.git

Execute a Ferramenta:

Execute a ferramenta a partir da linha de comando, passando a URL que deseja testar e as opções desejadas. Abaixo estão alguns exemplos de uso:

Verificação Rápida (todas as vulnerabilidades):

python3 scanner.py -f http://exemplo.com
Verificar Vulnerabilidades Específicas:

python3 scanner.py -c -d -r -s -m -e http://exemplo.com
Nesse exemplo, as opções especificadas são:

-c para verificar XSS
-d para verificar IDOR
-r para verificar Open Redirects
-s para verificar SQL Injection
-m para verificar Command Injection
-e para verificar exposição de dados sensíveis
Verificar Todas as Vulnerabilidades:

python3 scanner.py -a http://exemplo.com
Leia o Relatório:

Após a execução, a ferramenta gerará um relatório detalhado das vulnerabilidades encontradas. O relatório inclui informações sobre a vulnerabilidade, a localização e exemplos de exploração.

Exemplo de Uso

python3 scanner.py -f http://example.com
Isso executará uma verificação completa de todas as vulnerabilidades configuradas para a URL fornecida.
