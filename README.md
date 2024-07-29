Infiltrator


Infiltrator é uma ferramenta de análise de segurança web que ajuda a identificar vulnerabilidades comuns em sites e aplicações web. Desenvolvida por Victor, a ferramenta é projetada para detectar uma variedade de problemas de segurança que podem comprometer a integridade e a confidencialidade dos dados.

Principais Funcionalidades
Verificação Rápida (-f, --fast)
Realiza uma análise abrangente e rápida, verificando todas as vulnerabilidades suportadas: XSS, IDOR, redirecionamentos inseguros, SQL Injection, Command Injection e exposição de dados sensíveis.

Verificação Completa (-a, --all)
Similar ao modo rápido, mas oferece uma análise detalhada das vulnerabilidades especificadas. Ideal para uma auditoria completa.

Verificação XSS (-c, --check-xss)
Checa por vulnerabilidades de Cross-Site Scripting (XSS), onde scripts maliciosos podem ser injetados e executados no navegador dos usuários.

Verificação IDOR (-d, --check-idor)
Identifica vulnerabilidades de Insecure Direct Object References (IDOR), que podem permitir acesso não autorizado a objetos ou dados através de parâmetros de URL.

Verificação de Redirecionamentos (-r, --check-redirects)
Verifica se a aplicação permite redirecionamentos para URLs não confiáveis, uma falha que pode ser explorada para phishing ou ataques similares.

Verificação SQL Injection (-s, --check-sql)
Detecta vulnerabilidades de SQL Injection, onde comandos SQL maliciosos podem ser inseridos para acessar ou modificar dados na base de dados.

Verificação de Command Injection (-m, --check-command)
Identifica falhas de Command Injection, onde comandos do sistema podem ser executados a partir de entradas não seguras.

Verificação de Dados Sensíveis (-e, --check-data)
Procura por exposição de dados sensíveis, como senhas e tokens, que devem ser protegidos adequadamente.

