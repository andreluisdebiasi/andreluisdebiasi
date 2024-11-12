import requests
import http.client as httplib
import logging
import urllib3
import json
import pandas as pd
import re
import time

# Configurações
ZABBIX_URL = 'https://zabbix.ultragaz.com.br/api_jsonrpc.php'
ZABBIX_USER = 'usercmdb'
ZABBIX_PASSWORD = ''

# Desativar warnings de SSL não verificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ServiceNow Configurações
snowinstance = "gazprod.service-now.com"
apirunningsnow = "/api/now/table/incident"
tokensnow = ""  # Token SN user Zabbix (usar em prd)

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Função para autenticar na API do Zabbix
def zabbix_authenticate():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": ZABBIX_USER,
            "password": ZABBIX_PASSWORD
        },
        "id": 1,
        "auth": None
    }
    headers = {'Content-Type': 'application/json-rpc'}
    response = requests.post(ZABBIX_URL, data=json.dumps(payload), headers=headers, verify=False)
    result = response.json()
    return result.get('result')

# Função que pega todos os INC do ServiceNow
def get_servicenow_inc():
    URL = "https://gazprod.service-now.com/api/now/table/incident?"
    queryCallerId = "sysparm_query=caller_id=5b91a5cddb04359057ac9f3bf39619d4^"
    state = "state=2"
    fields = "&sysparm_fields=number,sys_id,short_description,category,opened_by,sys_updated_on,company,cmdb_ci,u_related_topdesk_number_record,correlation_id,state,opened_at&sysparm_limit=2000&sysparm_orderby=opened_at"
    urlServiceNow = URL + queryCallerId + state + fields

    headers = {
        "Authorization": f"Basic {tokensnow}"
    }
    dados = []
    r = None
    try:
        r = requests.get(urlServiceNow, headers=headers)
        response = r.json()

        if r.status_code != 200:
            print(f"Erro com status HTTP {r.status_code}")
            logging.error(f"Erro ao executar a requisição de dados do Service Now: {response}")
            return None
        else:
            print(f"Query ServiceNow OK! Status da resposta HTTP: {r.status_code}")
            for x in response['result']:
                queryCorrelationId = x['correlation_id']
                cmdb_ci = x.get('cmdb_ci', 'N/A')

                if x['correlation_id'] == "":
                    continue
                else:
                    correlationIdSplit = queryCorrelationId.split(':')
                    if len(correlationIdSplit) == 4:  # Agora considerando o host ID como o 4º elemento
                        hostId = correlationIdSplit[0].strip()  # Novo campo host ID
                        alertId = correlationIdSplit[1].strip()
                        eventId = correlationIdSplit[2].strip()
                        hostName = correlationIdSplit[3].replace('.ultra.corp', '').strip()
                        
                        dadosTemp = {
                            'INC': x['number'],
                            'Sys Id': x['sys_id'],
                            'Trigger ID': alertId,
                            'Event ID': eventId,
                            'Host Name': hostName,
                            'Host ID': hostId,
                            'Status': x['state'],
                            'cmdb_ci': hostName  # Adiciona o host relacionado ao incidente
                        }
                        dados.append(dadosTemp)

        return dados
    except Exception as e:
        logging.error(f"Erro ao executar a requisição de dados do Service Now: {str(e)}")
        print("Falha ao executar a requisição de dados do Service Now !!!!")
        return None
    finally:
        if r is not None:
            r.close()

# Função para obter o status de um host pelo host ID
def get_host_status(auth_token, host_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid", "host"],
            "filter": {
                "hostid": host_id  # Usando o host ID para filtrar
            }
        },
        "id": 2,
        "auth": auth_token
    }
    headers = {'Content-Type': 'application/json-rpc'}
    response = requests.post(ZABBIX_URL, data=json.dumps(payload), headers=headers, verify=False)
    hosts = response.json().get('result', [])
    print(hosts)

    if not hosts:
        return {
            "Host": host_id,
            "Status": "Host not found",
            "TriggerID": "None"
        }

    host = hosts[0]
    trigger_payload = {
        "jsonrpc": "2.0",
        "method": "trigger.get",
        "params": {
            "output": ["triggerid"],
            "hostids": host["hostid"],
            "only_true": True,
            "sortfield": "lastchange",
            "sortorder": "DESC",
            "limit": 1
        },
        "id": 3,
        "auth": auth_token
    }
    trigger_response = requests.post(ZABBIX_URL, data=json.dumps(trigger_payload), headers=headers, verify=False)
    triggers = trigger_response.json().get('result', [])

    # Determinar se o host está OK ou em problema e obter o código da trigger alarmada
    if not triggers:
        status = "OK"
        trigger = "None"
    else:
        status = "PROBLEM"
        trigger = triggers[0]["triggerid"]

    return {
        "Host": host['hostid'],
        "Status": status,
        "TriggerID": trigger
    }

# Função para obter o sys_id do hostname no ServiceNow
def get_sys_id_by_hostname(hostname):
    url = f"https://{snowinstance}/api/now/table/cmdb_ci?sysparm_query=name={hostname}&sysparm_fields=sys_id"
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Basic {tokensnow}'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        response_json = response.json()
        if response_json['result']:
            sys_id = response_json['result'][0]['sys_id']
            return sys_id
        else:
            logging.warning(f"Hostname '{hostname}' não encontrado no CMDB do ServiceNow.")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro ao buscar sys_id para hostname '{hostname}': {str(e)}")
        return None

# Função para colocar os INC em andamento no ServiceNow
def in_process_servicenow(dataIntegrated):
    if not dataIntegrated or len(dataIntegrated) == 0:
        logging.error("Erro: Nenhum dado fornecido para integração.")
        return

    for sysID in dataIntegrated:
        payloadrunningsnow = {
            'state': '2',
            'u_state': '2',
            'comments': 'alterado para em andamento automaticamente',
            'incident_state': '2'
        }

        snowurl = f'{apirunningsnow}'
        id = f"/{sysID}?sysparm_exclude_ref_link=true"
        url = f'{snowurl}{id}'

        json_payloadrunning = json.dumps(payloadrunningsnow)
        headersrunningsnow = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Basic {tokensnow}'
        }
        conn = httplib.HTTPSConnection(snowinstance)
        conn.request("PATCH", url, json_payloadrunning, headersrunningsnow)
        res = conn.getresponse()
        logging.info(f"Resposta da alteração para em andamento, response code {res.status}")
        time.sleep(2)  # Pausa de em segundos para evitar sobrecarga

# Função para fechar os INC no ServiceNow
def close_servicenow(dataIntegrated):
    if not dataIntegrated or len(dataIntegrated) == 0:
        logging.error("Erro: Nenhum dado fornecido para fechamento.")
        return

    for sysID, cmdb_ci, status in dataIntegrated:
        if status == 'OK':
            snowurl = f'{apirunningsnow}'
            id = f"/{sysID}?sysparm_exclude_ref_link=true"
            url = f'{snowurl}{id}'
            payload_close = {
                'state': '6',
                'u_state': '6',
                'incident_state': '6',
                'u_service': '38d9dc291bb8fcd0b73285dde54bcb42',
                'u_resolution_classification': 'Indisponibilidade',
                'close_code': 'Encerrado/Solucionado pelo solicitante',
                'close_notes': 'Closed by Zabbix',
                'comments': 'fechado automaticamente devido a normalizacao do alerta'
            }
            if cmdb_ci not in ['N/A', '']:
                sys_id_cmdb = get_sys_id_by_hostname(cmdb_ci)
                if sys_id_cmdb:
                    payload_close['cmdb_ci'] = sys_id_cmdb
                else:
                    payload_close['cmdb_ci'] = 'fa28bab11bae2d989c0bda02f54bcbed'

            json_payload_close = json.dumps(payload_close)
            headers_close = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': f'Basic {tokensnow}'
            }
            conn = httplib.HTTPSConnection(snowinstance)
            conn.request("PATCH", url, json_payload_close, headers=headers_close)
            res = conn.getresponse()
            data = res.read().decode('ISO-8859-1')
            result = re.findall(r'"number":"[^"]*"', data)
            if res.status == 200:
                print(f"Incidente {result} encerrado com sucesso, response code: {res.status}")
            else:
                print(f"Erro ao encerrar o incidente {sysID}, response code: {res.status}, resposta: {data}")

# Função para correlacionar os hosts do Zabbix com os incidentes do ServiceNow
def correlate_data(auth_token, inc_data):
    data_in_process = []
    data_to_close = []

    for inc in inc_data:
        host_status = get_host_status(auth_token, inc['Host ID'])
        print(f"Host ID: {host_status['Host']} - Status: {host_status['Status']} - Trigger: {host_status['TriggerID']}")
        print(f"  INC: {inc['INC']} - Status: {inc['Status']}")

        if host_status['Status'] == 'OK':
            data_to_close.append((inc['Sys Id'], inc['cmdb_ci'], host_status['Status']))
            data_in_process.append(inc['Sys Id'])

    # Colocar os INC em andamento
    if data_in_process:
        logging.debug(f"INC a serem colocados em andamento: {data_in_process}")
        in_process_servicenow(data_in_process)
    else:
        logging.debug("Nenhum INC a ser colocado em andamento.")

    # Fechar os INC
    if data_to_close:
        logging.debug(f"INC a serem fechados: {data_to_close}")
        close_servicenow(data_to_close)
    else:
        logging.debug("Nenhum INC a ser fechado.")

# Fluxo principal
if __name__ == "__main__":
    try:
        # Autenticar e obter o token
        token = zabbix_authenticate()
        if not token:
            print("Erro ao autenticar no Zabbix API")
        else:
            # Obter os incidentes do ServiceNow
            inc_data = get_servicenow_inc()

            if inc_data is not None:
                # Correlacionar os hosts do Zabbix com os incidentes do ServiceNow
                correlate_data(token, inc_data)
    except Exception as e:
        print(f"Erro: {str(e)}")
