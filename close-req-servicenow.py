import requests
import http.client
import json
import re
import os
import pandas as pd
import numpy as np
import re
import sys

# variáveis para consumir os campos das reqs do servicenow
userServiceNow = "user"
userPassServiceNow = "@pwd@"
URL = "https://instancxe.service-now.com/api/now/v1/table/sc_task?sysparm_query=assignment_group=grouopid^companyLIKEUltragaz^state=1&sysparm_limit=500&sysparm_orderby=opened_at"
URL_DEV = "https://instancxe.service-now.com/api/now/v1/table/sc_task?sysparm_query=assignment_group=groupid^state=1&sysparm_limit=500&sysparm_orderby=opened_at"

# Dataframes
dataServiceNow = pd.DataFrame()

# Variáveis de encerramento da REQ
tokensnow = "@option.token_sn@"
snowinstance = "instancxe.service-now.com"
apirunningsnow = "/api/now/v1/table/task"

# Função que pega todos os INC do ServiceNow
def get_servicenow_req(urlServiceNow, userServiceNow, userPassServiceNow):
    dados = []
    try:
        r = requests.get(urlServiceNow, auth=(userServiceNow, userPassServiceNow))
        response = r.json()
        print(response)
        #if r.status == 200:
        for x in response['result']:
            dadosTemp = {
                'SCTASK': x['task_effective_number'],
                'Sys ID SCTASK': x['sys_id'],
                'Status' : x['state']
            }

            dados.append(dadosTemp)

        dataServiceNow = pd.DataFrame(dados)
        return dataServiceNow
       # else:
       #     sys.exit(1)    
    except:
        print("Falha ao executar a requisição de dados do Service Now !!!!")
        sys.exit(1)
    finally:
        r.close()

# função que coloca em andamento as REQs
def run_sctask_snow(dataIntegrated):
  
  for sysID, status in zip(dataIntegrated['Sys ID SCTASK'], dataIntegrated['Status']):
    if status == '1':
        snowurl= f'{apirunningsnow}'
        id = f"/{sysID}?sysparm_exclude_ref_link=true"
        url = f'{snowurl}{id}'
        payloadrunningsnow = {
            'state': '2',
            'u_state': '2',
            'comments': 'Colocado em andamento automaticamente pelo Rundeck',
        }
        json_payloadrunning = json.dumps(payloadrunningsnow)
        headersrunningsnow = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization':  f'Basic {tokensnow}'
        }
        conn = http.client.HTTPSConnection(snowinstance)
        conn.request("PATCH", url, json_payloadrunning, headers=headersrunningsnow)
        res = conn.getresponse()
        data = res.read()
        data = data.decode('ISO-8859-1')
        result = re.findall(r'"number":"[^"]*"', data)
        print(f"resposta da alteracao para em andamento para a SCTASK {result} response code", res.status)
    else:
        print("Status já em andamento ou encerrado!!!!")

# função que fecha as REQs
def close_sctask_snow(dataIntegrated):

    for sysID, status in zip(dataIntegrated['Sys ID SCTASK'], dataIntegrated['Status']):
        snowurl= f'{apirunningsnow}'
        id = f"/{sysID}?sysparm_exclude_ref_link=true"
        url = f'{snowurl}{id}'
        payloadrunningsnow = {
            'state': '3',
            'u_state': '3',
            'comments':'fechado automaticamente pelo Rundeck',
            'close_notes': 'Closed by Rundeck',
            'contact_type': 'service_portal',
            'cmdb_ci': '54e6a4821b4b1918b73285dde54bcb2c'
        }
        json_payloadrunning = json.dumps(payloadrunningsnow)
        headersrunningsnow = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization':  f'Basic {tokensnow}'
        }
        conn = http.client.HTTPSConnection(snowinstance)
        conn.request("PATCH", url, json_payloadrunning, headers=headersrunningsnow)
        res = conn.getresponse()
        data = res.read()
        data = data.decode('ISO-8859-1')
        result = re.findall(r'"number":"[^"]*"', data)
        print(f"resposta da alteracao para resolvido para a SCTASK {result} response code", res.status)

# função de processamento das validações e execuções de em andamento e encerramento no serviceNow
def main_validation(URL, userServiceNow, userPassServiceNow):
    dataServiceNow = get_servicenow_req(URL, userServiceNow, userPassServiceNow)
    print(dataServiceNow.head(500))

    run_sctask_snow(dataServiceNow)
    close_sctask_snow(dataServiceNow)

# função principal de processamento das REQS
main_validation(URL, userServiceNow, userPassServiceNow)
