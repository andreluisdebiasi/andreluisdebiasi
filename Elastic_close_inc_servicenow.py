import requests
import http.client
import json
import re
import os
import pandas as pd
import numpy as np
import re
import logging
import base64
import sys

# Dataframes
dataServiceNow = pd.DataFrame()
dataElastic = pd.DataFrame()
dataIntegrated = pd.DataFrame()

# SERVICENOW
# Composição da URL de consulta dos INC no ServiceNow
# essa URL tem a função de a partir da coluna caller_id procurar pelos usuários de serviço do elastic para fazer uma primeira filtragem na busca
urlServiceNowPrd = "https://instance.service-now.com/api/now/v1/table/incident?sysparm_query=caller_id=callerid^state=1&sysparm_fields=number,sys_id,short_description,category,opened_by,sys_updated_on,company,cmdb_ci,u_related_topdesk_number_record,correlation_id,state,opened_at&sysparm_limit=5000&sysparm_orderby=opened_at"

urlServiceNowCmdb = "https://instalce.service-now.com/api/now/v1/table/cmdb_ci?sysparm_query=companyLIKEempresa^ORnameSTARTSWITHxx^operational_status=1&sysparm_fields=sys_id,name,operational_status&sysparm_limit=5000"
userServiceNow = "user-servicenow"
userPassServiceNow = "@option.query-sn@"


# ServiceNow Dev
URL = "https://instance.service-now.com/api/now/table/incident?"
queryCallerId = "sysparm_query=caller_id=callerid^"
state = "state=1"
fields = "&sysparm_fields=number,sys_id,short_description,category,opened_by,sys_updated_on,company,cmdb_ci,u_related_topdesk_number_record,correlation_id,state,opened_at&sysparm_limit=5000&sysparm_orderby=opened_at"
urlServiceNow = URL+queryCallerId+state+fields
tokensnow = "token"
snowinstance = "instance.service-now.com"
apirunningsnow = "/api/now/table/incident"
apichecksnow ="/api/now/table/incident?sysparm_query=u_related_topdesk_number_record=:"
state1= "&state=1"
state2= "&state=2"
state3= "&state=3"

# ELASTIC
urlElastic = "https://kibana:5601/s/command-center/api/alerting/rules/_find"
apiKeyElastic = "token"

# Função que pega todos os INC do ServiceNow
def get_servicenow_inc(urlServiceNowPrd, userServiceNow, userPassServiceNow):
    dados = []
    try:
        r = requests.get(urlServiceNowPrd, auth=(userServiceNow, userPassServiceNow))
        response = r.json()
        
        #print(f"Resposta JSON do ServiceNow: {response}")
        if r.status_code != 200:
             print(f"Erro com status HTTP {r.status_code}")
             sys.exit("ESSE ERRO COSTUMA OCORRER QUANDO NÃO HÁ MAIS NENHUM INC COM STATUS EM ABERTO PELO ELASTIC NO SERVICENOW")
            
            #print(f"Resposta JSON do ServiceNow: {response}")
        else:
            print(f"Query ServiceNow OK! Status da resposta HTTP: {r.status_code}")
            for x in response['result']:
                queryCorrelationId = x['correlation_id']
        
                if x['correlation_id'] == "":
                       continue
                else:
                     # Split na variável queryCorrelationId para separar o id do ic 
                    correlationIdSplit = queryCorrelationId.split(':')
                    alertId = correlationIdSplit[0]
                      
                    # Realiza o split em icImpacted com delimitador ','
                    icImpacted_split = correlationIdSplit[1].split(',')
        
                    # Coleta o primeiro elemento após o split e força Uppercase
                    icImpacted = icImpacted_split[0].upper()
                        
                    dadosTemp = {
                    'INC': x['number'],
                    'Sys Id': x['sys_id'],
                    'Alert ID' : alertId,
                    'IC Impacted' : icImpacted,
                    'Status' : x['state']
                    }
                        
                    dados.append(dadosTemp)

        dataServiceNow = pd.DataFrame(dados)
        return dataServiceNow
    except Exception as e:
        # Registrar a exceção no arquivo de log
        logging.error(f"Erro ao executar a requisição de dados do Service Now: {str(e)}")
        print("Falha ao executar a requisição de dados do Service Now !!!!")
        return None
    finally:
        r.close()
    
# Função que pega todos os alertas do Elastic
def get_elastic_alerts(urlElastic, apiKeyElastic):

    headers = {
        "Authorization": f"ApiKey {apiKeyElastic}"
    }
    
    params = {
        "search_fields": "name",
        "search": "*",
        "per_page": "1000"
    }
   
    try:
        getAlerts = requests.get(urlElastic, headers=headers, params=params)
        alertsJson = getAlerts.json()

        jsonStr = json.dumps(alertsJson, indent=4)
        dataDict = json.loads(jsonStr)

        data = dataDict.get("data")  # Use .get() para lidar com a possibilidade de retorno None
        if data is None:
            raise Exception("Os dados do Elastic retornaram None.")

        columns = ["id", "name", "status", "last_execution_date", "last_duration", "status_count"]

        dataElastic = pd.DataFrame(
            [
                {
                    "id": d["id"],
                    "name": d["name"],
                    "status": d.get("execution_status", {}).get("status"),
                    "last_execution_date": d.get("execution_status", {}).get("last_execution_date"),
                    "last_duration": d.get("execution_status", {}).get("last_duration"),
                    "status_count": d.get("last_run", {}).get("alerts_count", {}).get("active")
                }
                for d in data
            ],
            columns=columns,
        )
        return dataElastic
    except Exception as e:
        # Registrar a exceção no arquivo de log
        logging.error(f"Erro ao executar a requisição de dados dos alertas do Elastic: {str(e)}")
        print("Falha ao executar a requisição de dados dos alertas do Elastic !!!!")
        return None
    finally:
        getAlerts.close()

# Função que pega todos os IC do Service Now
def get_cmdb_ci(urlServiceNowCmdb, urlServiceNowPrd, userServiceNow):
    dados = []
    try:
        r = requests.get(urlServiceNowCmdb, auth=(userServiceNow, userPassServiceNow))
        response = r.json()

        for x in response['result']:
            dadosTemp = {
            'Sys ID IC': x['sys_id'],
            'Host Name': x['name'],
            }
            dados.append(dadosTemp)

        dataServiceNowCmdb = pd.DataFrame(dados)
        
        return dataServiceNowCmdb
    except Exception as e:
        # Registrar a exceção no arquivo de log
        logging.error(f"Erro ao executar a requisição de dados do CMDB do Service Now: {str(e)}")
        print("Falha ao executar a requisição de dados do CMDB do Service Now !!!!")
        return None
    finally:
        r.close()
    
# função que que faz a correlação dos dados do dataframe do ServiceNow com o dataframe do Elastic
def integration_data(dataServiceNow, dataElastic, dataServiceNowCmdb):
    
    # Verificar se dataElastic é None
    if dataElastic is None:
        print("Erro: DataFrame dataElastic é None.")
        return None

    dados = []
    for incSearchServiceNow, sysIdSearchServiceNow, idSearchServiceNow, icSearchServiceNow, statusSearchServiceNow in zip(dataServiceNow['INC'], dataServiceNow['Sys Id'], dataServiceNow['Alert ID'], dataServiceNow['IC Impacted'], dataServiceNow['Status']):   
        for idSearchElastic, status in zip(dataElastic['id'], dataElastic['status']):
            if idSearchServiceNow == idSearchElastic:  
                for cmdbId, cmdbHost in zip(dataServiceNowCmdb['Sys ID IC'], dataServiceNowCmdb['Host Name']):
                    if cmdbHost.upper() in icSearchServiceNow.upper():           
                        dadosTemp = {
                            'INC': incSearchServiceNow,
                            'Host ID' : cmdbId,
                            'Sys Id': sysIdSearchServiceNow,
                            'Alert ID' : idSearchServiceNow,
                            'IC Impacted' : icSearchServiceNow,
                            'Status' : statusSearchServiceNow,
                            'Status Alert' : status
                            }
                        dados.append(dadosTemp)
                    
    df = pd.DataFrame(dados)

    return df
    
# Função que coloca os INC em andamento no Service Now
def in_process_servicenow(dataIntegrated):

    # Verificar se dataIntegrated é None
    if dataIntegrated is None:
        print("Erro: DataFrame dataIntegrated é None.")
        return
   
    #for sysID, status in zip(dataIntegrated['Sys Id'], dataIntegrated['Status Alert']):
    #    if status == 'ok':
            
    for hostId, sysID, status in zip(dataIntegrated['Host ID'], dataIntegrated['Sys Id'], dataIntegrated['Status Alert']):
        #if status == 'ok':
        #print(hostId)
        if status == 'ok' and hostId != '':        
            snowurl= f'{apirunningsnow}'
            id = f"/{sysID}?sysparm_exclude_ref_link=true"
            url = f'{snowurl}{id}'
            payloadrunningsnow = {
            'state': '2',
            'u_state': '2',
            'comments':'alterado para em em andamento automaticamente',
            'incident_state': '2',
            "caller_id": "2970d391db496594103ca581149619d5"
            }
            json_payloadrunning = json.dumps(payloadrunningsnow)
            headersrunningsnow = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization':  f'Basic {tokensnow}'
            }
            conn = http.client.HTTPSConnection(snowinstance)
            conn.request("PATCH", url, json_payloadrunning, headers=headersrunningsnow)
            print(conn)
            res = conn.getresponse()
            data = res.read()
            data = data.decode('ISO-8859-1')
            result = re.findall(r'"number":"[^"]*"', data)
            print(f"resposta da alteracao para em andamento numero do incidente {result} response code", res.status)
            print(result)

        else:
            print("Status ainda ativo!!!!")
 
# Função que coloca os INC como resolvidos no Service Now
def close_servicenow(dataIntegrated):
    for hostId, sysID, status in zip(dataIntegrated['Host ID'], dataIntegrated['Sys Id'], dataIntegrated['Status Alert']):
        if status == 'ok':
            snowurl= f'{apirunningsnow}'
            id = f"/{sysID}?sysparm_exclude_ref_link=true"
            url = f'{snowurl}{id}'
            payloadclosesnow = { 
            'state': '6',
            'u_state': '6',
            'incident_state': '6',
            'close_code': 'Encerrado/Solucionado pelo solicitante',
            'comments':'fechado automaticamente devido a normalizacao do alerta',
            'u_service': 'Monitoração de Disponibilidade',
            'u_resolution_classification': 'Restart de Serviços',
            'u_prioritization_addon': 'Apenas comigo',
            'u_choice_incident_principal': 'principal incidente',
            'close_notes': 'Closed by Elastic',
            'subcategory': 'Indisponibilidade',
            'contact_type': 'phone',
            'cmdb_ci': hostId
            #'cmdb_ci': { 'link': 'https://ultradev.service-now.com/api/now/v1/table/cmdb_ci/hostId', 'value': 'hostId'}
            #'business_service': { 'link': 'https://ultradev.service-now.com/api/now/v1/table/cmdb_ci_service/f6ba33b7db0cc25057ac9f3bf39619b6', 'value': 'f6ba33b7db0cc25057ac9f3bf39619b6'}
                }
            json_payloadrunning = json.dumps(payloadclosesnow)
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
            print(f"resposta da alteracao para solucionado numero do incidente {result} response code", res.status)
        else:
            print("Status ainda ativo!!!!")

# Função de processamento e execução
def main_process(urlElastic, apiKeyElastic, urlServiceNowCmdb, urlServiceNowPrd, userServiceNow, userPassServiceNow, dataServiceNow, dataElastic, dataIntegrated):

    # Buscando informações dos INCs e Alertas
    dataServiceNow = get_servicenow_inc(urlServiceNowPrd, userServiceNow, userPassServiceNow)
    print(dataServiceNow.head(5000))
    dataElastic = get_elastic_alerts(urlElastic, apiKeyElastic)
    print(dataElastic.head(5000))
    dataServiceNowCmdb = get_cmdb_ci(urlServiceNowCmdb, urlServiceNowPrd, userServiceNow)
    print(dataServiceNowCmdb.head(5000))
    dataIntegrated = integration_data(dataServiceNow, dataElastic, dataServiceNowCmdb)
    print(dataIntegrated.head(2000))

    if dataIntegrated is not None:
        in_process_servicenow(dataIntegrated)
        close_servicenow(dataIntegrated)
    else:
        print("Erro: Não foi possível integrar os dados.")
    
    if dataServiceNowCmdb is not None:
        next
    else:
        print("Erro: Não foi possível obter os dados do CMDB do Service Now.")
    
# Chamada função que gerencia o código
main_process(urlElastic, apiKeyElastic, urlServiceNowCmdb, urlServiceNow, userServiceNow, userPassServiceNow, dataServiceNow, dataElastic, dataIntegrated)



