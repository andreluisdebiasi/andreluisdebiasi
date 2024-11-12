import requests
import http.client
import json
import re
import os
import pandas as pd
import numpy as np
import re
import sys
from requests.auth import HTTPBasicAuth
import urllib3

# Desativar warnings de SSL não verificados
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variables servicenow
urlInputSn = "https://.service-now.com/api/now/v1/table/cmdb_ci_server"
urlServiceNowCmdb = 'https://.service-now.com/api/now/v1/table/cmdb_ci_server?sysparm_query=companyLIKEUltragaz^discovery_source=Zabbix&sysparm_fields=sys_id,u_hostid,name,operational_status,host_name,company,sys_class_name,environment,u_ci_criticality,operational_status,u_description,short_description,category,u_instances_banks,u_cluster,u_sox,u_safe_box,ip_address,dns_domain,u_domain,sys_domain,u_tipo_de_rede,u_os_custom,virtual,u_backlevel,location,manufacturer,cpu_type,cpu_count,ram,u_backup,discovery_source&sysparm_limit=15000'
urlServiceNowCmdbWin = 'https://.service-now.com/api/now/v1/table/cmdb_ci_win_server?sysparm_query=companyLIKEUltragaz&sysparm_fields=sys_id,u_hostid,name,operational_status,host_name,company,sys_class_name,environment,u_ci_criticality,operational_status,u_description,short_description,category,u_instances_banks,u_cluster,u_sox,u_safe_box,ip_address,dns_domain,u_domain,sys_domain,u_tipo_de_rede,u_os_custom,virtual,u_backlevel,location,manufacturer,cpu_type,cpu_count,ram,u_backup,discovery_source&sysparm_limit=15000'
urlServiceNowCmdbLin = 'https://.service-now.com/api/now/v1/table/cmdb_ci_linux_server?sysparm_query=companyLIKEUltragaz&sysparm_fields=sys_id,u_hostid,name,operational_status,host_name,company,sys_class_name,environment,u_ci_criticality,operational_status,u_description,short_description,category,u_instances_banks,u_cluster,u_sox,u_safe_box,ip_address,dns_domain,u_domain,sys_domain,u_tipo_de_rede,u_os_custom,virtual,u_backlevel,location,manufacturer,cpu_type,cpu_count,ram,u_backup,discovery_source&sysparm_limit=15000'
urlServiceNowCmdbEsx = 'https://.service-now.com/api/now/v1/table/cmdb_ci_esx_server?sysparm_query=companyLIKEUltragaz&sysparm_fields=sys_id,u_hostid,name,operational_status,host_name,company,sys_class_name,environment,u_ci_criticality,operational_status,u_description,short_description,category,u_instances_banks,u_cluster,u_sox,u_safe_box,ip_address,dns_domain,u_domain,sys_domain,u_tipo_de_rede,u_os_custom,virtual,u_backlevel,location,manufacturer,cpu_type,cpu_count,ram,u_backup,discovery_source&sysparm_limit=15000'

#urls = [urlServiceNowCmdbWin, urlServiceNowCmdbLin, urlServiceNowCmdbEsx] 
urls = [urlServiceNowCmdb] # retirar esse e colocar os respectivos após

urlLocation = 'https://.service-now.com/api/now/v1/table/cmn_location?sysparm_fields=name,sys_id'
urlCompanyAndManufacture = 'https://.service-now.com/api/now/v1/table/core_company?sysparm_fields=name,sys_id'
userServiceNow = ""
userPassServiceNow = ""

#userServiceNow = "jenkins.integration"
#userPassServiceNow = "@option.jenkins_integration@"

# Variables zabbix
zabbix_url = 'https://zabbix.com.br/api_jsonrpc.php'
zabbix_user = ''
zabbix_password = ''

# Dataframes
## Dataframes que carregam dados do zabbix e do servicenow
dataServiceNowCmdb = pd.DataFrame()
dataServiceNowCmdbWin = pd.DataFrame()
dataServiceNowCmdbLin = pd.DataFrame()
dataServiceNowCmdbEsx = pd.DataFrame()
dataZabbix = pd.DataFrame()

## Dataframes que fazem integração de dados entre dataframes
dataIntegratedLinux = pd.DataFrame()
dataIntegratedElx = pd.DataFrame()
dataIntegratedWindows = pd.DataFrame()
dataIntegratedSnZabbix = pd.DataFrame()
dataZabbixHost = pd.DataFrame()
dataZabbixAdjustment = pd.DataFrame()

headers = {
    'Content-Type': 'application/json'
}

# Dados para autenticação
auth_data = {
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "user": zabbix_user,
        "password": zabbix_password
    },
    "id": 1
}

# função que carrega os servidores Linux, ESX e Windows registrados no CMDB do servicenow
def get_cmdb_for_all(urls, userServiceNow, userPassServiceNow):
    try:
        dados = []
        for url in urls:
            r = requests.get(url, auth=(userServiceNow, userPassServiceNow))
            r.raise_for_status()  # Verifica se ocorreu algum erro na solicitação HTTP
            response = r.json()

            for x in response.get('result', []):
                
                manufacturer = x.get('manufacturer', {})
                value = manufacturer.get('value', '') if isinstance(manufacturer, dict) else ''

                location = x.get('location', {})
                value2 = location.get('value', '') if isinstance(location, dict) else ''

                dadosTemp = {
                    'sys_id_ic': x.get('sys_id', ''),
                    'host_id' : x.get('u_hostid', ''),
                    'name': x.get('name', ''), 
                    'host_name': x.get('host_name', ''),
                    'company': x.get('company', {}).get('value', ''), 
                    'class_name' : x.get('sys_class_name', ''), 
                    'environment' : x.get('environment', ''), 
                    'criticality' : x.get('u_ci_criticality', ''),
                    'status' : x.get('operational_status', ''),
                    'description' : x.get('u_description', ''),
                    'short_description' : x.get('short_description', ''),
                    'category' : x.get('category', ''),
                    'instance_bank' : x.get('u_instances_banks', ''),
                    'cluster' : x.get('u_cluster', ''),
                    'sox' : x.get('u_sox', ''),
                    'vault' : x.get('u_safe_box', ''),
                    'ip_address' : x.get('ip_address', ''),
                    'dns_domain' : x.get('dns_domain', ''),
                    'domain' : x.get('u_domain', ''),
                    'system_domain' : x.get('sys_domain', {}).get('value', ''),
                    'type_network' : x.get('u_tipo_de_rede', ''),
                    'os' : x.get('u_os_custom', ''),
                    'virtual' : x.get('virtual', ''),
                    'backlevel' : x.get('u_backlevel', ''),
                    'location' : value2, #x.get('location', '').get('value', ''),
                    'manufacturer' : value, #x.get('location', '').get('value', '')
                    'cpu_type' : x.get('cpu_type', ''),
                    'cpu_count' : x.get('cpu_count', ''),
                    'ram' : x.get('ram', ''),
                    'backup' : x.get('u_backup', ''),
                    'discovery_source' : x.get('discovery_source', '')
                }

                dados.append(dadosTemp)

        dataServiceNowCmdb = pd.DataFrame(dados)

        return dataServiceNowCmdb
    except requests.exceptions.RequestException as e:
        print("Falha ao conectar ao ServiceNow CMDB para Lin: ", e)
        return pd.DataFrame()  # Retorna um DataFrame vazio em caso de falha na solicitação HTTP
    except ValueError as e:
        print("Erro ao processar os dados JSON do ServiceNow CMDB para Lin: ", e)
        return pd.DataFrame()  # Retorna um DataFrame vazio em caso de falha no processamento JSON

# função que busca o location a partir do sys_id
def get_cmdb_location(urlLocation, userServiceNow, userPassServiceNow):
    dados = []
    try:
        r = requests.get(urlLocation, auth=(userServiceNow, userPassServiceNow))
        response = r.json()

        for x in response['result']:
            dadosTemp = {
            'Sys ID Location': x['sys_id'],
            'Name': x['name'],
            }
            dados.append(dadosTemp)

        dataServiceNowCmdb = pd.DataFrame(dados)

        return dataServiceNowCmdb
    except:
        print("Falha ao executar a requisição de dados do CMDB do Service Now !!!!")
    finally:
        r.close()

# função que busca o company e o manufacture a partir do sys_id
def get_cmdb_company_manufacture(urlCompanyAndManufacture, userServiceNow, userPassServiceNow):
    dados = []
    try:
        r = requests.get(urlCompanyAndManufacture, auth=(userServiceNow, userPassServiceNow))
        response = r.json()

        for x in response['result']:
            dadosTemp = {
            'Sys ID Company/Manufacture': x['sys_id'],
            'Name': x['name']
            }
            dados.append(dadosTemp)

        dataServiceNowCmdb = pd.DataFrame(dados)

        return dataServiceNowCmdb
    except:
        print("Falha ao executar a requisição de dados do CMDB do Service Now !!!!")
    finally:
        r.close()

# função que carrega os servidores monitorados pelo zabbix
def get_zabbix_hosts(auth_token, group_ids):
    columns = ["Host"]
    dados = []

    # Mapeamento dos campos do inventário
    inventory_mapping = {
        'type': '#Backlevel',
        'type_full': '#Ambiente',
        'name': '#Hostname',
        'alias': '#Classe',
        'os': '#Sistema Operacional',
        'os_full': '#Sistema Operacional(Full details)',
        'os_short': '#Arch',
        'serialno_a': '#Empresa',
        'serialno_b': '#Numero Serie',
        'tag': '#Garantia Final',
        'macaddress_a': '#Endereco Fisico',
        'macaddress_b': '#Antivirus',
        'hardware': '#Discos',
        'software_app_a': '#Memoria',
        'software_app_b': '#Processadores',
        'software_app_c': '#Cores',
        'software_app_d': '#Tipo Processador',
        'software_app_e': '#Memoria Utilizada',
        'location': '#Localidade',
        'location_lat': '#Backup',
        'location_lon': '#Sox',
        'notes': '#Descricao',
        'chassis': '#Criticidade',
        'model': '#Modelo',
        'hw_arch': '#Funcao Servidor',
        'vendor': '#Fornecedor',
        'installer_name': '#Cluster',
        'deployment_status': '#Cofre',
        'url_a': '#Dominio',
        'url_b': '#Fabricante',
        'url_c': '#Tipo Rede',
        'host_networks': '#Virtual',
        'site_address_b': '#Info DNS',
        'site_address_c': '#Horario Local',
        'poc_1_name': '#Uptime',
        'poc_2_notes': '#Status Servidor'
    }

    for group_id in group_ids:
        # Dados para obter os hosts do grupo específico
        hosts_data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["hostid", "host", "status", "inventory"],
                "groupids": group_id,
                "selectInventory": list(inventory_mapping.keys()),
                "selectInterfaces": ["ip"]
                #"limit": 2
            },
            "auth": auth_token,
            "id": 2
        }
        # Requisição para obter os hosts do grupo específico
        hosts_response = requests.post(zabbix_url, json=hosts_data, headers=headers, verify=False)
        if hosts_response.status_code == 200:
            hosts_info = hosts_response.json().get('result')
            jsonStr = json.dumps(hosts_info, indent=4)
            dataDict = json.loads(jsonStr)
            # Verificar se há hosts na resposta
            if dataDict:
                # Processar os hosts
                for item in dataDict:
                    hostid = item['hostid']
                    host = item['inventory']['name']
                    status = item['status']
                    company = item['inventory']['serialno_a']
                    classstr = item['inventory']['alias']
                    environment = item['inventory']['type_full']
                    criticality = item['inventory']['chassis']
                    state = item['inventory']['poc_2_notes']
                    description = item['inventory']['notes']
                    hostFunction = item['inventory']['hw_arch']
                    instanceBank = item['inventory']['notes']
                    cluster = item['inventory']['installer_name']
                    sox = item['inventory']['location_lon']
                    vault = item['inventory']['deployment_status']
                    ipAddress = item['interfaces'][0]['ip']
                    domain = item['inventory']['url_a']
                    typeNetwork = item['inventory']['url_c']
                    typeOs = item['inventory']['os']
                    vmhost = item['inventory']['host_networks']
                    backLevel = item['inventory']['type']
                    local = item['inventory']['location']
                    manufacture = item['inventory']['url_b']
                    typeCPU = item['inventory']['software_app_d']
                    numberCPU = item['inventory']['software_app_b']
                    memoryRAM = item['inventory']['software_app_a']
                    backup = item['inventory']['location_lat']

                    # split do hostid host_inventory_location_lat
                    hosttemp = host.split('.')
                    hostfn = hosttemp[0]

                    dados.append({'hostid': hostid.upper(), 'host': hostfn.upper(), 'status': status.upper(), 'company': company.upper(), 'class': classstr.upper(), 'environment': environment.upper(), 'criticality': criticality.upper() ,'state': state.upper() ,'description': description.upper(),
                                  'hostFunction': hostFunction.upper(), 'instanceBank': instanceBank.upper(), 'cluster': cluster.upper(), 'sox': sox.upper(), 'vault': vault.upper(), 'ipAddress': ipAddress.upper(), 'domain': domain.upper(),
                                  'typeNetwork': typeNetwork.upper(), 'typeOs': typeOs.upper(), 'vmhost': vmhost.upper(), 'backLevel': backLevel.upper(), 'local': local.upper(), 'manufacture': manufacture.upper(), 'typeCPU': typeCPU.upper(),
                                  'numberCPU': numberCPU.upper(), 'memoryRAM': memoryRAM.upper(), 'backup' : backup.upper()})
            else:
                print(f"Nenhuma informação de hosts encontrada para o groupid {group_id}.")
        else:
            print("Erro durante o processamento da resposta:", hosts_response.text)

    dataZabbixHostTemp = pd.DataFrame(dados)
    return dataZabbixHostTemp

# função que faz autenticação de acesso no zabbix
def zabbix_autetication(zabbix_url, auth_data, headers):
    dataZabbixTemp = pd.DataFrame()
    # Autenticação no Zabbix
    auth_response = requests.post(zabbix_url, json=auth_data, headers=headers, verify=False)
    if auth_response.status_code == 200:
        auth_token = auth_response.json().get('result')
        group_ids = ["37", "40", "58"]  # IDs dos grupos desejados do Zabbix
        dataZabbixTemp = get_zabbix_hosts(auth_token, group_ids)
        return dataZabbixTemp
    else:
        print("Erro durante a autenticação:", auth_response.text)

# função que ajusta campos do dataframe final que vai ser utilizado na função de input no SN
def zabbix_adjustment(dataZabbix):

    # Substituição de dados vazios em cada coluna por valores temporarios a serem substituidos conforme for ocorrendo updates dentro do zabbix
    dataZabbix['host'] = dataZabbix['host'].replace({'': 'N/A'})
    dataZabbix['backLevel'] = dataZabbix['backLevel'].replace({'': False})
    dataZabbix['environment'] = dataZabbix['environment'].replace({'': 'Test'})
    dataZabbix['class'] = dataZabbix['class'].replace({'': 'cmdb_ci_server'})
    dataZabbix['typeOs'] = dataZabbix['typeOs'].replace({'': 'N/A'})
    dataZabbix['typeNetwork'] = dataZabbix['typeNetwork'].replace({'': 'CORPORATIVA'})
    dataZabbix['company'] = dataZabbix['company'].replace({'': 'Ultragaz'})
    dataZabbix['numberCPU'] = dataZabbix['numberCPU'].replace({'': '0'})
    dataZabbix['memoryRAM'] = dataZabbix['memoryRAM'].replace({'': '0'})
    dataZabbix['typeCPU'] = dataZabbix['typeCPU'].replace({'': 'N/A'})
    dataZabbix['local'] = dataZabbix['local'].replace({'': 'Equinix SP3'})
    dataZabbix['backup'] = dataZabbix['backup'].replace({'': False})
    dataZabbix['sox'] = dataZabbix['sox'].replace({'': False})
    dataZabbix['description'] = dataZabbix['description'].replace({'': 'N/A'})
    dataZabbix['criticality'] = dataZabbix['criticality'].replace({'': '2 - Medium'})
    dataZabbix['hostFunction'] = dataZabbix['hostFunction'].replace({'': 'N/A'})
    dataZabbix['cluster'] = dataZabbix['cluster'].replace({'': False})
    dataZabbix['vault'] = dataZabbix['vault'].replace({'': False})
    dataZabbix['domain'] = dataZabbix['domain'].replace({'': 'N/A'})
    dataZabbix['manufacture'] = dataZabbix['manufacture'].replace({'': 'VMware'})
    dataZabbix['vmhost'] = dataZabbix['vmhost'].replace({'': False})
    dataZabbix['ipAddress'] = dataZabbix['ipAddress'].replace({'': 'N/A'})
    dataZabbix['status'] = dataZabbix['status'].replace({'': '1'})
    dataZabbix['state'] = dataZabbix['state'].replace({'': 'OK'})
    dataZabbix['instanceBank'] = dataZabbix['instanceBank'].replace({'': 'N/A'})

    # Substituição nos demais campos ('environment','status', cluster', 'sox', 'vault', 'vmhost', 'backLevel', backup)
    dataZabbix['environment'] = dataZabbix['environment'].replace({'PRD': 'Production', 'HML': 'Test', 'DEV': 'Development'})
    dataZabbix['status'] = dataZabbix['status'].replace({'0': '1', '1': '6'})
    dataZabbix['cluster'] = dataZabbix['cluster'].replace({'SIM': True, 'NAO': False})
    dataZabbix['sox'] = dataZabbix['sox'].replace({'SIM': True, 'NAO': False})
    dataZabbix['vault'] = dataZabbix['vault'].replace({'SIM': True, 'NAO': False})
    dataZabbix['vmhost'] = dataZabbix['vmhost'].replace({'SIM': True, 'NAO': False})
    dataZabbix['backLevel'] = dataZabbix['backLevel'].replace({'SIM': True, 'NAO': False})
    dataZabbix['backup'] = dataZabbix['backup'].replace({'SIM': True, 'NAO': False})

    return dataZabbix

# função que vai integrar o dataframe dos host do Linux, ESX e Windows com os dataframes que trazem os dados de company, manufacture e location
def servicenow_integrated(dataServiceNowCmdb, dataServiceNowCmdbLocation, dataServiceNowCmdbCompanyManufacture):
    dados = []

    for sys_id_ic, host_id, name, host_name, company, class_name, environment, criticality, status, description, short_description, category, instance_bank, cluster, sox, vault, ip_address, dns_domain, domain, system_domain, type_network, os, virtual, backLevel, location, manufacture, cpu_type, cpu_count, ram, backup, discovery_source in zip(dataServiceNowCmdb['sys_id_ic'],
        dataServiceNowCmdb['host_id'], dataServiceNowCmdb['name'], dataServiceNowCmdb['host_name'], dataServiceNowCmdb['company'], dataServiceNowCmdb['class_name'], dataServiceNowCmdb['environment'], dataServiceNowCmdb['criticality'], dataServiceNowCmdb['status'],
        dataServiceNowCmdb['description'], dataServiceNowCmdb['short_description'], dataServiceNowCmdb['category'], dataServiceNowCmdb['instance_bank'], dataServiceNowCmdb['cluster'], dataServiceNowCmdb['sox'], dataServiceNowCmdb['vault'],
        dataServiceNowCmdb['ip_address'], dataServiceNowCmdb['dns_domain'], dataServiceNowCmdb['domain'], dataServiceNowCmdb['system_domain'], dataServiceNowCmdb['type_network'], dataServiceNowCmdb['os'], dataServiceNowCmdb['virtual'],
        dataServiceNowCmdb['backlevel'], dataServiceNowCmdb['location'], dataServiceNowCmdb['manufacturer'], dataServiceNowCmdb['cpu_type'], dataServiceNowCmdb['cpu_count'], dataServiceNowCmdb['ram'], dataServiceNowCmdb['backup'], dataServiceNowCmdb['discovery_source']):

        for sysidlocation, nameLocation in zip(dataServiceNowCmdbLocation['Sys ID Location'], dataServiceNowCmdbLocation['Name']):
            
            if sysidlocation == location:

                for sysidCompanyManufacture, nameManufacture in zip(dataServiceNowCmdbCompanyManufacture['Sys ID Company/Manufacture'], dataServiceNowCmdbCompanyManufacture['Name']):

                    if sysidCompanyManufacture == manufacture:
                        companyName = 'Ultragaz'
                        dadosTemp = {
                            'host_id': host_id,
                            'sys_id_ic': sys_id_ic,
                            'name': name,
                            'host_name': host_name,
                            'company': companyName,
                            'class_name' : class_name,
                            'environment' : environment,
                            'criticality' : criticality,
                            'status' : status,
                            'description' : description,
                            'short_description' : short_description,
                            'category' : category,
                            'instance_bank' : instance_bank,
                            'cluster' : cluster,
                            'sox' : sox,
                            'vault' : vault,
                            'ip_address' : ip_address,
                            'dns_domain' : dns_domain,
                            'domain' : domain,
                            'system_domain' : system_domain,
                            'type_network' : type_network,
                            'os' : os,
                            'virtual' : virtual,
                            'backlevel' : backLevel,
                            'location' : nameLocation,
                            'manufacturer' : nameManufacture,
                            'cpu_type' : cpu_type,
                            'cpu_count' : cpu_count,
                            'ram' : ram,
                            'backup' : backup,
                            'discovery_source' : discovery_source
                        }
                        dados.append(dadosTemp)
        
    df = pd.DataFrame(dados)

    return df

# função que verifica se existe novos host para inserção no cmdb
def host_verification(dataServiceNowCmdb, dataZabbix):

    new_host = dataZabbix[~dataZabbix['hostid'].isin(dataServiceNowCmdb['host_id'])]
    print(new_host.head())

    if new_host.empty:
        print("Frame vazio")
        next

    return new_host

# função que adiona servidores não existentes no CMDB utilizando post com todas as infos
def service_now_input(urlInputSn, userServiceNow, userPassServiceNow, dataZabbix):

    for hostid, host, status, company, classstr, environment, criticality, state, description, hostFunction, instanceBank, cluster, sox, vault, ipAddress, domain, typeNetwork, typeOs, vmhost, backLevel, local, manufacture, typeCPU, numberCPU, memoryRAM, backup in zip(dataZabbix['hostid'],
        dataZabbix['host'], dataZabbix['status'], dataZabbix['company'], dataZabbix['class'], dataZabbix['environment'], dataZabbix['criticality'], dataZabbix['state'], dataZabbix['description'],
        dataZabbix['hostFunction'], dataZabbix['instanceBank'], dataZabbix['cluster'], dataZabbix['sox'], dataZabbix['vault'],dataZabbix['ipAddress'], dataZabbix['domain'],
        dataZabbix['typeNetwork'], dataZabbix['typeOs'], dataZabbix['vmhost'], dataZabbix['backLevel'], dataZabbix['local'], dataZabbix['manufacture'], dataZabbix['typeCPU'],
        dataZabbix['numberCPU'], dataZabbix['memoryRAM'], dataZabbix['backup']):

        if host == 'N/A':
            print("Host nulo encontrado")
            next
        else:

            # Dados a serem enviados na solicitação
            data = {
                # Informações Gerais
                'u_hostid': hostid,
                'name': host,
                'host_name': host,
                'company': company,
                'sys_class_name': classstr,
                'environment': environment,
                'u_ci_criticality': criticality,
                'operational_status': status,
                'u_description': description,
                'short_description': description,
                'category': hostFunction,
                'u_instances_banks':  instanceBank,
                'u_cluster': cluster,
                'u_sox': sox,
                'u_safe_box' : vault,
                'ip_address': ipAddress,
                'dns_domain': domain,
                'u_domain': domain,
                'sys_domain': domain,
                'u_tipo_de_rede': typeNetwork,
                'u_os_custom': typeOs,
                'virtual': vmhost,
                'u_backlevel': backLevel,
                'location': local,
                'manufacturer': manufacture,
                'cpu_type': typeCPU,
                'cpu_count': numberCPU,
                'ram': memoryRAM,
                'u_backup' : backup,
                'discovery_source' : 'Zabbix'
            }

            # Fazendo a solicitação POST para criar o registro
            response = requests.post(urlInputSn, auth=HTTPBasicAuth(userServiceNow, userPassServiceNow), headers=headers, json=data)

            # Verificando a resposta
            if response.status_code == 201:
                json_str = json.dumps(response.json(), indent=4)
                print('Registro criado com sucesso!')
                #print('Detalhes do registro:', json_str)
            else:
                print('Erro ao criar o registro. Status:', response.status_code)
                print('Resposta:', response.text)

# função que verifica se algum campo do Dataframe do zabbix foi alterado e compara com a base do Zabbix inserido no CMDB para isolar e posteriormente fazer o update
def zabbix_servicenow_compare_database(dataServiceNowCmdb, dataZabbix):
    
    dados = []
    count = 0

    # preparando dataServiceNowCmdb Dataframe
    # tratamento para falsos
    dataServiceNowCmdb['cluster'] = dataServiceNowCmdb['cluster'].replace({'false': False})
    dataServiceNowCmdb['sox'] = dataServiceNowCmdb['sox'].replace({'false': False})
    dataServiceNowCmdb['vault'] = dataServiceNowCmdb['vault'].replace({'false': False})
    dataServiceNowCmdb['virtual'] = dataServiceNowCmdb['virtual'].replace({'false': False})
    dataServiceNowCmdb['backlevel'] = dataServiceNowCmdb['backlevel'].replace({'false': False})
    dataServiceNowCmdb['backup'] = dataServiceNowCmdb['backup'].replace({'false': False})

    # tratamento para true
    dataServiceNowCmdb['cluster'] = dataServiceNowCmdb['cluster'].replace({'true': True})
    dataServiceNowCmdb['sox'] = dataServiceNowCmdb['sox'].replace({'true': True})
    dataServiceNowCmdb['vault'] = dataServiceNowCmdb['vault'].replace({'true': True})
    dataServiceNowCmdb['virtual'] = dataServiceNowCmdb['virtual'].replace({'true': True})
    dataServiceNowCmdb['backlevel'] = dataServiceNowCmdb['backlevel'].replace({'true': True})
    dataServiceNowCmdb['backup'] = dataServiceNowCmdb['backup'].replace({'true': True})

    for hostidZabbix, hostZabbix, statusZabbix, companyZabbix, classstrZabbix, environmentZabbix, criticalityZabbix, stateZabbix, descriptionZabbix, hostFunctionZabbix, instanceBankZabbix, clusterZabbix, soxZabbix, vaultZabbix, ipAddressZabbix, domainZabbix, typeNetworkZabbix, typeOsZabbix, vmhostZabbix, backLevelZabbix, localZabbix, manufactureZabbix, typeCPUZabbix, numberCPUZabbix, memoryRAMZabbix, backupZabbix in zip(dataZabbix['hostid'],
        dataZabbix['host'], dataZabbix['status'], dataZabbix['company'], dataZabbix['class'], dataZabbix['environment'], dataZabbix['criticality'], dataZabbix['state'], dataZabbix['description'],
        dataZabbix['hostFunction'], dataZabbix['instanceBank'], dataZabbix['cluster'], dataZabbix['sox'], dataZabbix['vault'],dataZabbix['ipAddress'], dataZabbix['domain'],dataZabbix['typeNetwork'], 
        dataZabbix['typeOs'], dataZabbix['vmhost'], dataZabbix['backLevel'], dataZabbix['local'], dataZabbix['manufacture'], dataZabbix['typeCPU'],
        dataZabbix['numberCPU'], dataZabbix['memoryRAM'], dataZabbix['backup']):

        for sys_id_ic, host_id, name, host_name, company, class_name, environment, criticality, status, description, short_description, category, instance_bank, cluster, sox, vault, ip_address, dns_domain, domain, system_domain, type_network, os, virtual, backLevel, location, manufacturer, cpu_type, cpu_count, ram, backup, discovery_source in zip(dataServiceNowCmdb['sys_id_ic'],
            dataServiceNowCmdb['host_id'], dataServiceNowCmdb['name'], dataServiceNowCmdb['host_name'], dataServiceNowCmdb['company'], dataServiceNowCmdb['class_name'], dataServiceNowCmdb['environment'], dataServiceNowCmdb['criticality'], dataServiceNowCmdb['status'],
            dataServiceNowCmdb['description'], dataServiceNowCmdb['short_description'], dataServiceNowCmdb['category'], dataServiceNowCmdb['instance_bank'], dataServiceNowCmdb['cluster'], dataServiceNowCmdb['sox'], dataServiceNowCmdb['vault'],
            dataServiceNowCmdb['ip_address'], dataServiceNowCmdb['dns_domain'], dataServiceNowCmdb['domain'], dataServiceNowCmdb['system_domain'], dataServiceNowCmdb['type_network'], dataServiceNowCmdb['os'], dataServiceNowCmdb['virtual'],
            dataServiceNowCmdb['backlevel'], dataServiceNowCmdb['location'], dataServiceNowCmdb['manufacturer'], dataServiceNowCmdb['cpu_type'], dataServiceNowCmdb['cpu_count'], dataServiceNowCmdb['ram'], dataServiceNowCmdb['backup'], dataServiceNowCmdb['discovery_source']):
            
            if hostidZabbix == host_id:

                dadosZabbix = []
                dadosSn = []
                # não precisa incluir o hostid do zabbix e o sysid do SN tambem não entra na comparação
                # discovery source também retirado
                arrayTempZabbix = {
                    'name': hostZabbix.upper(), 
                    'host_name': hostZabbix.upper(),
                    'company': companyZabbix.upper(), 
                    'class_name' : classstrZabbix.upper(), 
                    'environment' : environmentZabbix.upper(), 
                    'criticality' : criticalityZabbix.upper(),
                    'status' : statusZabbix.upper(),
                    'description' : descriptionZabbix.upper(),
                    'short_description' : descriptionZabbix.upper(),
                    'category' : hostFunctionZabbix.upper(),
                    'instance_bank' : instanceBankZabbix.upper(),
                    'cluster' : clusterZabbix,
                    'sox' : soxZabbix,
                    'vault' : vaultZabbix,
                    'ip_address' : ipAddressZabbix.upper(),
                    'dns_domain' : dns_domain.upper(),
                    'domain' : dns_domain.upper(),
                    'system_domain' : dns_domain.upper(),
                    'type_network' : typeNetworkZabbix.upper(),
                    'os' : typeOsZabbix.upper(),
                    'virtual' : vmhostZabbix,
                    'backlevel' : backLevelZabbix,
                    'location' : localZabbix.upper(),
                    'manufacturer' : manufactureZabbix.upper(),
                    'backup' : backupZabbix
                }

                arrayTempSn = {
                    'name': name.upper(), 
                    'host_name': host_name.upper(),
                    'company': company.upper(), 
                    'class_name' : class_name.upper(), 
                    'environment' : environment.upper(), 
                    'criticality' : criticality.upper(),
                    'status' : status.upper(),
                    'description' : description.upper(),
                    'short_description' : short_description.upper(),
                    'category' : category.upper(),
                    'instance_bank' : instance_bank.upper(),
                    'cluster' : cluster,
                    'sox' : sox,
                    'vault' : vault,
                    'ip_address' : ip_address.upper(),
                    'dns_domain' : dns_domain.upper(),
                    'domain' : dns_domain.upper(),
                    'system_domain' : dns_domain.upper(),
                    'type_network' : type_network.upper(),
                    'os' : os.upper(),
                    'virtual' : virtual,
                    'backlevel' : backLevel,
                    'location' : location.upper(),
                    'manufacturer' : manufacturer.upper(),
                    'backup' : backup
                }
                
                # arrays temporarios
                dadosZabbix.append(arrayTempZabbix)
                dadosSn.append(arrayTempSn)
                # dataframes temporarios
                dataTempZabbix = pd.DataFrame(dadosZabbix)
                dataTempSn = pd.DataFrame(dadosSn)

                # Comparando os DataFrames
                compare = dataTempZabbix.compare(dataTempSn)

                # Printando as diferenças encontradas
                if not compare.empty:
                    print("contagem numero: ", count)
                    count = count + 1
                    print("Diferenças encontradas:")
                    print(compare)

                    dataTemp = {
                        # Informações Gerais
                        'u_hostid': hostidZabbix,
                        'sysid': sys_id_ic,
                        'name': hostZabbix,
                        'host_name': hostZabbix,
                        'company': companyZabbix,
                        'sys_class_name': classstrZabbix,
                        'environment': environmentZabbix,
                        'u_ci_criticality': criticalityZabbix,
                        'operational_status': statusZabbix,
                        'u_description': descriptionZabbix,
                        'short_description': descriptionZabbix,
                        'category': hostFunctionZabbix,
                        'u_instances_banks':  instanceBankZabbix,
                        'u_cluster': clusterZabbix,
                        'u_sox': soxZabbix,
                        'u_safe_box' : vaultZabbix,
                        'ip_address': ipAddressZabbix,
                        'dns_domain': domainZabbix,
                        'u_domain': domainZabbix,
                        'sys_domain': domainZabbix,
                        'u_tipo_de_rede': typeNetworkZabbix,
                        'u_os_custom': typeOsZabbix,
                        'virtual': vmhostZabbix,
                        'u_backlevel': backLevelZabbix,
                        'location': localZabbix,
                        'manufacturer': manufactureZabbix,
                        'cpu_type': typeCPUZabbix,
                        'cpu_count': numberCPUZabbix,
                        'ram': memoryRAMZabbix,
                        'u_backup' : backupZabbix,
                        'discovery_source' : 'Zabbix'
                    }

                    dados.append(dataTemp)
                else:
                    next
    
    df = pd.DataFrame(dados)
    return df

# função para realizar o update de dados alterados em host existentes no CMDB                
def service_now_update(dataUpdateCmdb, urlInputSn, userServiceNow, userPassServiceNow):

    for u_hostid, sysid, name, company, sys_class_name, environment, u_ci_criticality, operational_status, u_description, short_description, category, u_instances_banks, u_cluster, u_sox, u_safe_box, ip_address, dns_domain, u_domain, sys_domain, u_tipo_de_rede, u_os_custom, virtual, u_backlevel, location, manufacturer, cpu_type, cpu_count, ram, u_backup, discovery_source in zip(dataUpdateCmdb['u_hostid'],
        dataUpdateCmdb['sysid'], dataUpdateCmdb['name'], dataUpdateCmdb['company'], dataUpdateCmdb['sys_class_name'], dataUpdateCmdb['environment'], dataUpdateCmdb['u_ci_criticality'], dataUpdateCmdb['operational_status'], dataUpdateCmdb['u_description'],
        dataUpdateCmdb['short_description'], dataUpdateCmdb['category'], dataUpdateCmdb['u_instances_banks'], dataUpdateCmdb['u_cluster'], dataUpdateCmdb['u_sox'],dataUpdateCmdb['u_safe_box'], dataUpdateCmdb['ip_address'],
        dataUpdateCmdb['dns_domain'], dataUpdateCmdb['u_domain'], dataUpdateCmdb['sys_domain'], dataUpdateCmdb['u_tipo_de_rede'], dataUpdateCmdb['u_os_custom'], dataUpdateCmdb['virtual'], dataUpdateCmdb['u_backlevel'],
        dataUpdateCmdb['location'], dataUpdateCmdb['manufacturer'], dataUpdateCmdb['cpu_type'], dataUpdateCmdb['cpu_count'], dataUpdateCmdb['ram'], dataUpdateCmdb['u_backup'], dataUpdateCmdb['discovery_source']):

        # Dados a serem enviados na solicitação
        data = {
            # Informações Gerais
            'u_hostid': u_hostid,
            'name': name,
            'host_name': name,
            'company': company,
            'sys_class_name': sys_class_name, #cmdb_ci_win_server, cmdb_ci_esx_server
            'environment': environment, # tratar string
            'u_ci_criticality': u_ci_criticality,
            'operational_status': operational_status, # tratar númerico
            'u_description': u_description,
            'short_description': short_description,
            'category': category,
            'u_instances_banks':  u_instances_banks,
            'u_cluster': u_cluster, # tratar booleano
            'u_sox': u_sox, # tratar boleano
            'u_safe_box' : u_safe_box, # tratar boleano
            'ip_address': ip_address,
            'dns_domain': dns_domain,
            'u_domain': u_domain,
            'sys_domain': sys_domain,
            'u_tipo_de_rede': u_tipo_de_rede,
            'u_os_custom': u_os_custom,
            'virtual': virtual, # tratar boleano
            'u_backlevel': u_backlevel, # tratar boleano
            'location': location,
            'manufacturer': manufacturer,
            'cpu_type': cpu_type,
            'cpu_count': cpu_count,
            'ram': ram,
            'u_backup' : u_backup,
            'discovery_source' : 'Zabbix'
        }

        # Cabeçalhos da solicitação
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        urlUpdate = f"{urlInputSn}/{sysid}"
        print(urlUpdate)
        try:
            # Enviar solicitação PATCH para atualizar o host cadastrado no CMDB
            response = requests.patch(urlUpdate, auth=(userServiceNow, userPassServiceNow), json=data, headers=headers)
            print(response)
            # Verificar se a solicitação foi bem-sucedida
            if response.status_code == 200:
                print(f"host: {name} com ID: {u_hostid} feito update com sucesso")
            else:
                print(f"Falha ao realizar o update para o host: {name} com ID: {u_hostid}. Código de status HTTP: {response.status_code}")
                print(f"Resposta: {response.content.decode()}")
        except Exception as e:
            print(f"Ocorreu um erro ao enviar a solicitação: {str(e)}")

# função de processamento dos dados advindos do zabbix e do cmdb
def main_process(urls, urlLocation, urlCompanyAndManufacture, urlInputSn, userServiceNow, userPassServiceNow, zabbix_url, headers, auth_data):

    # funções que carregam dados para os dataframes vindos do servicenow
    dataServiceNowCmdb = get_cmdb_for_all(urls, userServiceNow, userPassServiceNow)
    dataServiceNowCmdbLocation = get_cmdb_location(urlLocation, userServiceNow, userPassServiceNow)
    dataServiceNowCmdbCompanyManufacture = get_cmdb_company_manufacture(urlCompanyAndManufacture, userServiceNow, userPassServiceNow)

    print(dataServiceNowCmdb.head(500))
    
    # funções que carregam dados para o dataframe com dados vindos do zabbix
    dataZabbix = zabbix_autetication(zabbix_url, auth_data, headers)

    # função que faz a integração de dados vindos do servicenow, essa função integram os dataframes do linux, ESX e windows com seus dados nas tabelas que tem o company, manufacture e location
    dataIntegratedCmdb = servicenow_integrated(dataServiceNowCmdb, dataServiceNowCmdbLocation, dataServiceNowCmdbCompanyManufacture)

    print(dataIntegratedCmdb.info())
    print(dataIntegratedCmdb.isnull().values.any())
    print(dataIntegratedCmdb.describe())
    print(dataIntegratedCmdb.head(500))

    # ajuste de dados para o Dataframe do Zabbix
    dataZabbixAdjustment = zabbix_adjustment(dataZabbix) 

    # função que detecta novos host adicionados ao Zabbix 
    dataNewHostCmdb = host_verification(dataIntegratedCmdb, dataZabbixAdjustment)

    if dataNewHostCmdb.empty:
        print("Frame vazio")
        next
    else:
        print("############# NEW HOST ################")
        print(dataNewHostCmdb.info())
        print(dataNewHostCmdb.isnull().values.any())
        print(dataNewHostCmdb.describe())
        print(dataNewHostCmdb.head(1000))

        """count4 =  dataNewHostCmdb['host'].value_counts().reset_index() 
        count4.colums = ['Valor', 'Freq']

        print(count4)"""
        service_now_input(urlInputSn, userServiceNow, userPassServiceNow, dataNewHostCmdb)

    # função que detecta dados alterados em um host existente no CMDB
    dataUpdateCmdb = zabbix_servicenow_compare_database(dataIntegratedCmdb, dataZabbixAdjustment)

    if dataUpdateCmdb.empty:
        print("Frame vazio")
        next
    else:
        print("############# UPDATE ################")
        print(dataUpdateCmdb.info())
        print(dataUpdateCmdb.isnull().values.any())
        print(dataUpdateCmdb.describe())
        print(dataUpdateCmdb.head(500))


        count4 =  dataUpdateCmdb['name'].value_counts().reset_index() 
        count4.colums = ['Valor', 'Freq']

        print(count4)
        service_now_update(dataUpdateCmdb, urlInputSn, userServiceNow, userPassServiceNow)

main_process(urls, urlLocation, urlCompanyAndManufacture, urlInputSn, userServiceNow, userPassServiceNow, zabbix_url, headers, auth_data)
