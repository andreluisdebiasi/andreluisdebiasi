import requests

# Configurações do Zabbix
zabbix_url = 'https://zabbixurl.com.br/api_jsonrpc.php'
zabbix_user = 'user'
zabbix_password = senha

# Headers da requisição
headers = {
    'Content-Type': 'application/json'
}

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

# Função para obter informações dos hosts de uma lista de groupids
def get_hosts_info(auth_token, group_ids, hostname):
    for group_id in group_ids:
        # Dados para obter os hosts do grupo específico com todos os campos de inventário
        hosts_data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": ["hostid", "host", "inventory"],
                "groupids": group_id,
                "selectInventory": list(inventory_mapping.keys()),
                "filter": {"host": [hostname]}
            },
            "auth": auth_token,
            "id": 2
        }
        # Requisição para obter os hosts do grupo específico
        hosts_response = requests.post(zabbix_url, json=hosts_data, headers=headers, verify=False)
        if hosts_response.status_code == 200:
            hosts_info = hosts_response.json().get('result')
            # Verificar se há hosts na resposta
            if hosts_info:
                # Processar os hosts
                for host in hosts_info:
                    host_id = host.get('hostid')
                    host_name = host.get('host')
                    inventory = host.get('inventory', {})
                    if inventory:
                        # Verificar se há informações de inventário
                        print(f"Host ID: {host_id}, Name: {host_name}, Inventory Data:")
                        # Iterar sobre os campos de inventário e renomear conforme o mapeamento
                        for field, renamed_field in inventory_mapping.items():
                            value = inventory.get(field)
                            print(f"{renamed_field}: {value}")
                        print()
                    else:
                        print(f"Nenhum valor de inventário encontrado para o host {host_name}")
            else:
                print(f"Nenhuma informação de hosts encontrada para o groupid {group_id}.")
        else:
            print("Erro durante o processamento da resposta:", hosts_response.text)

# Autenticação no Zabbix
auth_data = {
    "jsonrpc": "2.0",
    "method": "user.login",
    "params": {
        "user": zabbix_user,
        "password": zabbix_password
    },
    "id": 1
}
auth_response = requests.post(zabbix_url, json=auth_data, headers=headers, verify=False)
if auth_response.status_code == 200:
    auth_token = auth_response.json().get('result')
    # IDs dos grupos de servidores desejados
    group_ids = ["99", "98"]  # Substitua pelos IDs dos grupos desejados
    # Nome do host a ser procurado
    hostname = "server"
    # Obter informações dos hosts para cada groupid
    get_hosts_info(auth_token, group_ids, hostname)
else:
    print("Erro durante a autenticação:", auth_response.text)
