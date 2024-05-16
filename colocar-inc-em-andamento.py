import requests
import json

# Verificação se as variáveis de Rundeck foram substituídas
sys_id = "@option.SysID_INC@"
password = "@option.sn_pwd@"
cmdb_ci = "@option.cmdb_ic@"


if sys_id.startswith("@") or password.startswith("@"):
    print("Erro: As variáveis do Rundeck não foram substituídas corretamente.")
else:
    # URL do incidente que deseja fechar
    incident_url = f"https://instance.service-now.com/api/now/table/incident/{sys_id}"

    # Dados para atualizar o incidente e marcá-lo como fechado
    payload = {
        'state': '2',
        'u_state': '2',
        'comments':'alterado para em em andamento automaticamente',
        'incident_state': '2',
        "caller_id": "callerid"
    }

    # Cabeçalhos da solicitação
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        # Enviar solicitação PATCH para fechar o incidente
        response = requests.patch(incident_url, auth=("user", password), json=payload, headers=headers)

        # Verificar se a solicitação foi bem-sucedida
        if response.status_code == 200:
            print("Incidente colocado em andamento com sucesso.")
        else:
            print(f"Falha ao colocar incidente em andamento. Código de status HTTP: {response.status_code}")
            print(f"Resposta: {response.content.decode()}")

    except Exception as e:
        print(f"Ocorreu um erro ao enviar a solicitação: {str(e)}")
