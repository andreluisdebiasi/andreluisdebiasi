#!/bin/bash

# Faz a requisição à API de autenticação do Salesforce
response=$(curl -s "@option.ES_SALESFORCE_AUTH_URL@/services/oauth2/token" \
  -d "grant_type=password" \
  -d "client_id=@option.ES_SALESFORCE_CLIENT_ID@" \
  -d "client_secret=@option.ES_SALESFORCE_CLIENT_SECRET@" \
  -d "username=@option.ES_SALESFORCE_USER@" \
  -d "password=@option.ES_SALESFORCE_PWD@")

# Verifica se a requisição foi bem-sucedida
if [[ $? -ne 0 ]]; then
  echo "Erro ao realizar a autenticação no Salesforce."
  exit 1
fi

# Extrai o 'access_token' da resposta
access_token=$(echo "$response" | /apl/elk/logstash-prd/config/pipelines/ultragaz/salesforce/jq -r '.access_token')

# Verifica se o 'access_token' foi extraído com sucesso
if [[ -z "$access_token" || "$access_token" == "null" ]]; then
  echo "Erro: não foi possível extrair o 'access_token'."
  exit 1
fi

# Armazena o 'access_token' no arquivo especificado
echo "$access_token" > /apl/elk/logstash-prd/config/pipelines/ultragaz/salesforce/.access_token

# Atualizar Keystore Token
cat /apl/elk/logstash-prd/config/pipelines/ultragaz/salesforce/.access_token | sudo /usr/bin/heartbeat keystore add salesforce_access_token --stdin --force

# Restart Heartbeat
sudo /bin/systemctl restart heartbeat-elastic.service

# Exibe mensagem de sucesso
echo "Access Token foi adicionado ao Logstash Keystore com sucesso."
