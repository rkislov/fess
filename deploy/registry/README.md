# FESS Docker Registry

Приватный registry на сервере: **чтение (pull) без пароля**, **запись (push/delete) только с Basic Auth**.

## Запуск

```bash
cd deploy/registry
# Создайте пользователя (если ещё нет auth/htpasswd):
htpasswd -Bbn fess 'YOUR_PUSH_PASSWORD' > auth/htpasswd
chmod 600 auth/htpasswd
docker compose up -d
```

По умолчанию слушает **`:5000`**. Переменная: `REGISTRY_HOST_PORT`.

На хосте с **ufw** откройте порт (и не забудьте SSH, если включаете firewall с нуля):

```bash
ufw allow 22222/tcp
ufw allow 5000/tcp comment 'FESS Docker Registry'
ufw reload
ufw status
```

## Клиент Docker (HTTP)

На машинах, которые пушат/пулят по HTTP:

```json
{
  "insecure-registries": ["85.137.24.140:5000"]
}
```

в `/etc/docker/daemon.json`, затем `systemctl restart docker`.

```bash
# pull — без логина
docker pull 85.137.24.140:5000/fess/policy-api:latest

# push — нужен логин
docker login 85.137.24.140:5000 -u fess
docker tag fess/policy-api:local 85.137.24.140:5000/fess/policy-api:latest
docker push 85.137.24.140:5000/fess/policy-api:latest
```

## Смена пароля

```bash
htpasswd -Bbn fess 'NEW_PASSWORD' > auth/htpasswd
docker compose -f deploy/registry/docker-compose.yml restart registry-proxy
```

Файл `auth/htpasswd` и `.credentials.local` **не коммитятся**.
