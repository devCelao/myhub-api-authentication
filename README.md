# MyHub — API Authentication

API de autenticação e autorização com JWT, refresh tokens e gerenciamento de chaves JWKS.

## Estrutura

```
AuthenticationAPI/           → Controllers e configuração da API
AuthenticationApplication/   → Serviços e lógica de aplicação
AuthenticationDomain/        → Entidades e DTOs
AuthenticationInfrastructure/ → Repositórios e contexto de dados
```

## Desenvolvimento Local

Requisitos: Docker, Docker Compose e .NET 9.0

### Rodar com Docker Compose

```bash
# 1. Configurar variáveis de ambiente
cp .env.example .env

# 2. Subir o container
docker compose up -d --build
```

A API fica disponível em `http://api-authentication.localhost` (via Traefik).

### Rodar com dotnet CLI

```bash
cd AuthenticationAPI
dotnet run
```

A API fica disponível em `http://localhost:8080`.

## Deploy

O deploy é feito via GitHub Actions. Para publicar uma nova versão no Docker Hub:

1. Criar uma tag no repositório (ex: `v1.2.0`)
2. Ir em **Actions → Build & Push Docker Image**
3. Executar manualmente informando a tag criada

A imagem é publicada como `<dockerhub-username>/api-authentication:<tag>`.
