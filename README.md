# MyHub Authentication API

## Visao Geral

API REST de autenticacao e autorizacao do MyHub. Gerencia criacao de acessos, login com JWT, refresh tokens com rotacao automatica, JWKS (JSON Web Key Set), reset de senha com codigo de verificacao e acesso root.

## Arquitetura

Projeto organizado em 4 camadas seguindo Clean Architecture:

- **AuthenticationAPI** - Controllers REST, configuracao do pipeline
- **AuthenticationApplication** - Application Services, Responders (RabbitMQ)
- **AuthenticationDomain** - Entidades, DTOs, Validators (FluentValidation)
- **AuthenticationInfrastructure** - Repositorios, DbContext (EF Core + MySQL)

## Tecnologias

- .NET 9.0
- Entity Framework Core 9 (Pomelo MySQL)
- FluentValidation
- RabbitMQ (MessageBus)
- JWT Authentication (Provider mode com JWKS)
- BCrypt (hash de senhas)
- Docker

## Endpoints

### Health
| Verbo | Rota | Descricao | Auth | Status codes |
|-------|------|-----------|------|-------------|
| GET | `/api/authentication/health` | Health check (DB + RabbitMQ) | Nao | 200, 503 |
| GET | `/api/authentication/health/ping` | Ping | Nao | 200 |

### Autenticacao
| Verbo | Rota | Descricao | Auth | Status codes |
|-------|------|-----------|------|-------------|
| POST | `/api/authentication/criar-acesso` | Criar acesso (email + senha) | Nao | 200, 400 |
| POST | `/api/authentication/login` | Login (retorna access + refresh token) | Nao | 200, 400 |
| POST | `/api/authentication/refresh` | Renovar access token via refresh token | Sim | 200, 400, 401 |
| POST | `/api/authentication/root-login` | Login root (credenciais do appsettings) | Nao | 200, 400 |

### Gerenciamento de Conta
| Verbo | Rota | Descricao | Auth | Status codes |
|-------|------|-----------|------|-------------|
| GET | `/api/authentication/desbloquear-conta/{email}` | Desbloquear conta de usuario | Sim | 200, 400, 401, 404 |

### Reset de Senha
| Verbo | Rota | Descricao | Auth | Status codes |
|-------|------|-----------|------|-------------|
| POST | `/api/authentication/forgot-password/{email}` | Iniciar reset (envia codigo por email) | Nao | 200, 400 |
| POST | `/api/authentication/validate-reset-code` | Validar codigo de verificacao | Nao | 200, 400 |
| POST | `/api/authentication/reset-password` | Redefinir senha com codigo | Nao | 200, 400 |

### JWKS
| Verbo | Rota | Descricao | Auth | Status codes |
|-------|------|-----------|------|-------------|
| GET | `/.well-known/jwks.json` | Chaves publicas para validacao de tokens JWT | Nao | 200, 500 |

## Formato de Resposta

Todas as respostas seguem o envelope padronizado `ApiResponse<T>`:

**Sucesso com dados:**
```json
{ "success": true, "message": "Descricao.", "data": { ... }, "errors": [] }
```

**Sucesso sem dados (operacoes de comando):**
```json
{ "success": true, "message": "Descricao.", "data": null, "errors": [] }
```

**Erro:**
```json
{ "success": false, "message": "Descricao do erro.", "data": null, "errors": [{ "code": "ERR", "message": "detalhe" }] }
```

## Entidades

- **AcessoUsuario** - Credenciais de acesso (email, senha criptografada, bloqueio, tentativas)
- **RefreshToken** - Token opaco com rotacao automatica, deteccao de reuso e versao de senha
- **TokenRedefinicaoSenha** - Codigo de verificacao para reset de senha (6 digitos, com limite de tentativas)

## MessageBus (RabbitMQ)

O `AuthenticationResponder` processa mensagens via RabbitMQ:

- **ValidateSession** - Valida se refresh token e sessao ainda sao validos
- **RefreshToken** - Renova access token via refresh token (para outras APIs)
- **GetJwks** - Retorna chaves publicas JWKS
- **Acesso** - Cria acesso de usuario (chamado pela API de Management)

## Como Executar

### Pre-requisitos
- .NET 9.0 SDK
- MySQL
- RabbitMQ
- Docker (opcional)

### Execucao Local

```
cd AuthenticationAPI
dotnet restore
dotnet run
```

### Execucao com Docker

```
docker compose up
```

### Testes

```
dotnet test AuthenticationTest/AuthenticationTest.csproj
```

## Estrutura de Pastas

```
myhub-api-authentication/
|-- AuthenticationAPI/
|   |-- Controllers/          # AuthenticacaoController, HealthController, JwksController
|   |-- Program.cs            # Pipeline e DI
|-- AuthenticationApplication/
|   |-- Services/             # AuthenticationService, TokenService, EmailService
|   |-- Responders/           # AuthenticationResponder (RabbitMQ)
|-- AuthenticationDomain/
|   |-- Entities/             # AcessoUsuario, RefreshToken, TokenRedefinicaoSenha
|   |-- Dtos/                 # DTOs e Requests
|   |-- Validators/           # FluentValidation
|-- AuthenticationInfrastructure/
|   |-- Context/              # AcessoContext (EF Core)
|   |-- Repositories/         # AuthenticationRepository
|   |-- Store/                # DatabaseJwksStore
|-- AuthenticationTest/
|   |-- Domain/               # Testes de validadores
|   |-- Integration/          # Testes de integracao (WebApplicationFactory)
```

## Dependencias Externas

Componentes compartilhados em `myhub-api-all-components`:
- **DomainObjects** - IUnitOfWork, ConnectionSettings
- **MicroserviceCore** - BaseController, ServiceResult, JWT, CORS, Swagger, Error handling
- **MessageBus** - RabbitMQ
- **IntegrationHandlers** - Request/Response para comunicacao entre APIs
- **SecurityCore** - JWKS, JWT Provider, IssuerService
