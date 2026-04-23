# syntax=docker/dockerfile:1.7-labs

ARG DOTNET_VERSION=9.0
ARG BUILD_CONFIGURATION=Release

######## RUNTIME ########
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS runtime
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

######## BUILD ########
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copiar .csproj dos Componentes (repo myhub-api-all-components)
COPY myhub-api-all-components/DomainObjects/DomainObjects.csproj                myhub-api-all-components/DomainObjects/
COPY myhub-api-all-components/MessageBus/MessageBus.csproj                   myhub-api-all-components/MessageBus/
COPY myhub-api-all-components/SecurityCore/SecurityCore.csproj               myhub-api-all-components/SecurityCore/
COPY myhub-api-all-components/MicroserviceCore/MicroserviceCore.csproj       myhub-api-all-components/MicroserviceCore/
COPY myhub-api-all-components/IntegrationHandlers/IntegrationHandlers.csproj myhub-api-all-components/IntegrationHandlers/

# Copiar .csproj do servico Authentication (repo myhub-api-authentication)
COPY myhub-api-authentication/AuthenticationAPI/AuthenticationAPI.csproj                             myhub-api-authentication/AuthenticationAPI/
COPY myhub-api-authentication/AuthenticationApplication/AuthenticationApplication.csproj             myhub-api-authentication/AuthenticationApplication/
COPY myhub-api-authentication/AuthenticationDomain/AuthenticationDomain.csproj                       myhub-api-authentication/AuthenticationDomain/
COPY myhub-api-authentication/AuthenticationInfrastructure/AuthenticationInfrastructure.csproj       myhub-api-authentication/AuthenticationInfrastructure/

# Restore
RUN dotnet restore myhub-api-authentication/AuthenticationAPI/AuthenticationAPI.csproj

# Copiar todo o codigo-fonte
COPY myhub-api-all-components/ ./myhub-api-all-components/
COPY myhub-api-authentication/ ./myhub-api-authentication/

# Build
WORKDIR /src/myhub-api-authentication/AuthenticationAPI
RUN dotnet publish AuthenticationAPI.csproj -c ${BUILD_CONFIGURATION} -o /app/publish /p:UseAppHost=false

######## FINAL ########
FROM runtime AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "AuthenticationAPI.dll"]
