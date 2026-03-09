# Acesse https://aka.ms/customizecontainer para saber como personalizar seu contêiner de depuração e como o Visual Studio usa este Dockerfile para criar suas imagens para uma depuração mais rápida.

ARG DOTNET_VERSION=9.0
ARG BUILD_CONFIGURATION=Release

######## RUNTIME ########
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS runtime
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

######## BUILD ########
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS compilate
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copiar arquivos de projeto dos Componentes (dependências)
COPY myhub-api-all-components/DomainCore/DomainObjects.csproj                         myhub-api-all-components/DomainCore/
COPY myhub-api-all-components/DataTransferObjects/DataTransferObjects.csproj          myhub-api-all-components/DataTransferObjects/
COPY myhub-api-all-components/MessageBus/MessageBus.csproj                            myhub-api-all-components/MessageBus/
COPY myhub-api-all-components/SecurityCore/SecurityCore.csproj                        myhub-api-all-components/SecurityCore/
COPY myhub-api-all-components/MicroserviceCore/MicroserviceCore.csproj                myhub-api-all-components/MicroserviceCore/
COPY myhub-api-all-components/IntegrationHandlers/IntegrationHandlers.csproj          myhub-api-all-components/IntegrationHandlers/

# Copiar arquivos de projeto do serviço Authentication
COPY myhub-api-authentication/AuthenticationAPI/AuthenticationAPI.csproj                     myhub-api-authentication/AuthenticationAPI/
COPY myhub-api-authentication/AuthenticationApplication/AuthenticationApplication.csproj    myhub-api-authentication/AuthenticationApplication/
COPY myhub-api-authentication/AuthenticationDomain/AuthenticationDomain.csproj              myhub-api-authentication/AuthenticationDomain/
COPY myhub-api-authentication/AuthenticationInfrastructure/AuthenticationInfrastructure.csproj myhub-api-authentication/AuthenticationInfrastructure/

# Restore
RUN dotnet restore myhub-api-authentication/AuthenticationAPI/AuthenticationAPI.csproj

# Copiar todo o código
COPY myhub-api-all-components/ ./myhub-api-all-components/
COPY myhub-api-authentication/ ./myhub-api-authentication/

# Build
WORKDIR /src/myhub-api-authentication/AuthenticationAPI
RUN dotnet publish -c ${BUILD_CONFIGURATION} -o /app/publish /p:UseAppHost=false

######## FINAL ########
FROM runtime AS final
WORKDIR /app
COPY --from=compilate /app/publish .
ENTRYPOINT ["dotnet", "AuthenticationAPI.dll"]
