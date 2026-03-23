using AuthenticationApplication.Services;
using AuthenticationApplication.Responders;
using AuthenticationInfrastructure.Context;
using AuthenticationInfrastructure.Repositories;
using AuthenticationInfrastructure.Store;
using MicroserviceCore.Configuration;
using Microsoft.OpenApi.Models;
using SecurityCore.Services;
using SecurityCore.Store;
using MessageBus.Configuration;

var builder = WebApplication.CreateBuilder(args);
bool isDevelopment = builder.Environment.IsDevelopment();
builder.AddJsonFile();

if (isDevelopment)
{
    builder.Configuration.AddUserSecrets<Program>();
}

// Add o contexto de banco de dados
builder.Services.AddContextCustomConfiguration<AcessoContext>(builder.Configuration);

// Add os controllers
builder.Services.AddExtensionConfiguration();

// Add configurações do cors
builder.Services.AddCustomCors();

// Add configurações do swagger
var infoApi = new OpenApiInfo
{
    Version = "v1",
    Title = "Authentication API",
    Description = "API de autenticação e autorização",
    Contact = new()
    {
        Name = "",
        Email = "",
        Url = new Uri(uriString: "https://www.linkedin.com/in/fernandes-marcelo/")
    },
    License = new()
    {
        Name = "MIT",
        Url = new Uri(uriString: "https://opensorce.org/licenses/MIT")
    }
};

builder.Services.AddSwaggerConfiguration(infoApi);

// ========== Autenticação JWT com JWKS (API Provider) ==========

// Registrar DatabaseJwksStore (específico desta API)
builder.Services.AddScoped<IDatabaseJwksStore, DatabaseJwksStore>();

// Registrar IssuerService (para issuer dinâmico baseado no subdomínio)
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IIssuerService, IssuerService>();

// Configurar JWT Provider (gera tokens com issuer dinâmico)
builder.Services.AddJwtAuthenticationProvider(builder.Configuration);

// ========== Services ==========

builder.Services.AddScoped<IAuthenticationRepository, AuthenticationRepository>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IEmailService, EmailService>();
// Handler
builder.Services.AddMediatR(c => c.RegisterServicesFromAssemblyContaining<Program>());

// MessageBus - Responder para validação de sessão, refresh token e JWKS
builder.Services.AddMessageBusResponder<AuthenticationResponder>(builder.Configuration);
var app = builder.Build();

app.UseSwaggerConfiguration(isDevelopment);

app.UseCustomCors();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();