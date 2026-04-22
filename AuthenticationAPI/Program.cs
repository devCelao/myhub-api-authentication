using AuthenticationApplication.Services;
using AuthenticationApplication.Responders;
using AuthenticationDomain.Validators;
using AuthenticationInfrastructure.Context;
using AuthenticationInfrastructure.Repositories;
using AuthenticationInfrastructure.Store;
using FluentValidation;
using FluentValidation.AspNetCore;
using MicroserviceCore.Configuration;
using MicroserviceCore.Extensions;
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

builder.Services.AddContextCustomConfiguration<AcessoContext>(builder.Configuration);

builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();
builder.Services.AddValidatorsFromAssemblyContaining<LoginRequestValidator>();

builder.Services.AddExtensionConfiguration();

builder.Services.AddCustomCors();

var infoApi = new OpenApiInfo
{
    Version = "v1",
    Title = "Authentication API",
    Description = "API de autenticacao e autorizacao",
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

builder.Services.AddScoped<IDatabaseJwksStore, DatabaseJwksStore>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IIssuerService, IssuerService>();

builder.Services.AddJwtAuthenticationProvider(builder.Configuration);

builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

builder.Services.AddScoped<IAuthenticationRepository, AuthenticationRepository>();
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IEmailService, EmailService>();

builder.Services.AddMessageBusResponder<AuthenticationResponder>(builder.Configuration);

var app = builder.Build();

app.UseSwaggerConfiguration(isDevelopment);

app.UseCustomCors();

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.UseCustomError();

app.Run();

public partial class Program { }
