using System.Security.Claims;
using System.Text.Encodings.Web;
using AuthenticationApplication.Services;
using AuthenticationInfrastructure.Context;
using AuthenticationInfrastructure.Repositories;
using DomainObjects.Data;
using MessageBus.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using SecurityCore.Services;
using SecurityCore.Store;

namespace AuthenticationTest.Integration;

public class AuthenticationApiFactory : WebApplicationFactory<Program>
{
    public Mock<IAuthenticationRepository> AuthRepoMock { get; } = new();
    public Mock<ITokenService> TokenServiceMock { get; } = new();
    public Mock<IEmailService> EmailServiceMock { get; } = new();
    public Mock<IUnitOfWork> UnitOfWorkMock { get; } = new();

    public AuthenticationApiFactory()
    {
        AuthRepoMock.Setup(r => r.UnitOfWork).Returns(UnitOfWorkMock.Object);
        UnitOfWorkMock.Setup(u => u.Commit()).ReturnsAsync(true);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Connection:ConnectionString"] = "Server=localhost;Database=test;User=root;Password=test;",
                ["MessageQueueConnection:MessageBus"] = "amqp://guest:guest@localhost:5672/test",
                ["Jwt:Audience"] = "test-audience",
                ["Jwks:Algorithm"] = "RS256",
                ["Jwks:DaysUntilExpire"] = "90",
                ["Jwks:KeysToKeep"] = "5",
                ["Jwks:KeyPrefix"] = "test-",
                ["AppSettings:RootEmail"] = "root@test.com",
                ["AppSettings:RootPassword"] = "test-root-password"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            var hostedServices = services
                .Where(d => d.ServiceType == typeof(IHostedService))
                .ToList();
            foreach (var svc in hostedServices)
                services.Remove(svc);

            var dbDescriptors = services
                .Where(d => d.ServiceType == typeof(AcessoContext)
                          || d.ServiceType == typeof(DbContextOptions<AcessoContext>)
                          || d.ServiceType.FullName?.Contains("DbContextPool") == true
                          || d.ServiceType.FullName?.Contains("DbContextOptions") == true)
                .ToList();
            foreach (var d in dbDescriptors)
                services.Remove(d);

            services.AddDbContext<AcessoContext>(opts =>
                opts.UseInMemoryDatabase("AuthenticationTestDb"));

            services.RemoveAll<IBusMessage>();
            services.AddSingleton(new Mock<IBusMessage>().Object);

            services.RemoveAll<IJwksService>();
            services.AddSingleton(new Mock<IJwksService>().Object);

            services.RemoveAll<IDatabaseJwksStore>();
            services.AddSingleton(new Mock<IDatabaseJwksStore>().Object);

            services.RemoveAll<IIssuerService>();
            var issuerMock = new Mock<IIssuerService>();
            issuerMock.Setup(i => i.GetCurrentIssuer()).Returns("test-issuer");
            services.AddSingleton(issuerMock.Object);

            services.RemoveAll<IAuthenticationRepository>();
            services.RemoveAll<ITokenService>();
            services.RemoveAll<IEmailService>();

            services.AddSingleton(AuthRepoMock.Object);
            services.AddSingleton(TokenServiceMock.Object);
            services.AddSingleton(EmailServiceMock.Object);

            services.AddAuthentication("Test")
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

            services.PostConfigure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = "Test";
                o.DefaultChallengeScheme = "Test";
            });
        });
    }
}

public class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, "integration-test-user"),
            new Claim(ClaimTypes.Email, "test@test.com")
        };

        var identity = new ClaimsIdentity(claims, "Test");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, "Test");

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
