using System.Net;
using System.Net.Http.Json;
using AuthenticationDomain.Dtos;
using FluentAssertions;
using MicroserviceCore.Respostas;

namespace AuthenticationTest.Integration;

public class AuthenticacaoControllerTests(AuthenticationApiFactory factory)
    : IClassFixture<AuthenticationApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Login_SemBody_DeveRetornar400()
    {
        var response = await _client.PostAsJsonAsync("api/authentication/login", new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task CriarAcesso_SemBody_DeveRetornar400()
    {
        var response = await _client.PostAsJsonAsync("api/authentication/criar-acesso", new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ValidateResetCode_SemBody_DeveRetornar400()
    {
        var response = await _client.PostAsJsonAsync("api/authentication/validate-reset-code", new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPassword_SemBody_DeveRetornar400()
    {
        var response = await _client.PostAsJsonAsync("api/authentication/reset-password", new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task HealthCheck_DeveRetornarOk()
    {
        var response = await _client.GetAsync("api/authentication/health/ping");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
