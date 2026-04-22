using AuthenticationInfrastructure.Context;
using MessageBus.Interfaces;
using MicroserviceCore.Controller;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;

namespace AuthenticationAPI.Controllers;

[AllowAnonymous]
[Route("api/authentication/health")]
public class HealthController(AcessoContext dbContext, IBusMessage busMessage) : BaseController
{
    private readonly AcessoContext _dbContext = dbContext;
    private readonly IBusMessage _busMessage = busMessage;

    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<IActionResult> Get()
    {
        var dbCheck = await CheckDatabase();
        var mqCheck = CheckMessageBus();

        var isHealthy = dbCheck.Status == "Healthy" && mqCheck.Status == "Healthy";

        var result = new
        {
            Status = isHealthy ? "Healthy" : "Unhealthy",
            Timestamp = DateTime.UtcNow,
            Service = "Authentication API",
            Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0",
            Checks = new
            {
                Database = dbCheck,
                MessageBus = mqCheck
            }
        };

        return isHealthy ? Ok(result) : StatusCode(503, result);
    }

    [HttpGet("ping")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult Ping() => Ok(new { Status = "Alive", Timestamp = DateTime.UtcNow });

    private async Task<HealthCheckResult> CheckDatabase()
    {
        try
        {
            var canConnect = await _dbContext.Database.CanConnectAsync();
            return new HealthCheckResult(
                canConnect ? "Healthy" : "Unhealthy",
                "MySQL",
                canConnect ? "Connection established" : "Unable to connect"
            );
        }
        catch (Exception ex)
        {
            return new HealthCheckResult("Unhealthy", "MySQL", $"Erro: {ex.Message}");
        }
    }

    private HealthCheckResult CheckMessageBus()
    {
        try
        {
            var connected = _busMessage.IsConnected;
            return new HealthCheckResult(
                connected ? "Healthy" : "Unhealthy",
                "RabbitMQ",
                connected ? "Connection established" : "Broker not connected"
            );
        }
        catch (Exception ex)
        {
            return new HealthCheckResult("Unhealthy", "RabbitMQ", $"Erro: {ex.Message}");
        }
    }
}

public record HealthCheckResult(string Status, string Component, string Description);
