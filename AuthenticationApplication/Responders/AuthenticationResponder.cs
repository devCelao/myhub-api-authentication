using AuthenticationApplication.Services;
using AuthenticationInfrastructure.Repositories;
using MessageBus.Interfaces;
using MessageBus.Messages.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SecurityCore.Services;
using System.Text.Json;

namespace AuthenticationApplication.Responders;

/// <summary>
/// Responder para mensagens de autenticação via MessageBus
/// Processa: ValidateSession, RefreshToken, GetJwks
/// </summary>
public class AuthenticationResponder : BackgroundService
{
    private readonly IBusMessage _busMessage;
    private readonly IServiceProvider _provider;
    private readonly ILogger<AuthenticationResponder> _logger;
    
    private IDisposable? _validateSessionDisposable;
    private IDisposable? _refreshTokenDisposable;
    private IDisposable? _getJwksDisposable;

    public AuthenticationResponder(
        IBusMessage busMessage,
        IServiceProvider serviceProvider,
        ILogger<AuthenticationResponder> logger)
    {
        _busMessage = busMessage;
        _provider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🔐 [AuthenticationResponder] Aguardando RabbitMQ estar pronto...");
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        _logger.LogInformation("🔐 [AuthenticationResponder] Registrando responders...");

        // Registrar responder para ValidateSession
        _validateSessionDisposable = await _busMessage.RespondAsync<ValidateSessionRequest, ValidateSessionResponse>(
            async (request) =>
            {
                _logger.LogInformation("🔐 [ValidateSession] Validando sessão...");
                return await HandleValidateSession(request);
            });

        // Registrar responder para RefreshToken
        _refreshTokenDisposable = await _busMessage.RespondAsync<RefreshTokenRequest, RefreshTokenResponse>(
            async (request) =>
            {
                _logger.LogInformation("🔄 [RefreshToken] Renovando token...");
                return await HandleRefreshToken(request);
            });

        // Registrar responder para GetJwks
        _getJwksDisposable = await _busMessage.RespondAsync<GetJwksRequest, GetJwksResponse>(
            async (request) =>
            {
                _logger.LogInformation("🔑 [GetJwks] Obtendo chaves JWKS...");
                return await Task.FromResult(HandleGetJwks());
            });

        _logger.LogInformation("✅ [AuthenticationResponder] Todos os responders registrados com sucesso!");

        // Manter o serviço vivo
        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    /// <summary>
    /// Valida se o refresh token ainda é válido (não revogado, não expirado)
    /// </summary>
    private async Task<ValidateSessionResponse> HandleValidateSession(ValidateSessionRequest request)
    {
        try
        {
            using var scope = _provider.CreateScope();
            var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
            var repository = scope.ServiceProvider.GetRequiredService<IAuthenticationRepository>();

            if (string.IsNullOrEmpty(request.RefreshToken))
            {
                _logger.LogWarning("🔐 [ValidateSession] RefreshToken vazio");
                return ValidateSessionResponse.Invalid("RefreshToken não fornecido");
            }

            // Gerar hash do token para buscar no banco
            var hash = tokenService.GerarHashToken(request.RefreshToken);
            var token = await repository.ObterRefreshTokenPorHash(hash);

            if (token is null)
            {
                _logger.LogWarning("🔐 [ValidateSession] Token não encontrado no banco");
                return ValidateSessionResponse.Invalid("Token não encontrado");
            }

            if (!token.EstaValido())
            {
                if (token.IndRevogado)
                {
                    _logger.LogWarning("🔐 [ValidateSession] Token revogado: {Motivo}", token.MotivoRevogacao);
                    return ValidateSessionResponse.Invalid($"Sessão revogada: {token.MotivoRevogacao}");
                }
                if (token.IndUtilizado)
                {
                    _logger.LogWarning("🔐 [ValidateSession] Token já utilizado");
                    return ValidateSessionResponse.Invalid("Token já utilizado");
                }
                if (token.DataExpiracao < DateTime.UtcNow)
                {
                    _logger.LogWarning("🔐 [ValidateSession] Token expirado");
                    return ValidateSessionResponse.Invalid("Token expirado");
                }

                return ValidateSessionResponse.Invalid("Token inválido");
            }

            _logger.LogInformation("✅ [ValidateSession] Sessão válida para usuário: {IdUsuario}", token.IdUsuario);
            return ValidateSessionResponse.Valid();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ [ValidateSession] Erro ao validar sessão");
            return ValidateSessionResponse.Invalid($"Erro interno: {ex.Message}");
        }
    }

    /// <summary>
    /// Renova o access token usando o refresh token
    /// </summary>
    private async Task<RefreshTokenResponse> HandleRefreshToken(RefreshTokenRequest request)
    {
        try
        {
            using var scope = _provider.CreateScope();
            var authService = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

            _logger.LogInformation("🔄 [RefreshToken] Chamando RenovarAccessToken com issuer: {Issuer}", request.Issuer ?? "N/A");
            var resultado = await authService.RenovarAccessToken(request.RefreshToken, request.Issuer);

            if (resultado.PossuiErros)
            {
                _logger.LogWarning("🔄 [RefreshToken] Falha: {Erros}", string.Join(", ", resultado.Errors));
                return RefreshTokenResponse.Failed();
            }

            // Verificar se ResultObject existe
            if (resultado.ResultObject == null)
            {
                _logger.LogWarning("🔄 [RefreshToken] ResultObject é nulo!");
                return RefreshTokenResponse.Failed();
            }

            // Extrair tokens do resultado
            var resultJson = JsonSerializer.Serialize(resultado.ResultObject);
            _logger.LogInformation("🔄 [RefreshToken] ResultObject JSON: {Json}", resultJson);
            
            var tokens = JsonSerializer.Deserialize<TokenData>(resultJson, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            _logger.LogInformation("🔄 [RefreshToken] Tokens deserializados - AccessToken: {HasAccess}, RefreshToken: {HasRefresh}", 
                tokens?.AccessToken != null, 
                tokens?.RefreshToken != null);

            if (tokens?.AccessToken == null || tokens?.RefreshToken == null)
            {
                _logger.LogWarning("🔄 [RefreshToken] Tokens não encontrados no resultado. AccessToken: '{Access}', RefreshToken: '{Refresh}'",
                    tokens?.AccessToken ?? "NULL",
                    tokens?.RefreshToken ?? "NULL");
                return RefreshTokenResponse.Failed();
            }

            _logger.LogInformation("✅ [RefreshToken] Tokens renovados com sucesso");
            return RefreshTokenResponse.Succeeded(
                tokens.AccessToken, 
                tokens.RefreshToken,
                tokens.ExpiresIn,
                tokens.RefreshExpiresIn);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ [RefreshToken] Erro ao renovar token");
            return RefreshTokenResponse.Failed();
        }
    }

    /// <summary>
    /// Obtém as chaves públicas JWKS
    /// </summary>
    private GetJwksResponse HandleGetJwks()
    {
        try
        {
            using var scope = _provider.CreateScope();
            var jwksService = scope.ServiceProvider.GetRequiredService<IJwksService>();

            var keys = jwksService.GetPublicKeys(5);
            
            // Serializar para formato JWKS padrão
            var jwks = new { keys = keys };
            var jwksJson = JsonSerializer.Serialize(jwks, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            _logger.LogInformation("✅ [GetJwks] Retornando {Count} chaves públicas", keys.Count);
            return new GetJwksResponse(jwksJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ [GetJwks] Erro ao obter chaves JWKS");
            return new GetJwksResponse("{}");
        }
    }

    public override void Dispose()
    {
        _validateSessionDisposable?.Dispose();
        _refreshTokenDisposable?.Dispose();
        _getJwksDisposable?.Dispose();
        base.Dispose();
    }
}

// DTO interno para deserialização
// Nota: Usa PropertyNameCaseInsensitive na deserialização para funcionar com PascalCase ou camelCase
internal class TokenData
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public int ExpiresIn { get; set; } = 900;
    public int RefreshExpiresIn { get; set; } = 2592000;
}

