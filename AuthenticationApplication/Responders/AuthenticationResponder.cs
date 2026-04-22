using AuthenticationApplication.Services;
using AuthenticationInfrastructure.Repositories;
using IntegrationHandlers.Requests.Authetication;
using MessageBus.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityCore.Services;

namespace AuthenticationApplication.Responders;

public class AuthenticationResponder(
    IBusMessage busMessage,
    IServiceProvider serviceProvider,
    ILogger<AuthenticationResponder> logger) : BackgroundService
{
    private readonly IBusMessage _busMessage = busMessage;
    private readonly IServiceProvider _provider = serviceProvider;
    private readonly ILogger<AuthenticationResponder> _logger = logger;

    private IDisposable? _validateSessionDisposable;
    private IDisposable? _refreshTokenDisposable;
    private IDisposable? _getJwksDisposable;
    private IDisposable? _acessoDisposable;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("[AuthenticationResponder] Aguardando RabbitMQ estar pronto...");
        await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);

        _logger.LogInformation("[AuthenticationResponder] Registrando responders...");

        _validateSessionDisposable = await _busMessage.RespondAsync<ValidateSessionRequest, ValidateSessionResponse>(
            async (request) =>
            {
                _logger.LogInformation("[ValidateSession] Validando sessao...");
                return await HandleValidateSession(request);
            });

        _refreshTokenDisposable = await _busMessage.RespondAsync<RefreshTokenRequest, RefreshTokenResponse>(
            async (request) =>
            {
                _logger.LogInformation("[RefreshToken] Renovando token...");
                return await HandleRefreshToken(request);
            });

        _getJwksDisposable = await _busMessage.RespondAsync<GetJwksRequest, GetJwksResponse>(
            async (request) =>
            {
                _logger.LogInformation("[GetJwks] Obtendo chaves JWKS...");
                return await Task.FromResult(HandleGetJwks());
            });

        _acessoDisposable = await _busMessage.RespondAsync<AcessoRequest, AcessoResponse>(
            async (request) =>
            {
                _logger.LogInformation("[Acesso] Processando acesso para usuario: {Email}", request.Email);
                using var scope = _provider.CreateScope();
                var authService = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();
                var resultado = await authService.CriarAcessoUsuario(request.IdUsuario, request?.Email!, request?.Senha!);
                return new AcessoResponse(resultado.Message, resultado.Errors);
            });

        _logger.LogInformation("[AuthenticationResponder] Todos os responders registrados com sucesso!");

        await Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task<ValidateSessionResponse> HandleValidateSession(ValidateSessionRequest request)
    {
        try
        {
            using var scope = _provider.CreateScope();
            var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
            var repository = scope.ServiceProvider.GetRequiredService<IAuthenticationRepository>();

            if (string.IsNullOrEmpty(request.RefreshToken))
            {
                _logger.LogWarning("[ValidateSession] RefreshToken vazio");
                return ValidateSessionResponse.Invalid("RefreshToken nao fornecido");
            }

            var hash = tokenService.GerarHashToken(request.RefreshToken);
            var token = await repository.ObterRefreshTokenPorHash(hash);

            if (token is null)
            {
                _logger.LogWarning("[ValidateSession] Token nao encontrado no banco");
                return ValidateSessionResponse.Invalid("Token nao encontrado");
            }

            if (!token.EstaValido())
            {
                if (token.IndRevogado)
                {
                    _logger.LogWarning("[ValidateSession] Token revogado: {Motivo}", token.MotivoRevogacao);
                    return ValidateSessionResponse.Invalid($"Sessao revogada: {token.MotivoRevogacao}");
                }
                if (token.IndUtilizado)
                {
                    _logger.LogWarning("[ValidateSession] Token ja utilizado");
                    return ValidateSessionResponse.Invalid("Token ja utilizado");
                }
                if (token.DataExpiracao < DateTime.UtcNow)
                {
                    _logger.LogWarning("[ValidateSession] Token expirado");
                    return ValidateSessionResponse.Invalid("Token expirado");
                }

                return ValidateSessionResponse.Invalid("Token invalido");
            }

            var usuario = await repository.ObterUsuarioPorId(token.IdUsuario);
            if (usuario is not null && !token.VersaoSenhaValida(usuario.VersaoSenha))
            {
                _logger.LogWarning("[ValidateSession] VersaoSenha divergente para usuario: {IdUsuario}", token.IdUsuario);
                return ValidateSessionResponse.Invalid("Senha foi alterada. Faca login novamente.");
            }

            _logger.LogInformation("[ValidateSession] Sessao valida para usuario: {IdUsuario}", token.IdUsuario);
            return ValidateSessionResponse.Valid();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ValidateSession] Erro ao validar sessao");
            return ValidateSessionResponse.Invalid($"Erro interno: {ex.Message}");
        }
    }

    private async Task<RefreshTokenResponse> HandleRefreshToken(RefreshTokenRequest request)
    {
        try
        {
            using var scope = _provider.CreateScope();
            var authService = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

            _logger.LogInformation("[RefreshToken] Chamando RenovarAccessToken com issuer: {Issuer}", request.Issuer ?? "N/A");
            var resultado = await authService.RenovarAccessToken(request.RefreshToken, request.Issuer);

            if (!resultado.IsSuccess || resultado.Data is null)
            {
                _logger.LogWarning("[RefreshToken] Falha: {Erros}", string.Join(", ", resultado.Errors));
                return RefreshTokenResponse.Failed();
            }

            _logger.LogInformation("[RefreshToken] Tokens renovados com sucesso");
            return RefreshTokenResponse.Succeeded(
                resultado.Data.AccessToken,
                resultado.Data.RefreshToken,
                resultado.Data.ExpiresIn,
                resultado.Data.RefreshExpiresIn);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[RefreshToken] Erro ao renovar token");
            return RefreshTokenResponse.Failed();
        }
    }

    private GetJwksResponse HandleGetJwks()
    {
        try
        {
            using var scope = _provider.CreateScope();
            var jwksService = scope.ServiceProvider.GetRequiredService<IJwksService>();

            var keys = jwksService.GetPublicKeys(5);

            var jwks = new { keys };
            var jwksJson = System.Text.Json.JsonSerializer.Serialize(jwks, new System.Text.Json.JsonSerializerOptions
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            });

            _logger.LogInformation("[GetJwks] Retornando {Count} chaves publicas", keys.Count);
            return new GetJwksResponse(jwksJson);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[GetJwks] Erro ao obter chaves JWKS");
            return new GetJwksResponse("{}");
        }
    }

    public override void Dispose()
    {
        _validateSessionDisposable?.Dispose();
        _refreshTokenDisposable?.Dispose();
        _getJwksDisposable?.Dispose();
        _acessoDisposable?.Dispose();
        base.Dispose();
        GC.SuppressFinalize(this);
    }
}
