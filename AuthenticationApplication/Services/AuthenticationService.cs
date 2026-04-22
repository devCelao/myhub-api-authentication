using AuthenticationDomain.Dtos;
using AuthenticationDomain.Entities;
using AuthenticationDomain.Extensions;
using AuthenticationInfrastructure.Repositories;
using DomainObjects.Enums;
using MicroserviceCore.Respostas;
using Microsoft.Extensions.Options;
using System.Text.RegularExpressions;

namespace AuthenticationApplication.Services;

public interface IAuthenticationService
{
    Task<ServiceResult> CriarAcessoUsuario(Guid idUsuario, string email, string senha);
    Task<ServiceResult<DesbloqueioResponse>> DesbloquearContaAdmin(string email);

    Task<ServiceResult> IniciarResetSenha(string email, string ipOrigem, string? userAgent = null);
    Task<ServiceResult> ValidarCodigoResetSenha(string codigo, string email);
    Task<ServiceResult> FinalizarResetSenha(string codigo, string email, string novaSenha, string ipOrigem);

    Task<ServiceResult<TokenResponse>> RealizarLogin(string email, string senha, string? ipOrigem = null, string? deviceInfo = null, string? userAgent = null);
    Task<ServiceResult<TokenResponse>> RenovarAccessToken(string refreshToken, string? issuer = null);

    ServiceResult<TokenResponse> RealizarLoginRoot(string email, string senha);
}

public class AuthenticationService(
    IAuthenticationRepository repository,
    ITokenService tokenService,
    IEmailService email,
    IOptions<AppSettings> appSettings) : IAuthenticationService
{
    private readonly IAuthenticationRepository _repository = repository;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IEmailService _emailService = email;
    private readonly AppSettings _appSettings = appSettings.Value;

    public async Task<ServiceResult> CriarAcessoUsuario(Guid idUsuario, string email, string senha)
    {
        var acessoExistente = await _repository.ObterUsuarioPorId(idUsuario);
        if (acessoExistente is not null)
            return ServiceResult.Failure("Ja existe um acesso criado para este usuario.");

        var emailEmUso = await _repository.ObterUsuarioPorEmail(email);
        if (emailEmUso is not null)
            return ServiceResult.Failure("Este email ja esta em uso.");

        string senhaCrypto = CriptografarSenha(senha);

        var novoAcesso = new AcessoUsuario(email, senhaCrypto, idUsuario);
        _repository.AdicionaUsuario(novoAcesso);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult.Failure("Erro ao criar acesso do usuario.");

        return ServiceResult.Success("Acesso criado com sucesso. Voce ja pode fazer login com seu email e senha.");
    }

    public async Task<ServiceResult<TokenResponse>> RealizarLogin(string email, string senha, string? ipOrigem = null, string? deviceInfo = null, string? userAgent = null)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);
        if (usuario is null)
            return ServiceResult<TokenResponse>.Failure("Email ou senha invalidos.");

        if (!usuario.PodeFazerLogin())
        {
            if (usuario.TipoBloqueio == TipoBloqueio.ManualPermanente)
                return ServiceResult<TokenResponse>.Failure("Conta bloqueada permanentemente. Entre em contato com o suporte.");
            else if (usuario.TipoBloqueio == TipoBloqueio.SuspeitaFraude)
                return ServiceResult<TokenResponse>.Failure("Conta bloqueada por suspeita de fraude. Entre em contato com o suporte.");
            else if (usuario.DataFimBloqueio.HasValue)
                return ServiceResult<TokenResponse>.Failure($"Conta bloqueada temporariamente ate {usuario.DataFimBloqueio.Value:dd/MM/yyyy HH:mm}.");
            else
                return ServiceResult<TokenResponse>.Failure("Conta inativa. Entre em contato com o suporte.");
        }

        if (!VerificarSenha(senha, usuario.SenhaCrypto))
        {
            usuario.RegistrarTentativaFalha(ipOrigem);
            _repository.AtualizarUsuario(usuario);
            await _repository.UnitOfWork.Commit();

            return ServiceResult<TokenResponse>.Failure("Email ou senha invalidos.");
        }

        usuario.RegistrarLoginSucesso(ipOrigem);
        _repository.AtualizarUsuario(usuario);

        var (accessToken, refreshToken) = await GerarTokensAutenticacao(usuario, deviceInfo, ipOrigem, userAgent);

        _repository.AdicionarRefreshToken(refreshToken);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult<TokenResponse>.Failure("Erro ao realizar login.");

        return ServiceResult<TokenResponse>.Success(CriarTokenResponse(accessToken, refreshToken.Token));
    }

    public async Task<ServiceResult<DesbloqueioResponse>> DesbloquearContaAdmin(string email)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);
        if (usuario is null)
            return ServiceResult<DesbloqueioResponse>.NotFound("Usuario nao encontrado.");

        usuario.DesbloquearConta();
        _repository.AtualizarUsuario(usuario);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult<DesbloqueioResponse>.Failure("Erro ao desbloquear conta.");

        var response = new DesbloqueioResponse
        {
            IdUsuario = usuario.IdUsuario,
            Email = usuario.Email,
            Status = "Conta desbloqueada com sucesso."
        };

        return ServiceResult<DesbloqueioResponse>.Success(response, "Conta desbloqueada com sucesso.");
    }

    public async Task<ServiceResult> IniciarResetSenha(string email, string ipOrigem, string? userAgent = null)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);

        if (usuario is null)
            return ServiceResult.Success("Se o email estiver cadastrado, voce recebera instrucoes para redefinir sua senha.");

        if (!usuario.IndAtivo)
            return ServiceResult.Success("Se o email estiver cadastrado, voce recebera instrucoes para redefinir sua senha.");

        const int limiteMinutos = 60;
        const int maxSolicitacoes = 3;
        var solicitacoesRecentes = await _repository.ContarTokensRedefinicaoSenhaRecentes(usuario.IdUsuario, limiteMinutos);

        if (solicitacoesRecentes >= maxSolicitacoes)
            return ServiceResult.Failure($"Limite de solicitacoes atingido. Tente novamente em {limiteMinutos} minutos.");

        await _repository.InativarTokensRedefinicaoSenhaUsuario(usuario.IdUsuario, "Novo codigo solicitado");

        var codigoNumerico = TokenRedefinicaoSenha.GerarCodigoNumerico();
        var tokenRedefinicao = new TokenRedefinicaoSenha(
            usuario.IdUsuario,
            usuario.Email,
            codigoNumerico,
            ipOrigem,
            userAgent
        );

        _repository.AdicionarTokenRedefinicaoSenha(tokenRedefinicao);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult.Failure("Erro ao processar solicitacao de reset de senha.");

        await _emailService.EnviarEmailResetSenha(usuario.Email, codigoNumerico);

        return ServiceResult.Success("Se o email estiver cadastrado, voce recebera instrucoes para redefinir sua senha.");
    }

    public async Task<ServiceResult> ValidarCodigoResetSenha(string codigo, string email)
    {
        if (string.IsNullOrWhiteSpace(codigo) || string.IsNullOrWhiteSpace(email))
            return ServiceResult.Failure("Codigo ou email invalido.");

        if (!Regex.IsMatch(codigo, @"^\d{6}$"))
            return ServiceResult.Failure("Codigo deve conter 6 digitos.");

        var codigoHash = _tokenService.GerarHashToken(codigo);
        var tokenRedefinicao = await _repository.ObterTokenRedefinicaoSenhaPorHash(codigoHash);

        if (tokenRedefinicao is null)
            return ServiceResult.Failure("Codigo invalido ou expirado.");

        if (!tokenRedefinicao.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
            return ServiceResult.Failure("Codigo invalido.");

        if (!tokenRedefinicao.ValidarCodigo(codigo))
        {
            _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);
            await _repository.UnitOfWork.Commit();

            return tokenRedefinicao.TentativasInvalidas >= 5
                ? ServiceResult.Failure("Codigo bloqueado por excesso de tentativas invalidas.")
                : ServiceResult.Failure("Codigo invalido ou expirado.");
        }

        return ServiceResult.Success("Codigo validado com sucesso. Voce pode definir sua nova senha.");
    }

    public async Task<ServiceResult> FinalizarResetSenha(string codigo, string email, string novaSenha, string ipOrigem)
    {
        if (string.IsNullOrWhiteSpace(codigo) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(novaSenha))
            return ServiceResult.Failure("Dados invalidos para reset de senha.");

        if (!Regex.IsMatch(codigo, @"^\d{6}$"))
            return ServiceResult.Failure("Codigo deve conter 6 digitos.");

        if (novaSenha.Length < 8)
            return ServiceResult.Failure("A senha deve ter no minimo 8 caracteres.");

        var codigoHash = _tokenService.GerarHashToken(codigo);
        var tokenRedefinicao = await _repository.ObterTokenRedefinicaoSenhaPorHash(codigoHash);

        if (tokenRedefinicao is null)
            return ServiceResult.Failure("Codigo invalido ou expirado.");

        if (!tokenRedefinicao.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
            return ServiceResult.Failure("Codigo invalido.");

        if (!tokenRedefinicao.ValidarCodigo(codigo))
        {
            _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);
            await _repository.UnitOfWork.Commit();

            return tokenRedefinicao.TentativasInvalidas >= 5
                ? ServiceResult.Failure("Codigo bloqueado por excesso de tentativas invalidas.")
                : ServiceResult.Failure("Codigo invalido ou expirado.");
        }

        var usuario = tokenRedefinicao.Usuario;
        if (usuario is null)
            return ServiceResult.NotFound("Usuario nao encontrado.");

        if (VerificarSenha(novaSenha, usuario.SenhaCrypto))
            return ServiceResult.Failure("A nova senha deve ser diferente da senha atual.");

        usuario.SenhaCrypto = CriptografarSenha(novaSenha);
        usuario.DataUltimaTrocaSenha = DateTime.UtcNow;
        usuario.VersaoSenha++;
        usuario.IndTrocaSenha = false;

        tokenRedefinicao.MarcarComoUtilizado(ipOrigem);

        await _repository.RevogarRefreshTokensUsuario(usuario.IdUsuario, "Senha redefinida");

        _repository.AtualizarUsuario(usuario);
        _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult.Failure("Erro ao resetar a senha.");

        if (tokenRedefinicao.IpUtilizacaoDiferente())
        {
            await _emailService.EnviarEmailAlertaSeguranca(usuario.Email);
        }

        await _emailService.EnviarEmailConformacaoAlteracao(usuario.Email);

        return ServiceResult.Success("Senha redefinida com sucesso. Voce pode fazer login com a nova senha.");
    }

    public async Task<ServiceResult<TokenResponse>> RenovarAccessToken(string refreshToken, string? issuer = null)
    {
        var hash = _tokenService.GerarHashToken(refreshToken);
        var token = await _repository.ObterRefreshTokenPorHash(hash);

        if (token is null)
            return ServiceResult<TokenResponse>.Failure("Refresh token invalido.");

        if (token.IndUtilizado)
        {
            await _repository.RevogarRefreshTokensUsuario(token.IdUsuario, "Tentativa de reuso de refresh token detectada");
            return ServiceResult<TokenResponse>.Failure("Refresh token ja utilizado. Todas as sessoes foram revogadas por seguranca.");
        }

        if (!token.EstaValido())
        {
            if (token.IndRevogado)
                return ServiceResult<TokenResponse>.Failure("Refresh token revogado.");
            else if (token.DataExpiracao < DateTime.UtcNow)
                return ServiceResult<TokenResponse>.Failure("Refresh token expirado.");
            else
                return ServiceResult<TokenResponse>.Failure("Refresh token invalido.");
        }

        if (!token.VersaoSenhaValida(token.Usuario!.VersaoSenha))
        {
            token.Revogar("Senha do usuario foi alterada");
            _repository.AtualizarRefreshToken(token);
            await _repository.UnitOfWork.Commit();
            return ServiceResult<TokenResponse>.Failure("Refresh token invalido. Senha foi alterada.");
        }

        var (novoAccessToken, novoRefreshToken) = await GerarTokensAutenticacao(
            token.Usuario,
            token.DeviceInfo,
            token.IpOrigem,
            token.UserAgent,
            issuer
        );

        token.MarcarComoUtilizado(novoRefreshToken.IdRefreshToken);
        _repository.AtualizarRefreshToken(token);
        _repository.AdicionarRefreshToken(novoRefreshToken);

        if (!await _repository.UnitOfWork.Commit())
            return ServiceResult<TokenResponse>.Failure("Erro ao renovar access token.");

        return ServiceResult<TokenResponse>.Success(CriarTokenResponse(novoAccessToken, novoRefreshToken.Token));
    }

    public ServiceResult<TokenResponse> RealizarLoginRoot(string email, string senha)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(senha))
            return ServiceResult<TokenResponse>.Failure("Credenciais invalidas.");

        if (string.IsNullOrWhiteSpace(_appSettings.RootEmail) || string.IsNullOrWhiteSpace(_appSettings.RootPassword))
            return ServiceResult<TokenResponse>.Failure("Credenciais invalidas.");

        if (!_appSettings.RootEmail.Equals(email, StringComparison.OrdinalIgnoreCase) ||
            !_appSettings.RootPassword.Equals(senha, StringComparison.Ordinal))
            return ServiceResult<TokenResponse>.Failure("Credenciais invalidas.");

        var accessToken = _tokenService.GerarAccessTokenRoot(email);
        var refreshToken = _tokenService.GerarRefreshToken();

        return ServiceResult<TokenResponse>.Success(CriarTokenResponse(accessToken, refreshToken));
    }

    private async Task<(string accessToken, RefreshToken refreshToken)> GerarTokensAutenticacao(
        AcessoUsuario usuario,
        string? deviceInfo = null,
        string? ipOrigem = null,
        string? userAgent = null,
        string? issuer = null)
    {
        var jwtId = _tokenService.GerarJwtId();
        var accessToken = await _tokenService.GerarAccessToken(usuario, issuer: issuer, jwtId: jwtId);
        var refreshTokenValue = _tokenService.GerarRefreshToken();

        var refreshToken = new RefreshToken(
            usuario.IdUsuario,
            refreshTokenValue,
            jwtId,
            usuario.VersaoSenha,
            deviceInfo,
            ipOrigem,
            userAgent
        );

        return (accessToken, refreshToken);
    }

    private static TokenResponse CriarTokenResponse(string accessToken, string refreshToken) => new()
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        ExpiresIn = 900,
        RefreshExpiresIn = 2592000,
        TokenType = "Bearer"
    };

    private static bool VerificarSenha(string senha, string senhaCrypto)
        => !string.IsNullOrWhiteSpace(senha) && !string.IsNullOrWhiteSpace(senhaCrypto) && BCrypt.Net.BCrypt.Verify(senha, senhaCrypto);

    private static string CriptografarSenha(string senha) => BCrypt.Net.BCrypt.HashPassword(senha);
}
