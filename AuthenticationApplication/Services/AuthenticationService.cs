using AuthenticationDomain.Entities;
using AuthenticationInfrastructure.Repositories;
using DomainObjects.Enums;
using MicroserviceCore.Respostas;
using MicroserviceCore.Services;
using System.Text.RegularExpressions;

namespace AuthenticationApplication.Services;
public interface IAuthenticationService
{
    // Criação de Acesso (após confirmação de email)
    Task<RespostaProcessamento> CriarAcessoUsuario(Guid idUsuario, string email, string senha);
    Task<RespostaProcessamento> DesbloquearContaAdmin(string email);

    // Reset de Senha
    Task<RespostaProcessamento> IniciarResetSenha(string email, string ipOrigem, string? userAgent = null);
    Task<RespostaProcessamento> ValidarCodigoResetSenha(string codigo, string email);
    Task<RespostaProcessamento> FinalizarResetSenha(string codigo, string email, string novaSenha, string ipOrigem);

    // Autenticação
    Task<RespostaProcessamento> RealizarLogin(string email, string senha, string? ipOrigem = null, string? deviceInfo = null, string? userAgent = null);
    Task<RespostaProcessamento> RenovarAccessToken(string refreshToken, string? issuer = null);
}
public class AuthenticationService(IAuthenticationRepository repository, ITokenService tokenService, IEmailService email) : BaseContextService, IAuthenticationService
{
    private readonly IAuthenticationRepository _repository = repository;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IEmailService _emailService = email;
    public async Task<RespostaProcessamento> CriarAcessoUsuario(Guid idUsuario, string email, string senha)
    {
        // Verificar se já existe acesso para este usuário
        var acessoExistente = await _repository.ObterUsuarioPorId(idUsuario);
        if (acessoExistente is not null)
        {
            AddErroProcessamento("Já existe um acesso criado para este usuário.");
            return RetornaProcessamento();
        }

        // Verificar se email já está em uso
        var emailEmUso = await _repository.ObterUsuarioPorEmail(email);
        if (emailEmUso is not null)
        {
            AddErroProcessamento("Este email já está em uso.");
            return RetornaProcessamento();
        }

        string senhaCrypto = CriptografarSenha(senha);

        var novoAcesso = new AcessoUsuario(email, senhaCrypto, idUsuario);
        _repository.AdicionaUsuario(novoAcesso);

        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao criar acesso do usuário.");
            return RetornaProcessamento();
        }

        AdicionaRetorno(new
        {
            novoAcesso.IdUsuario,
            novoAcesso.Email
        });

        return RetornaProcessamento();
    }
    public async Task<RespostaProcessamento> RealizarLogin(string email, string senha, string? ipOrigem = null, string? deviceInfo = null, string? userAgent = null)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);
        if (usuario is null)
        {
            AddErroProcessamento("Email ou senha inválidos.");
            return RetornaProcessamento();
        }

        // Verificar se pode fazer login
        if (!usuario.PodeFazerLogin())
        {
            if (usuario.TipoBloqueio == TipoBloqueio.ManualPermanente)
                AddErroProcessamento("Conta bloqueada permanentemente. Entre em contato com o suporte.");
            else if (usuario.TipoBloqueio == TipoBloqueio.SuspeitaFraude)
                AddErroProcessamento("Conta bloqueada por suspeita de fraude. Entre em contato com o suporte.");
            else if (usuario.DataFimBloqueio.HasValue)
                AddErroProcessamento($"Conta bloqueada temporariamente até {usuario.DataFimBloqueio.Value:dd/MM/yyyy HH:mm}.");
            else
                AddErroProcessamento("Conta inativa. Entre em contato com o suporte.");

            return RetornaProcessamento();
        }

        if (!VerificarSenha(senha, usuario.SenhaCrypto))
        {
            usuario.RegistrarTentativaFalha(ipOrigem);
            _repository.AtualizarUsuario(usuario);
            await _repository.UnitOfWork.Commit();

            AddErroProcessamento("Email ou senha inválidos.");
            return RetornaProcessamento();
        }

        // Login bem-sucedido
        usuario.RegistrarLoginSucesso(ipOrigem);
        _repository.AtualizarUsuario(usuario);

        // Busca os dados do Usuario via RPC

        // Gerar tokens JWT usando TokenService
        var (accessToken, refreshToken) = await GerarTokensAutenticacao(usuario, deviceInfo, ipOrigem, userAgent);

        _repository.AdicionarRefreshToken(refreshToken);

        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao realizar login.");
            return RetornaProcessamento();
        }

        AdicionarRetornoTokens(accessToken, refreshToken.Token);

        return RetornaProcessamento();
    }
    public async Task<RespostaProcessamento> DesbloquearContaAdmin(string email)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);
        if (usuario is null)
        {
            AddErroProcessamento("Email ou senha inválidos.");
            return RetornaProcessamento();
        }

        usuario.DesbloquearConta();
        _repository.AtualizarUsuario(usuario);
        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao desbloquear conta.");
            return RetornaProcessamento();
        }
        AdicionaRetorno(new
        {
            usuario.IdUsuario,
            usuario.Email,
            Status = "Conta desbloqueada com sucesso."
        });
        return RetornaProcessamento();
    }
    public async Task<RespostaProcessamento> IniciarResetSenha(string email, string ipOrigem, string? userAgent = null)
    {
        var usuario = await _repository.ObterUsuarioPorEmail(email);
        
        // Por segurança, sempre retornar sucesso mesmo se o email não existir
        // Isso evita que atacantes descubram emails válidos no sistema
        if (usuario is null)
        {
            AdicionaRetorno(new
            {
                Mensagem = "Se o email estiver cadastrado, você receberá instruções para redefinir sua senha."
            });
            return RetornaProcessamento();
        }

        // Verificar se a conta está ativa
        if (!usuario.IndAtivo)
        {
            AdicionaRetorno(new
            {
                Mensagem = "Se o email estiver cadastrado, você receberá instruções para redefinir sua senha."
            });
            return RetornaProcessamento();
        }

        // Verificar limite de solicitações (proteção contra abuso)
        const int limiteMinutos = 60; // 1 hora
        const int maxSolicitacoes = 3;
        var solicitacoesRecentes = await _repository.ContarTokensRedefinicaoSenhaRecentes(usuario.IdUsuario, limiteMinutos);
        
        if (solicitacoesRecentes >= maxSolicitacoes)
        {
            AddErroProcessamento($"Limite de solicitações atingido. Tente novamente em {limiteMinutos} minutos.");
            return RetornaProcessamento();
        }

        // Inativar códigos anteriores do usuário
        await _repository.InativarTokensRedefinicaoSenhaUsuario(usuario.IdUsuario, "Novo código solicitado");

        // Gerar código numérico de 6 dígitos
        var codigoNumerico = TokenRedefinicaoSenha.GerarCodigoNumerico();
        var tokenRedefinicao = new TokenRedefinicaoSenha(
            usuario.IdUsuario,
            usuario.Email,
            codigoNumerico,
            ipOrigem,
            codigoNumerico
        );

        _repository.AdicionarTokenRedefinicaoSenha(tokenRedefinicao);

        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao processar solicitação de reset de senha.");
            return RetornaProcessamento();
        }

         await _emailService.EnviarEmailResetSenha(usuario.Email, codigoNumerico);

        AdicionaRetorno(new
        {
            Mensagem = "Se o email estiver cadastrado, você receberá um código de verificação para redefinir sua senha."
        });

        return RetornaProcessamento();
    }

    public async Task<RespostaProcessamento> ValidarCodigoResetSenha(string codigo, string email)
    {
        // Validações básicas
        if (string.IsNullOrWhiteSpace(codigo) || string.IsNullOrWhiteSpace(email))
        {
            AddErroProcessamento("Código ou email inválido.");
            return RetornaProcessamento();
        }

        // Validar formato do código (6 dígitos)
        if (!Regex.IsMatch(codigo, @"^\d{6}$"))
        {
            AddErroProcessamento("Código deve conter 6 dígitos.");
            return RetornaProcessamento();
        }

        // Gerar hash do código para buscar
        var codigoHash = _tokenService.GerarHashToken(codigo);
        var tokenRedefinicao = await _repository.ObterTokenRedefinicaoSenhaPorHash(codigoHash);

        if (tokenRedefinicao is null)
        {
            AddErroProcessamento("Código inválido ou expirado.");
            return RetornaProcessamento();
        }

        // Validar email
        if (!tokenRedefinicao.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
        {
            AddErroProcessamento("Código inválido.");
            return RetornaProcessamento();
        }

        // Validar código
        if (!tokenRedefinicao.ValidarCodigo(codigo))
        {
            _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);
            await _repository.UnitOfWork.Commit();

            if (tokenRedefinicao.TentativasInvalidas >= 5)
            {
                AddErroProcessamento("Código bloqueado por excesso de tentativas inválidas.");
            }
            else
            {
                AddErroProcessamento("Código inválido ou expirado.");
            }
            
            return RetornaProcessamento();
        }

        AdicionaRetorno(new
        {
            Mensagem = "Código validado com sucesso. Você pode definir sua nova senha.",
            CodigoValido = true
        });

        return RetornaProcessamento();
    }

    public async Task<RespostaProcessamento> FinalizarResetSenha(string codigo, string email, string novaSenha, string ipOrigem)
    {
        // Validações básicas
        if (string.IsNullOrWhiteSpace(codigo) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(novaSenha))
        {
            AddErroProcessamento("Dados inválidos para reset de senha.");
            return RetornaProcessamento();
        }

        // Validar formato do código (6 dígitos)
        if (!Regex.IsMatch(codigo, @"^\d{6}$"))
        {
            AddErroProcessamento("Código deve conter 6 dígitos.");
            return RetornaProcessamento();
        }

        // Validar força da senha
        if (novaSenha.Length < 8)
        {
            AddErroProcessamento("A senha deve ter no mínimo 8 caracteres.");
            return RetornaProcessamento();
        }

        // Gerar hash do código para buscar
        var codigoHash = _tokenService.GerarHashToken(codigo);
        var tokenRedefinicao = await _repository.ObterTokenRedefinicaoSenhaPorHash(codigoHash);

        if (tokenRedefinicao is null)
        {
            AddErroProcessamento("Código inválido ou expirado.");
            return RetornaProcessamento();
        }

        // Validar email (segurança adicional)
        if (!tokenRedefinicao.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
        {
            AddErroProcessamento("Código inválido.");
            return RetornaProcessamento();
        }

        // Validar código
        if (!tokenRedefinicao.ValidarCodigo(codigo))
        {
            _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);
            await _repository.UnitOfWork.Commit();

            if (tokenRedefinicao.TentativasInvalidas >= 5)
            {
                AddErroProcessamento("Código bloqueado por excesso de tentativas inválidas.");
            }
            else
            {
                AddErroProcessamento("Código inválido ou expirado.");
            }
            
            return RetornaProcessamento();
        }

        var usuario = tokenRedefinicao.Usuario;
        if (usuario is null)
        {
            AddErroProcessamento("Usuário não encontrado.");
            return RetornaProcessamento();
        }

        // Verificar se a nova senha é diferente da atual
        if (VerificarSenha(novaSenha, usuario.SenhaCrypto))
        {
            AddErroProcessamento("A nova senha deve ser diferente da senha atual.");
            return RetornaProcessamento();
        }

        // Atualizar senha
        usuario.SenhaCrypto = CriptografarSenha(novaSenha);
        usuario.DataUltimaTrocaSenha = DateTime.UtcNow;
        usuario.VersaoSenha++; // Incrementar versão para invalidar refresh tokens antigos
        usuario.IndTrocaSenha = false;

        // Marcar token como utilizado
        tokenRedefinicao.MarcarComoUtilizado(ipOrigem);

        // Revogar todos os refresh tokens do usuário por segurança
        await _repository.RevogarRefreshTokensUsuario(usuario.IdUsuario, "Senha redefinida");

        _repository.AtualizarUsuario(usuario);
        _repository.AtualizarTokenRedefinicaoSenha(tokenRedefinicao);

        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao resetar a senha.");
            return RetornaProcessamento();
        }

        // Verificar se o IP de utilização é diferente do IP de solicitação
        if (tokenRedefinicao.IpUtilizacaoDiferente())
        {
            // TODO: Enviar alerta de segurança por email
            // await _emailService.EnviarAlertaSeguranca(usuario.Email, "Senha alterada de IP diferente");
        }

        await _emailService.EnviarEmailConformacaoAlteracao(usuario.Email);

        AdicionaRetorno(new
        {
            Mensagem = "Senha redefinida com sucesso. Você pode fazer login com a nova senha."
        });

        return RetornaProcessamento();
    }
    public async Task<RespostaProcessamento> RenovarAccessToken(string refreshToken, string? issuer = null)
    {
        // Gerar hash do token para buscar usando TokenService
        var hash = _tokenService.GerarHashToken(refreshToken);

        var token = await _repository.ObterRefreshTokenPorHash(hash);

        if (token is null)
        {
            AddErroProcessamento("Refresh token inválido.");
            return RetornaProcessamento();
        }

        // Detectar tentativa de reuso (possível ataque)
        if (token.IndUtilizado)
        {
            // Revogar todos os tokens do usuário por segurança
            await _repository.RevogarRefreshTokensUsuario(token.IdUsuario, "Tentativa de reuso de refresh token detectada");
            AddErroProcessamento("Refresh token já utilizado. Todas as sessões foram revogadas por segurança.");
            return RetornaProcessamento();
        }

        if (!token.EstaValido())
        {
            if (token.IndRevogado)
                AddErroProcessamento("Refresh token revogado.");
            else if (token.DataExpiracao < DateTime.UtcNow)
                AddErroProcessamento("Refresh token expirado.");
            else
                AddErroProcessamento("Refresh token inválido.");

            return RetornaProcessamento();
        }

        // Validar versão da senha
        if (!token.VersaoSenhaValida(token.Usuario!.VersaoSenha))
        {
            token.Revogar("Senha do usuário foi alterada");
            _repository.AtualizarRefreshToken(token);
            await _repository.UnitOfWork.Commit();
            AddErroProcessamento("Refresh token inválido. Senha foi alterada.");
            return RetornaProcessamento();
        }

        // Gerar novo refresh token (rotação) usando TokenService
        // Passa o issuer recebido para manter consistência com o token original
        var (novoAccessToken, novoRefreshToken) = await GerarTokensAutenticacao(
            token.Usuario, 
            token.DeviceInfo, 
            token.IpOrigem, 
            token.UserAgent,
            issuer
        );

        // Marcar token antigo como utilizado
        token.MarcarComoUtilizado(novoRefreshToken.IdRefreshToken);

        _repository.AtualizarRefreshToken(token);

        _repository.AdicionarRefreshToken(novoRefreshToken);

        if (!await _repository.UnitOfWork.Commit())
        {
            AddErroProcessamento("Erro ao renovar access token.");
            return RetornaProcessamento();
        }

        AdicionarRetornoTokens(novoAccessToken, novoRefreshToken.Token);

        return RetornaProcessamento();
    }
    private async Task<(string accessToken, RefreshToken refreshToken)> GerarTokensAutenticacao(
        AcessoUsuario usuario, 
        string? deviceInfo = null, 
        string? ipOrigem = null, 
        string? userAgent = null,
        string? issuer = null)
    {
        var jwtId = _tokenService.GerarJwtId();
        // Passa o issuer para o TokenService (se não fornecido, usa o padrão do IssuerService)
        var accessToken = await _tokenService.GerarAccessToken(usuario, issuer: issuer);
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

    private void AdicionarRetornoTokens(string accessToken, string refreshToken)
    {
        AdicionaRetorno(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = 900, // 15 minutos para access token
            RefreshExpiresIn = 2592000, // 30 dias para refresh token
            //ExpiresIn = 900, // 15 minutos para access token
            //RefreshExpiresIn = 2592000, // 30 dias para refresh token
            TokenType = "Bearer"
        });
    }

    private static bool VerificarSenha(string senha, string senhaCrypto)
    {
        if (string.IsNullOrWhiteSpace(senha) || string.IsNullOrWhiteSpace(senhaCrypto))
            return false;

        return BCrypt.Net.BCrypt.Verify(senha, senhaCrypto);
    }

    private static string CriptografarSenha(string senha)
    {
        return BCrypt.Net.BCrypt.HashPassword(senha);
    }
}
