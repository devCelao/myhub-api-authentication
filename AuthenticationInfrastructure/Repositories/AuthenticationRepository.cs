using AuthenticationDomain.Entities;
using AuthenticationInfrastructure.Context;
using DomainObjects.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationInfrastructure.Repositories;
public interface IAuthenticationRepository
{
    IUnitOfWork UnitOfWork { get; }

    // AcessoUsuario
    void AdicionaUsuario(AcessoUsuario usuario);
    Task<AcessoUsuario?> ObterUsuarioPorEmail(string email);
    Task<AcessoUsuario?> ObterUsuarioPorId(Guid idUsuario);
    void AtualizarUsuario(AcessoUsuario usuario);

    // RefreshToken
    Task<RefreshToken?> ObterRefreshTokenPorHash(string tokenHash);
    void AdicionarRefreshToken(RefreshToken token);
    void AtualizarRefreshToken(RefreshToken token);
    Task RevogarRefreshTokensUsuario(Guid idUsuario, string motivo);

    // TokenRedefinicaoSenha
    void AdicionarTokenRedefinicaoSenha(TokenRedefinicaoSenha token);
    Task<TokenRedefinicaoSenha?> ObterTokenRedefinicaoSenhaPorHash(string tokenHash);
    void AtualizarTokenRedefinicaoSenha(TokenRedefinicaoSenha token);
    Task InativarTokensRedefinicaoSenhaUsuario(Guid idUsuario, string motivo);
    Task<int> ContarTokensRedefinicaoSenhaRecentes(Guid idUsuario, int minutos);
}
public class AuthenticationRepository(AcessoContext context) : IAuthenticationRepository
{
    private readonly AcessoContext context = context;
    public IUnitOfWork UnitOfWork => context;

    #region AcessoUsuario
    public void AdicionaUsuario(AcessoUsuario usuario) => context.Usuarios.Add(usuario);
    public async Task<AcessoUsuario?> ObterUsuarioPorEmail(string email)
        => await context.Usuarios.FirstOrDefaultAsync(u => u.Email == email);

    public async Task<AcessoUsuario?> ObterUsuarioPorId(Guid idUsuario)
        => await context.Usuarios.FirstOrDefaultAsync(u => u.IdUsuario == idUsuario);

    public void AtualizarUsuario(AcessoUsuario usuario)
        => context.Usuarios.Update(usuario);
    #endregion

    #region RefreshToken

    public async Task<RefreshToken?> ObterRefreshTokenPorHash(string tokenHash)
        => await context.RefreshToken
            .Include(r => r.Usuario)
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash);

    public void AdicionarRefreshToken(RefreshToken token)
        => context.RefreshToken.Add(token);

    public void AtualizarRefreshToken(RefreshToken token)
        =>  context.RefreshToken.Update(token);
    public async Task RevogarRefreshTokensUsuario(Guid idUsuario, string motivo)
    {
        var tokens = await context.RefreshToken
            .Where(r => r.IdUsuario == idUsuario && !r.IndRevogado)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Revogar(motivo);
            context.RefreshToken.Update(token);
        }

        await UnitOfWork.Commit();
    }
    #endregion

    #region TokenRedefinicaoSenha

    public void AdicionarTokenRedefinicaoSenha(TokenRedefinicaoSenha token)
        => context.TokensRedefinicaoSenha.Add(token);

    public async Task<TokenRedefinicaoSenha?> ObterTokenRedefinicaoSenhaPorHash(string codigoHash)
        => await context.TokensRedefinicaoSenha
            .Include(t => t.Usuario)
            .FirstOrDefaultAsync(t => t.CodigoHash == codigoHash);

    public void AtualizarTokenRedefinicaoSenha(TokenRedefinicaoSenha token)
        => context.TokensRedefinicaoSenha.Update(token);

    public async Task InativarTokensRedefinicaoSenhaUsuario(Guid idUsuario, string motivo)
    {
        var tokens = await context.TokensRedefinicaoSenha
            .Where(t => t.IdUsuario == idUsuario && t.IndAtivo && !t.IndUtilizado)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.Inativar(motivo);
            context.TokensRedefinicaoSenha.Update(token);
        }

        await UnitOfWork.Commit();
    }

    public async Task<int> ContarTokensRedefinicaoSenhaRecentes(Guid idUsuario, int minutos)
    {
        var dataLimite = DateTime.UtcNow.AddMinutes(-minutos);
        return await context.TokensRedefinicaoSenha
            .Where(t => t.IdUsuario == idUsuario && t.DataCriacao >= dataLimite)
            .CountAsync();
    }

    #endregion
}
