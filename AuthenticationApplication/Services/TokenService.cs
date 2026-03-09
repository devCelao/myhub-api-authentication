using AuthenticationDomain.Entities;
using IntegrationHandlers.Responses;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecurityCore.Models;
using SecurityCore.Services;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthenticationApplication.Services;
public interface ITokenService
{
    // Geração de Tokens JWT
    string GerarJwtId();
    Task<string> GerarAccessToken(AcessoUsuario usuario, Guid? idUsuarioWorkspace = null, string? issuer = null);
    string GerarRefreshToken();

    // Hash de Tokens
    string GerarHashToken(string token);
}
public class TokenService(IOptions<JwtOptions> jwtOptions, IJwksService jwksService, IIssuerService issuerService) : ITokenService
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;
    private readonly IJwksService _jwksService = jwksService;
    private readonly IIssuerService _issuerService = issuerService;
    private readonly JwtSecurityTokenHandler _tokenHandler = new ();
    private readonly int expiration = 15; // minutos

    // ========== Geração de Tokens ==========
    public string GerarJwtId() => Guid.NewGuid().ToString();
    
    /// <summary>
    /// Gera um Access Token JWT para o usuário
    /// </summary>
    /// <param name="usuario">Usuário para quem gerar o token</param>
    /// <param name="idUsuarioWorkspace">ID do workspace ativo (opcional)</param>
    /// <param name="issuer">Issuer a ser usado no token. Se não fornecido, usa o IssuerService</param>
    public async Task<string> GerarAccessToken(AcessoUsuario usuario, Guid? idUsuarioWorkspace = null, string? issuer = null)
    {
        // TODO: Implementar a geração do Access Token JWT com base nos dados do usuário
        // 1. Buscar dados do Usuario via busMessage : ID, Email, Workspaces, IdWorkspaceAtivo, Permissões    
        //var request = new ObterUsuarioGeracaoTokenRequest
        //{
        //    IdUsuario = usuario.IdUsuario,
        //    IdWorkspace = idUsuarioWorkspace
        //};

        //var response = await _bus.RequestAsync<ObterUsuarioGeracaoTokenRequest, ObterUsuarioGeracaoTokenResponse>(request) 
        //    ?? throw new Exception("Não foi possível obter os dados do usuário para geração do token.");

        var response = new ObterUsuarioGeracaoTokenResponse
        {
            IdUsuarioWorkspace = usuario.IdUsuario,
            Email = usuario.Email,
            NomeUsuario = "Marcelo",
            // Substitui expressão inválida por uma inicialização válida de coleção
            Workspaces = [Guid.NewGuid()],
            // Permissões como array vazio
            Permissoes = ["Administrador","Desenvolvedor"]
        };

        // 2. Construir payload do JWT com claims padrão e customizadas
        
        var payloadClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, usuario.IdUsuario.ToString()),
            new(JwtRegisteredClaimNames.Email, response.Email),
            new(JwtRegisteredClaimNames.Jti, GerarJwtId()),
            new(JwtRegisteredClaimNames.Nbf, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            new("pwd_version", usuario.VersaoSenha.ToString()),
            new("workspaces", string.Join(",", response.Workspaces)),
            new("idUsuarioWorkspace", response.IdUsuarioWorkspace.ToString()),
            new("NomeUsuario", response.NomeUsuario)
        };

        // Adiciona permissões como claims
        if (response.Permissoes is not null)
        {
            foreach (var permissao in response.Permissoes)
            {
                payloadClaims.Add(new Claim("permissao", permissao));
            }
        }

        // 3. AQUI É A MÁGICA DO JWKS! Obtém as credenciais de assinatura atuais
        var signingCredentials = _jwksService.GetCurrent();

        // 4. Obtém o Issuer: usa o passado por parâmetro ou obtém dinamicamente
        var tokenIssuer = issuer ?? _issuerService.GetCurrentIssuer();
        Console.WriteLine($"🏷️ [TokenService] Gerando token com issuer: {tokenIssuer}");

        // 5. Cria o token JWT
        var identityClaims = new ClaimsIdentity(payloadClaims);

        var token = _tokenHandler.CreateJwtSecurityToken(
           issuer: tokenIssuer, // ← Issuer dinâmico ou passado por parâmetro
           audience: _jwtOptions.Audience, // ← Audience fixo (ex: facimed.com)
           subject: identityClaims,
           notBefore: DateTime.UtcNow,
           expires: DateTime.UtcNow.AddMinutes(expiration),
           signingCredentials: signingCredentials
       );

        // 6. Retorna o token serializado
        return _tokenHandler.WriteToken(token);
    }
    public string GerarRefreshToken()
    {
        // Gera token opaco (não JWT) de 64 bytes
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);

        return Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    // ========== Hash de Tokens ==========

    /// <summary>
    /// Gera hash SHA256 de um token (usado para Refresh Tokens)
    /// </summary>
    public string GerarHashToken(string token)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }
}
