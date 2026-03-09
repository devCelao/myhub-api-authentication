using System.Security.Cryptography;
using System.Text;

namespace AuthenticationDomain.Entities;

public class RefreshToken
{
    private const int DiasValidadeRefreshToken = 30;
    public RefreshToken() { } // EF
    // Identificação
    public Guid IdRefreshToken { get; set; }
    public Guid IdUsuario { get; set; }

    // Token
    public string Token { get; set; } = default!;
    public string TokenHash { get; set; } = default!;
    public string JwtId { get; set; } = default!;

    // Validade
    public DateTime DataCriacao { get; set; }
    public DateTime DataExpiracao { get; set; }

    // Revogação
    public bool IndRevogado { get; set; }
    public DateTime? DataRevogacao { get; set; }
    public string? MotivoRevogacao { get; set; }

    // Rotação de Tokens
    public Guid? IdRefreshTokenSubstituido { get; set; }
    public bool IndUtilizado { get; set; }
    public DateTime? DataUtilizacao { get; set; }

    // Rastreamento
    public string? DeviceInfo { get; set; }
    public string? IpOrigem { get; set; }
    public string? UserAgent { get; set; }
    public int VersaoSenhaUsuario { get; set; }

    // Relacionamentos
    public virtual AcessoUsuario? Usuario { get; set; }
    public virtual RefreshToken? TokenSubstituido { get; set; }

    public RefreshToken(Guid idUsuario, string token, string jwtId, int versaoSenhaUsuario, string? deviceInfo = null, string? ipOrigem = null, string? userAgent = null)
    {
        IdRefreshToken = Guid.NewGuid();
        IdUsuario = idUsuario;
        Token = token;
        TokenHash = GerarHash(token);
        JwtId = jwtId;
        DataCriacao = DateTime.UtcNow;
        DataExpiracao = DateTime.UtcNow.AddDays(DiasValidadeRefreshToken);
        IndRevogado = false;
        IndUtilizado = false;
        VersaoSenhaUsuario = versaoSenhaUsuario;
        DeviceInfo = deviceInfo;
        IpOrigem = ipOrigem;
        UserAgent = userAgent;
    }
    public bool EstaValido()
    {
        if (IndRevogado)
            return false;

        if (IndUtilizado)
            return false;

        if (DataExpiracao < DateTime.UtcNow)
            return false;

        return true;
    }

    public void Revogar(string motivo)
    {
        IndRevogado = true;
        DataRevogacao = DateTime.UtcNow;
        MotivoRevogacao = motivo;
    }

    public void MarcarComoUtilizado(Guid? idNovoToken = null)
    {
        IndUtilizado = true;
        DataUtilizacao = DateTime.UtcNow;
        if (idNovoToken.HasValue)
        {
            IdRefreshTokenSubstituido = idNovoToken.Value;
        }
    }

    public bool ValidarIntegridade(string tokenOriginal)
    {
        var hashCalculado = GerarHash(tokenOriginal);
        return hashCalculado == TokenHash;
    }

    public bool VersaoSenhaValida(int versaoSenhaAtual)
    {
        return VersaoSenhaUsuario == versaoSenhaAtual;
    }
    private static string GerarHash(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}
