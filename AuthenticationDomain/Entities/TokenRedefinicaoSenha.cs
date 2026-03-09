using System.Security.Cryptography;
using System.Text;

namespace AuthenticationDomain.Entities;

public class TokenRedefinicaoSenha
{
    private const int MinutosValidadeToken = 30;
    private const int MaxTentativasInvalidas = 5;

    public TokenRedefinicaoSenha() { } // EF

    // Identificação
    public Guid Id { get; set; }
    public Guid IdUsuario { get; set; }
    public string Email { get; set; } = default!;

    // Código de Verificação
    public string CodigoHash { get; set; } = default!;

    // Controle de Validade
    public DateTime DataCriacao { get; set; }
    public DateTime DataExpiracao { get; set; }

    // Controle de Uso
    public bool IndUtilizado { get; set; }
    public DateTime? DataUtilizacao { get; set; }

    // Segurança e Auditoria
    public string IpSolicitacao { get; set; } = default!;
    public string? UserAgent { get; set; }
    public string? IpUtilizacao { get; set; }

    // Controle de Tentativas
    public int TentativasInvalidas { get; set; }
    public DateTime? DataUltimaTentativa { get; set; }

    // Soft Delete
    public bool IndAtivo { get; set; }
    public DateTime? DataInativacao { get; set; }
    public string? MotivoInativacao { get; set; }

    // Relacionamento
    public virtual AcessoUsuario? Usuario { get; set; }

    public TokenRedefinicaoSenha(
        Guid idUsuario, 
        string email, 
        string codigo, 
        string ipSolicitacao, 
        string? userAgent = null)
    {
        Id = Guid.NewGuid();
        IdUsuario = idUsuario;
        Email = email;
        CodigoHash = GerarHash(codigo);
        DataCriacao = DateTime.UtcNow;
        DataExpiracao = DateTime.UtcNow.AddMinutes(MinutosValidadeToken);
        IndUtilizado = false;
        IndAtivo = true;
        TentativasInvalidas = 0;
        IpSolicitacao = ipSolicitacao;
        UserAgent = userAgent;
    }

    public bool EstaValido()
    {
        if (!IndAtivo)
            return false;

        if (IndUtilizado)
            return false;

        if (DataExpiracao < DateTime.UtcNow)
            return false;

        if (TentativasInvalidas >= MaxTentativasInvalidas)
            return false;

        return true;
    }

    public bool ValidarCodigo(string codigoOriginal)
    {
        if (!EstaValido())
            return false;

        var hashCalculado = GerarHash(codigoOriginal);
        var codigoValido = hashCalculado == CodigoHash;

        if (!codigoValido)
        {
            RegistrarTentativaInvalida();
        }

        return codigoValido;
    }

    public void MarcarComoUtilizado(string? ipUtilizacao = null)
    {
        IndUtilizado = true;
        DataUtilizacao = DateTime.UtcNow;
        IpUtilizacao = ipUtilizacao;
    }

    public void Inativar(string motivo)
    {
        IndAtivo = false;
        DataInativacao = DateTime.UtcNow;
        MotivoInativacao = motivo;
    }

    private void RegistrarTentativaInvalida()
    {
        TentativasInvalidas++;
        DataUltimaTentativa = DateTime.UtcNow;

        if (TentativasInvalidas >= MaxTentativasInvalidas)
        {
            Inativar($"Máximo de {MaxTentativasInvalidas} tentativas inválidas atingido");
        }
    }

    public bool IpUtilizacaoDiferente()
    {
        if (string.IsNullOrEmpty(IpUtilizacao))
            return false;

        return IpSolicitacao != IpUtilizacao;
    }

    public static string GerarCodigoNumerico()
    {
        // Gera código de 6 dígitos
        var random = new Random();
        return random.Next(100000, 999999).ToString();
    }

    private static string GerarHash(string codigo)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(codigo);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}

