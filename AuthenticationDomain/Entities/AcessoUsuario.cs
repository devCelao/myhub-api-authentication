using DomainObjects.Enums;

namespace AuthenticationDomain.Entities;

public class AcessoUsuario
{
    private const int MaxTentativasFalhas = 5;
    private const int MinutosBloqueioTemporario = 30;

    public AcessoUsuario() { } // EF

    // Identificação
    public Guid IdUsuario { get; set; }
    public string Email { get; set; } = default!;
    public string SenhaCrypto { get; set; } = default!;

    // Status da Conta
    public bool IndAtivo { get; set; }
    public bool IndTrocaSenha { get; set; }
    public DateTime DataCadastro { get; set; }
    public bool IndDoisFatoresAtivo { get; set; }

    // Controle de Tentativas e Bloqueio
    public int QtdTentativasFalhas { get; set; }
    public TipoBloqueio TipoBloqueio { get; set; }
    public DateTime? DataBloqueio { get; set; }
    public DateTimeOffset? DataFimBloqueio { get; set; }
    public string? MotivoBloqueio { get; set; }
    public Guid? IdUsuarioBloqueio { get; set; }

    // Auditoria Básica
    public DateTime? DataUltimoAcesso { get; set; }
    public string? IpUltimoAcesso { get; set; }
    public DateTime? DataUltimaTrocaSenha { get; set; }
    public int VersaoSenha { get; set; }

    public AcessoUsuario(string email, string senhaCrypto, Guid idUsuario)
    {
        IdUsuario = idUsuario;
        Email = email;
        SenhaCrypto = senhaCrypto;
        IndAtivo = true;
        IndTrocaSenha = false;
        DataCadastro = DateTime.UtcNow;
        IndDoisFatoresAtivo = false;
        QtdTentativasFalhas = 0;
        TipoBloqueio = TipoBloqueio.Nenhum;
        VersaoSenha = 1;
    }

    public bool PodeFazerLogin()
    {
        if (!IndAtivo)
            return false;

        if (TipoBloqueio == TipoBloqueio.ManualPermanente)
            return false;

        if (TipoBloqueio == TipoBloqueio.SuspeitaFraude)
            return false;

        if (DataFimBloqueio.HasValue && DataFimBloqueio.Value > DateTimeOffset.UtcNow)
            return false;

        // Se o bloqueio temporário expirou, desbloqueia automaticamente
        if (DataFimBloqueio.HasValue && DataFimBloqueio.Value <= DateTimeOffset.UtcNow)
        {
            DesbloquearConta();
        }

        return true;
    }

    public void DesbloquearConta()
    {
        TipoBloqueio = TipoBloqueio.Nenhum;
        DataBloqueio = null;
        DataFimBloqueio = null;
        MotivoBloqueio = null;
        QtdTentativasFalhas = 0;
    }

    public void RegistrarTentativaFalha(string? ipOrigem = null)
    {
        QtdTentativasFalhas++;

        if (QtdTentativasFalhas >= MaxTentativasFalhas)
        {
            TipoBloqueio = TipoBloqueio.TemporarioTentativas;
            DataBloqueio = DateTime.UtcNow;
            DataFimBloqueio = DateTimeOffset.UtcNow.AddMinutes(MinutosBloqueioTemporario);
            MotivoBloqueio = $"Bloqueio automático por {MaxTentativasFalhas} tentativas falhas de login";
        }

        if (!string.IsNullOrEmpty(ipOrigem))
        {
            IpUltimoAcesso = ipOrigem;
        }
    }

    public void RegistrarLoginSucesso(string? ipOrigem = null)
    {
        QtdTentativasFalhas = 0;
        DataUltimoAcesso = DateTime.UtcNow;

        if (!string.IsNullOrEmpty(ipOrigem))
        {
            IpUltimoAcesso = ipOrigem;
        }

        // Se estava bloqueado temporariamente, desbloqueia
        if (TipoBloqueio == TipoBloqueio.TemporarioTentativas)
        {
            DesbloquearConta();
        }
    }
}
