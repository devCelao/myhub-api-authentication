using IntegrationHandlers.Events.EmailsWorker;
using MessageBus.Interfaces;

namespace AuthenticationApplication.Services;

/// <summary>
/// Interface para serviço de envio de emails
/// </summary>
public interface IEmailService
{
    Task<bool> EnviarEmailResetSenha(string destinatario, string codigo, string? nomeUsuario = null);
    Task<bool> EnviarEmailConformacaoAlteracao(string destinatario);
    Task<bool> EnviarEmailAlertaSeguranca(string destinatario);
}

/// <summary>
/// Implementação exemplo do serviço de email
/// TODO: Implementar com provedor real (SendGrid, AWS SES, SMTP, etc)
/// </summary>
public class EmailService(IBusMessage bus) : IEmailService
{
    private readonly IBusMessage _bus = bus;

    public async Task<bool> EnviarEmailResetSenha(string destinatario, string codigo, string? nomeUsuario = null)
    {
        var request = new EmailRecuperacaoSenhaEvent(assunto: "Código de Verificação - Redefinição de Senha"
                                                    , isHtml: true)
        {
            Email = destinatario,
            Nome = nomeUsuario ?? "Usuário",
            TokenRecuperacao = codigo,
            ExpiracaoToken = DateTime.UtcNow.AddMinutes(30),
        };

        return await _bus.PublishAsync(message: request, topic: request.Topic);
    }

    public async Task<bool> EnviarEmailConformacaoAlteracao(string destinatario)
    {
        var request = new EmailConfirmacaoAlteracaoSenhaEvent(assunto: "Alteração de senha", isHtml: true)
        {
            Email = destinatario
        };

        return await _bus.PublishAsync(message: request, topic: request.Topic);
    }

    public async Task<bool> EnviarEmailAlertaSeguranca(string destinatario)
    {
        var request = new EmailAlertaSegurancaEvent(assunto: "Alerta de Segurança", isHtml: true)
        {
            Email = destinatario
        };

        return await _bus.PublishAsync(message: request, topic: request.Topic);
    }
}

