namespace AuthenticationDomain.Extensions;

public class AppSettings
{
    public string AutenticacaoJwksUrl { get; set; } = default!;
    public string RootEmail { get; set; } = default!;
    public string RootPassword { get; set; } = default!;
}
