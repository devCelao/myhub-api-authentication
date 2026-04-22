namespace AuthenticationDomain.Dtos;

public class DesbloqueioResponse
{
    public Guid IdUsuario { get; set; }
    public string Email { get; set; } = default!;
    public string Status { get; set; } = default!;
}
