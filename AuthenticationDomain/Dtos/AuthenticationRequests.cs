using System.ComponentModel.DataAnnotations;

namespace AuthenticationDomain.Dtos;

public class CriarAcessoRequest
{
    [Required(ErrorMessage = "Id do usuario e obrigatorio.")]
    public Guid IdUsuario { get; set; }

    [Required(ErrorMessage = "Email e obrigatorio.")]
    [EmailAddress(ErrorMessage = "Email invalido.")]
    public string Email { get; set; } = default!;

    [Required(ErrorMessage = "Senha e obrigatoria.")]
    [MinLength(8, ErrorMessage = "Senha deve ter no minimo 8 caracteres.")]
    public string Senha { get; set; } = default!;
}

public class LoginRequest
{
    [Required(ErrorMessage = "Email e obrigatorio.")]
    [EmailAddress(ErrorMessage = "Email invalido.")]
    public string Email { get; set; } = default!;

    [Required(ErrorMessage = "Senha e obrigatoria.")]
    public string Password { get; set; } = default!;
}

public class RefreshTokenRequest
{
    [Required(ErrorMessage = "Refresh token e obrigatorio.")]
    public string RefreshToken { get; set; } = default!;
}

public class ValidateCodeRequest
{
    [Required(ErrorMessage = "Codigo e obrigatorio.")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Codigo deve conter 6 digitos.")]
    public string Codigo { get; set; } = default!;

    [Required(ErrorMessage = "Email e obrigatorio.")]
    [EmailAddress(ErrorMessage = "Email invalido.")]
    public string Email { get; set; } = default!;
}

public class ResetPasswordRequest
{
    [Required(ErrorMessage = "Codigo e obrigatorio.")]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "Codigo deve conter 6 digitos.")]
    public string Codigo { get; set; } = default!;

    [Required(ErrorMessage = "Email e obrigatorio.")]
    [EmailAddress(ErrorMessage = "Email invalido.")]
    public string Email { get; set; } = default!;

    [Required(ErrorMessage = "Nova senha e obrigatoria.")]
    [MinLength(8, ErrorMessage = "Senha deve ter no minimo 8 caracteres.")]
    public string NewPassword { get; set; } = default!;
}
