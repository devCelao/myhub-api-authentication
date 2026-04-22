using AuthenticationDomain.Dtos;
using FluentValidation;

namespace AuthenticationDomain.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email e obrigatorio.")
            .EmailAddress().WithMessage("Email invalido.");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Senha e obrigatoria.");
    }
}

public class CriarAcessoRequestValidator : AbstractValidator<CriarAcessoRequest>
{
    public CriarAcessoRequestValidator()
    {
        RuleFor(x => x.IdUsuario)
            .NotEmpty().WithMessage("Id do usuario e obrigatorio.");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email e obrigatorio.")
            .EmailAddress().WithMessage("Email invalido.");

        RuleFor(x => x.Senha)
            .NotEmpty().WithMessage("Senha e obrigatoria.")
            .MinimumLength(8).WithMessage("Senha deve ter no minimo 8 caracteres.");
    }
}

public class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.Codigo)
            .NotEmpty().WithMessage("Codigo e obrigatorio.")
            .Matches(@"^\d{6}$").WithMessage("Codigo deve conter 6 digitos.");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email e obrigatorio.")
            .EmailAddress().WithMessage("Email invalido.");

        RuleFor(x => x.NewPassword)
            .NotEmpty().WithMessage("Nova senha e obrigatoria.")
            .MinimumLength(8).WithMessage("Senha deve ter no minimo 8 caracteres.");
    }
}

public class ValidateCodeRequestValidator : AbstractValidator<ValidateCodeRequest>
{
    public ValidateCodeRequestValidator()
    {
        RuleFor(x => x.Codigo)
            .NotEmpty().WithMessage("Codigo e obrigatorio.")
            .Matches(@"^\d{6}$").WithMessage("Codigo deve conter 6 digitos.");

        RuleFor(x => x.Email)
            .NotEmpty().WithMessage("Email e obrigatorio.")
            .EmailAddress().WithMessage("Email invalido.");
    }
}
