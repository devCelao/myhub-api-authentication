using AuthenticationDomain.Dtos;
using AuthenticationDomain.Validators;
using FluentAssertions;

namespace AuthenticationTest.Domain;

public class ValidatorTests
{
    [Fact]
    public void LoginRequest_EmailVazio_DeveFalhar()
    {
        var validator = new LoginRequestValidator();
        var request = new LoginRequest { Email = "", Password = "senha123" };

        var result = validator.Validate(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Email");
    }

    [Fact]
    public void LoginRequest_EmailInvalido_DeveFalhar()
    {
        var validator = new LoginRequestValidator();
        var request = new LoginRequest { Email = "nao-e-email", Password = "senha123" };

        var result = validator.Validate(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Email");
    }

    [Fact]
    public void LoginRequest_Valido_DevePassar()
    {
        var validator = new LoginRequestValidator();
        var request = new LoginRequest { Email = "user@test.com", Password = "senha123" };

        var result = validator.Validate(request);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void CriarAcessoRequest_SenhaCurta_DeveFalhar()
    {
        var validator = new CriarAcessoRequestValidator();
        var request = new CriarAcessoRequest
        {
            IdUsuario = Guid.NewGuid(),
            Email = "user@test.com",
            Senha = "123"
        };

        var result = validator.Validate(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Senha");
    }

    [Fact]
    public void CriarAcessoRequest_Valido_DevePassar()
    {
        var validator = new CriarAcessoRequestValidator();
        var request = new CriarAcessoRequest
        {
            IdUsuario = Guid.NewGuid(),
            Email = "user@test.com",
            Senha = "senhaSegura123"
        };

        var result = validator.Validate(request);

        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void ResetPasswordRequest_CodigoInvalido_DeveFalhar()
    {
        var validator = new ResetPasswordRequestValidator();
        var request = new ResetPasswordRequest
        {
            Codigo = "ABC",
            Email = "user@test.com",
            NewPassword = "novaSenha123"
        };

        var result = validator.Validate(request);

        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName == "Codigo");
    }

    [Fact]
    public void ValidateCodeRequest_Valido_DevePassar()
    {
        var validator = new ValidateCodeRequestValidator();
        var request = new ValidateCodeRequest
        {
            Codigo = "123456",
            Email = "user@test.com"
        };

        var result = validator.Validate(request);

        result.IsValid.Should().BeTrue();
    }
}
