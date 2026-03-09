using AuthenticationApplication.Services;
using MicroserviceCore.Controller;
using MicroserviceCore.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace AuthenticationAPI.Controllers;
[Route("Autenticacao")]
public class AuthenticacaoController(IAuthenticationService authService) : RootController
{
    private readonly IAuthenticationService _authService = authService;
    // ========== Criação de Acesso ==========

    /// <summary>
    /// Cria o acesso (senha) para um usuário após confirmação de email
    /// </summary>
    [HttpPost("criar-acesso")]
    public async Task<IActionResult> CriarAcesso([FromBody] CriarAcessoRequest request)
    {
        var resultado = await _authService.CriarAcessoUsuario(request.IdUsuario, request.Email, request.Senha);

        return CustomResponde(resultado);
    }
    // ========== Autenticação ==========

    /// <summary>
    /// Realiza o login do usuário
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ipOrigem = ObterIpRequisicao;
        var userAgent = Request.Headers.UserAgent.ToString();
        var deviceInfo = ObterDeviceInfo();

        var resultado = await _authService.RealizarLogin(
            request.Email,
            request.Password,
            ipOrigem,
            deviceInfo,
            userAgent
        );

        if (!resultado.PossuiErros) SetCookies(resultado.ResultObject);

        return CustomResponde(resultado);
    }
    /// <summary>
    /// Renova o access token usando refresh token
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var resultado = await _authService.RenovarAccessToken(request.RefreshToken);

        if (!resultado.PossuiErros) SetCookies(resultado.ResultObject);

        return CustomResponde(resultado);
    }

    private void SetCookies(object? ResultObject)
    {
        var tokens = JsonSerializer.Deserialize<TokenResponse>(
                JsonSerializer.Serialize(ResultObject));
        
        if (tokens is not null)
        {
            AuthCookieManager.SetTokenCookies(
                Response, 
                tokens.AccessToken, 
                tokens.RefreshToken
            );
        }
    }

    /// <summary>
    /// Desbloqueia conta
    /// </summary>
    [HttpGet("desbloquear-conta/{email}")]
    public async Task<IActionResult> DesbloquearConta(string email)
    {
        var resultado = await _authService.DesbloquearContaAdmin(email);
        return CustomResponde(resultado);
    }

    /// <summary>
    /// Envio de email para reset de senha
    /// </summary>
    [HttpPost("forgot-password/{email}")]
    public async Task<IActionResult> ForgotPassword(string email)
    {
        var ipOrigem = ObterIpRequisicao;
        var userAgent = Request.Headers.UserAgent.ToString();

        var resultado = await _authService.IniciarResetSenha(email, ipOrigem, userAgent);

        return CustomResponde(resultado);
    }

    /// <summary>
    /// Valida código de verificação para reset de senha
    /// </summary>
    [HttpPost("validate-reset-code")]
    public async Task<IActionResult> ValidateResetCode([FromBody] ValidateCodeRequest request)
    {
        var resultado = await _authService.ValidarCodigoResetSenha(request.Codigo, request.Email);

        return CustomResponde(resultado);
    }

    /// <summary>
    /// Reset de senha com código de verificação
    /// </summary>
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPassword reset)
    {
        var ipOrigem = ObterIpRequisicao;

        var resultado = await _authService.FinalizarResetSenha(
            reset.Codigo, 
            reset.Email, 
            reset.NewPassword, 
            ipOrigem
        );

        return CustomResponde(resultado);
    }

    // ========== Métodos Auxiliares ==========
    private string ObterIpRequisicao
        => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private string ObterDeviceInfo()
    {
        var userAgent = Request.Headers.UserAgent.ToString();
        // TODO: Implementar parsing de user agent para extrair device info
        return JsonSerializer.Serialize(new
        {
            UserAgent = userAgent,
            Platform = "Web" // Pode ser extraído do user agent
        });
    }
}
// ========== DTOs ==========

public record CriarAcessoRequest(Guid IdUsuario, string Email, string Senha);
public record LoginRequest(string Email, string Password);
public record RefreshTokenRequest(string RefreshToken);
public record ValidateCodeRequest(string Codigo, string Email);
public record ResetPassword(string Codigo, string Email, string NewPassword);
public record TokenResponse(string AccessToken, string RefreshToken, int ExpiresIn, int RefreshExpiresIn, string TokenType);
