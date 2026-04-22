using AuthenticationApplication.Services;
using AuthenticationDomain.Dtos;
using MicroserviceCore.Controller;
using MicroserviceCore.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace AuthenticationAPI.Controllers;

[Route("api/authentication")]
public class AuthenticacaoController(IAuthenticationService authService) : BaseController
{
    private readonly IAuthenticationService _authService = authService;

    [AllowAnonymous]
    [HttpPost("criar-acesso")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CriarAcesso([FromBody] CriarAcessoRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var result = await _authService.CriarAcessoUsuario(request.IdUsuario, request.Email, request.Senha);
        return ToActionResult(result);
    }

    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var ipOrigem = ObterIpRequisicao;
        var userAgent = Request.Headers.UserAgent.ToString();
        var deviceInfo = ObterDeviceInfo();

        var result = await _authService.RealizarLogin(
            request.Email,
            request.Password,
            ipOrigem,
            deviceInfo,
            userAgent
        );

        if (result.IsSuccess && result.Data is not null)
            SetCookies(result.Data);

        return ToActionResult(result);
    }

    [Authorize]
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var result = await _authService.RenovarAccessToken(request.RefreshToken);

        if (result.IsSuccess && result.Data is not null)
            SetCookies(result.Data);

        return ToActionResult(result);
    }

    [Authorize]
    [HttpGet("desbloquear-conta/{email}")]
    [ProducesResponseType(typeof(DesbloqueioResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DesbloquearConta(string email)
    {
        var result = await _authService.DesbloquearContaAdmin(email);
        return ToActionResult(result);
    }

    [AllowAnonymous]
    [HttpPost("forgot-password/{email}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ForgotPassword(string email)
    {
        var ipOrigem = ObterIpRequisicao;
        var userAgent = Request.Headers.UserAgent.ToString();

        var result = await _authService.IniciarResetSenha(email, ipOrigem, userAgent);
        return ToActionResult(result);
    }

    [AllowAnonymous]
    [HttpPost("validate-reset-code")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ValidateResetCode([FromBody] ValidateCodeRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var result = await _authService.ValidarCodigoResetSenha(request.Codigo, request.Email);
        return ToActionResult(result);
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var ipOrigem = ObterIpRequisicao;

        var result = await _authService.FinalizarResetSenha(
            request.Codigo,
            request.Email,
            request.NewPassword,
            ipOrigem
        );

        return ToActionResult(result);
    }

    [AllowAnonymous]
    [HttpPost("root-login")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult RootLogin([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid) return ValidationError();

        var result = _authService.RealizarLoginRoot(request.Email, request.Password);

        if (result.IsSuccess && result.Data is not null)
            SetCookies(result.Data);

        return ToActionResult(result);
    }

    private void SetCookies(TokenResponse tokens)
    {
        AuthCookieManager.SetTokenCookies(
            Response,
            tokens.AccessToken,
            tokens.RefreshToken
        );
    }

    private string ObterIpRequisicao
        => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private string ObterDeviceInfo()
    {
        var userAgent = Request.Headers.UserAgent.ToString();
        return JsonSerializer.Serialize(new
        {
            UserAgent = userAgent,
            Platform = "Web"
        });
    }
}
