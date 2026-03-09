using MicroserviceCore.Controller;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityCore.Services;

namespace AuthenticationAPI.Controllers;
[AllowAnonymous]
[Route(".well-known")]
public class JwksController(IJwksService jwksService) : RootController
{
    private readonly IJwksService _jwksService = jwksService;
    /// <summary>
    /// Endpoint padrão JWKS conforme RFC 7517
    /// Retorna as chaves públicas para validação de tokens JWT
    /// </summary>
    /// <returns>JSON Web Key Set com chaves públicas</returns>
    [HttpGet("jwks.json")]
    public IActionResult GetJwks()
    {
        try
        {
            // Obtém as 5 chaves mais recentes (permite rotação suave)
            var keys = _jwksService.GetPublicKeys(5);

            // Formato padrão JWKS
            var jwks = new { keys };

            return Ok(jwks);
        }
        catch (Exception ex)
        {
            // Log do erro (adicionar logger se necessário)
            return StatusCode(500, new { error = "Erro ao obter chaves JWKS", message = ex.Message });
        }
    }
}
