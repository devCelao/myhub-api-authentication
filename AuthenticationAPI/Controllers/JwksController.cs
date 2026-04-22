using MicroserviceCore.Controller;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityCore.Services;

namespace AuthenticationAPI.Controllers;

[AllowAnonymous]
[Route(".well-known")]
public class JwksController(IJwksService jwksService) : BaseController
{
    private readonly IJwksService _jwksService = jwksService;

    [HttpGet("jwks.json")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public IActionResult GetJwks()
    {
        try
        {
            var keys = _jwksService.GetPublicKeys(5);
            var jwks = new { keys };
            return Ok(jwks);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = "Erro ao obter chaves JWKS", message = ex.Message });
        }
    }
}
