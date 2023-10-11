using DsK.JWTExample.API.Services;
using DsK.JWTExample.Shared;
using Microsoft.AspNetCore.Mvc;

namespace DsK.JWTExample.API.Controllers;

[Route("[controller]")]
[ApiController]
public class RefreshTokenController : ControllerBase
{
    private readonly SecurityService _securityService;

    public RefreshTokenController(SecurityService securityService)
    {
        _securityService = securityService;
    }

    [HttpPost]
    public TokenModel Post(TokenModel tokenModel)
    {
        return _securityService.ValidateRefreshToken(tokenModel);
    }
}
