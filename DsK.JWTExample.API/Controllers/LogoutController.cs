using DsK.JWTExample.API.Services;
using DsK.JWTExample.Shared;
using Microsoft.AspNetCore.Mvc;

namespace DsK.JWTExample.API.Controllers;

[Route("[controller]")]
[ApiController]
public class LogoutController : ControllerBase
{
    private readonly SecurityService _securityService;

    public LogoutController(SecurityService securityService)
    {
        _securityService = securityService;
    }

    [HttpPost]
    public string Post(TokenModel tokenModel)
    {
        return _securityService.Logout(tokenModel);
    }
}
