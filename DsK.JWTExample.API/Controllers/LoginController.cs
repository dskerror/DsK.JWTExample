using DsK.JWTExample.API.Services;
using DsK.JWTExample.Shared;
using Microsoft.AspNetCore.Mvc;

namespace DsK.JWTExample.API.Controllers;

[Route("[controller]")]
[ApiController]
public class LoginController : ControllerBase
{
    private readonly SecurityService _securityService;

    public LoginController(SecurityService securityService)
    {
        _securityService = securityService;
    }

    [HttpPost]
    public TokenModel Post(LoginRequest loginRequest)
    {
        return _securityService.Login(loginRequest);
    }
}
