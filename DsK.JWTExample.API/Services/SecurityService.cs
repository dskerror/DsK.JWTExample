using DsK.JWTExample.Shared;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace DsK.JWTExample.API.Services;
public class SecurityService
{
    private readonly TokenSettingsModel _tokenSettings;
    private readonly RefreshTokens _refreshTokens;

    public SecurityService(IOptions<TokenSettingsModel> tokenSettings, RefreshTokens refreshTokens)
    {
        _tokenSettings = tokenSettings.Value;
        _refreshTokens = refreshTokens;
    }
    public TokenModel Login(LoginRequest loginRequest)
    {
        if (IsUserAuthenticated(loginRequest))
        {
            return GenerateToken(loginRequest.Username);
        }
        return null;
    }
    public string Logout(TokenModel tokenModel)
    {
        _refreshTokens.RefreshTokenList.Remove(tokenModel.RefreshToken);
        return "You have been logged out";
    }
    public TokenModel ValidateRefreshToken(TokenModel tokenModel)
    {
        if (_refreshTokens.RefreshTokenList.Contains(tokenModel.RefreshToken))
        {
            var claimsPrincipal = ValidateToken(tokenModel.Token);
            if (claimsPrincipal != null)
            {
                var username = GetUsernameFromClaimsPrincipal(claimsPrincipal);
                if (username != null)
                {
                    Logout(tokenModel); //Delete _refreshToken
                    return GenerateToken(username);
                }
            }
        }

        return null;
    }
    private bool IsUserAuthenticated(LoginRequest loginRequest)
    {
        if (loginRequest.Username == "admin" && loginRequest.Password == "admin123")
            return true;

        return false;
    }
    private TokenModel GenerateToken(string username)
    {
        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenSettings.Key));
        var credentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
        var userClaims = new List<Claim>();
        userClaims.Add(new Claim("Username", username ?? ""));            
        userClaims.Add(new Claim(ClaimTypes.Role, "WeatherForecast"));
        userClaims.Add(new Claim(ClaimTypes.Role, "Counter"));
        userClaims.Add(new Claim(ClaimTypes.Role, "Counter.Increment"));

        var newJwtToken = new JwtSecurityToken(
                issuer: _tokenSettings.Issuer,
                audience: _tokenSettings.Audience,
                expires: DateTime.UtcNow.AddSeconds(30),
                signingCredentials: credentials,
                claims: userClaims
        );

        string token = new JwtSecurityTokenHandler().WriteToken(newJwtToken);
        string refreshToken = GenerateRefreshToken();
        _refreshTokens.RefreshTokenList.Add(refreshToken);
        return new TokenModel(token, refreshToken);
    }
    private string GenerateRefreshToken()
    {
        var key = new Byte[32];
        using (var refreshTokenGenerator = RandomNumberGenerator.Create())
        {
            refreshTokenGenerator.GetBytes(key);
            return Convert.ToBase64String(key);
        }
    }
    private ClaimsPrincipal ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var claimsPrincipal = tokenHandler.ValidateToken(token,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _tokenSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _tokenSettings.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_tokenSettings.Key)),
                ValidateLifetime = false
            }, out SecurityToken validatedToken);


            var jwtToken = validatedToken as JwtSecurityToken;

            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
                return null;

            return claimsPrincipal;
        }
        catch (Exception)
        {
            return null;
        }
    }
    private string GetUsernameFromClaimsPrincipal(ClaimsPrincipal claimsPrincipal)
    {
        if (claimsPrincipal == null)
            return null;

        var username = claimsPrincipal.Claims.Where(_ => _.Type == "Username").Select(_ => _.Value).FirstOrDefault();            
        if (string.IsNullOrEmpty(username))
            return null;

        return username;
    }
}