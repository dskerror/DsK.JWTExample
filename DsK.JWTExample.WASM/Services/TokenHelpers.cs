using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Text.Json;

namespace DsK.JWTExample.WASM.Services;
public static class TokenHelpers
{
    public static bool IsTokenExpired(string token)
    {
        List<Claim> claims = ParseClaimsFromJwt(token).ToList();
        if (claims?.Count == 0)
            return true;

        string expirationSeconds = claims.Where(_ => _.Type.ToLower() == "exp").Select(_ => _.Value).FirstOrDefault();
        if (string.IsNullOrEmpty(expirationSeconds))
            return true;

        var expirationDate = DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(expirationSeconds));
        if (expirationDate < DateTime.UtcNow)
            return true;

        return false;
    }

    public static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        var claims = new List<Claim>();

        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(jwt);
        var token = jsonToken as JwtSecurityToken;

        foreach(var claim in token.Claims)
        {
            claims.Add(claim);
        }

        //var payload = jwt.Split('.')[1];

        //var jsonBytes = ParseBase64WithoutPadding(payload);


        //var keyValuePairs = JsonConvert.DeserializeObject<Dictionary<string, object>>(jsonBytes);

        //if (keyValuePairs != null)
        //{
        //    foreach (var keyValuePair in keyValuePairs)
        //    {                
        //        if (keyValuePair.Key == ClaimTypes.Role)
        //        {
        //            var roles = JsonConvert.DeserializeObject<List<string>>(keyValuePair.Value);
        //            foreach (var role in roles)
        //            {
        //                Claim newclaim = new Claim(ClaimTypes.Role, role);
        //                claims.Add(newclaim);
        //            }
        //        }
        //        else
        //        {
        //            Claim newclaim = new Claim(ClaimTypes.Role, keyValuePair.Value.ToString());
        //            claims.Add(newclaim);
        //        }

        //    }
        //var claim = keyValuePairs.Select(kvp => new Claim(kvp.Key, kvp.Value.ToString() ?? ""));            
        //claims.AddRange(claim);
        //}

        return claims;
    }
    //private static byte[] ParseBase64WithoutPadding(string base64)
    //{
    //    switch (base64.Length % 4)
    //    {
    //        case 2: base64 += "=="; break;
    //        case 3: base64 += "="; break;
    //    }
    //    return Convert.FromBase64String(base64);
    //}
}
