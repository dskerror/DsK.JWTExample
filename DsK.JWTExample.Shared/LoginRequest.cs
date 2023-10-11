using System.ComponentModel.DataAnnotations;
namespace DsK.JWTExample.Shared;
public class LoginRequest
{
    [Required]
    [StringLength(256, MinimumLength = 5)]
    public string? Username { get; set; }
    [Required]
    public string? Password { get; set; }
}
