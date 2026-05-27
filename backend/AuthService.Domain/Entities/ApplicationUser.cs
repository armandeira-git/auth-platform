using Microsoft.AspNetCore.Identity;

namespace AuthService.Domain.Entities;

public class ApplicationUser : IdentityUser
{
    public string FullName { get; set; } = string.Empty;
}