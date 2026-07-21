namespace AuthService.Application.Services;

public interface IJwtTokenService
{
    string GenerateToken(string userId, string email, string fullName, IEnumerable<string> roles);
}