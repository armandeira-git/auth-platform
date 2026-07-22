namespace AuthService.Application.DTOs;

public class UserDto
{
    public required string Id { get; init; }

    public required string FullName { get; init; }

    public required string Email { get; init; }

    public required IList<string> Roles { get; init; }
}