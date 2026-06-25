using AuthService.Infrastructure.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace AuthService.Tests;

public class JwtTokenServiceTests
{
    private readonly JwtTokenService _sut;
    private readonly JwtSecurityTokenHandler _handler = new();
    private const string UserId = "123";
    private const string Email = "teste@email.com";

    public JwtTokenServiceTests()
    {
        var settings = new Dictionary<string, string?>
        {
            { "Jwt:Key", "ThisIsASecretKeyWithMoreThan32Characters!" },
            { "Jwt:Issuer", "AuthPlatform" },
            { "Jwt:Audience", "AuthPlatformUsers" }
        };

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        _sut = new JwtTokenService(configuration);
    }

    [Fact]
    public void GenerateToken_ShouldReturnValidToken()
    {
        // Arrange
        var userId = UserId;
        var email = Email;

        // Act
        var token = _sut.GenerateToken(userId, email, "Armando Bandeira");

        // Assert
        token.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void GenerateToken_ShouldContainExpectedClaims()
    {
        // Arrange
        var userId = UserId;
        var email = Email;

        // Act
        var token = _sut.GenerateToken(userId, email, "Armando Bandeira");
        var jwt = _handler.ReadJwtToken(token);

        // Assert
        jwt.Claims.Should().Contain(c =>
            c.Type == JwtRegisteredClaimNames.Sub &&
            c.Value == UserId);

        jwt.Claims.Should().Contain(c =>
            c.Type == JwtRegisteredClaimNames.Email &&
            c.Value == Email);

        jwt.Claims.Should().Contain(c =>
            c.Type == JwtRegisteredClaimNames.Name &&
            c.Value == "Armando Bandeira");

        jwt.Issuer.Should().Be("AuthPlatform");

        jwt.Audiences.Should().Contain("AuthPlatformUsers");
    }
}