using AuthService.Infrastructure.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace AuthService.Tests;

public class JwtTokenServiceTests
{
    [Fact]
    public void GenerateToken_ShouldReturnValidToken()
    {
        // Arrange
        var settings = new Dictionary<string, string?>
        {
            { "Jwt:Key", "ThisIsASecretKeyWithMoreThan32Characters!" },
            { "Jwt:Issuer", "AuthPlatform" },
            { "Jwt:Audience", "AuthPlatformUsers" }
        };

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var sut = new JwtTokenService(configuration);

        // Act
        var token = sut.GenerateToken(
            "123",
            "teste@email.com");

        // Assert
        token.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void GenerateToken_ShouldContainExpectedClaims()
    {
        // Arrange
        var settings = new Dictionary<string, string?>
        {
            { "Jwt:Key", "ThisIsASecretKeyWithMoreThan32Characters!" },
            { "Jwt:Issuer", "AuthPlatform" },
            { "Jwt:Audience", "AuthPlatformUsers" }
        };

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var sut = new JwtTokenService(configuration);

        var userId = "123";
        var email = "teste@email.com";

        // Act
        var token = sut.GenerateToken(userId, email);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // Assert
        jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub)
            .Value.Should().Be(userId);

        jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email)
            .Value.Should().Be(email);

        jwt.Issuer.Should().Be("AuthPlatform");

        jwt.Audiences.Should().Contain("AuthPlatformUsers");
    }
}