using AuthService.Infrastructure.Services;
using FluentAssertions;
using Microsoft.Extensions.Configuration;

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
}