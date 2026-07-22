using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Infrastructure.Persistence.Seeders;

public static class AdminSeeder
{
    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();

        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();

        var email = configuration["AdminUser:Email"];
        var password = configuration["AdminUser:Password"];
        var fullName = configuration["AdminUser:FullName"];

        if (string.IsNullOrWhiteSpace(email))
            throw new InvalidOperationException("Configuration 'AdminUser:Email' was not found.");

        if (string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Configuration 'AdminUser:Password' was not found.");

        if (string.IsNullOrWhiteSpace(fullName))
            throw new InvalidOperationException("Configuration 'AdminUser:FullName' was not found.");

        var admin = await userManager.FindByEmailAsync(email);

        if (admin is not null)
            return;

        admin = new ApplicationUser
        {
            FullName = fullName,
            Email = email,
            UserName = email
        };

        var result = await userManager.CreateAsync(admin, password);

        if (!result.Succeeded)
            throw new Exception("Failed to create default administrator.");

        await userManager.AddToRoleAsync(admin, "Admin");
    }
}