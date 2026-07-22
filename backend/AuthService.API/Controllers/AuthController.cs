using AuthService.Application.DTOs;
using AuthService.API.DTOs;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Services;


namespace AuthService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtTokenService _jwtTokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        IJwtTokenService jwtTokenService)
    {
        _userManager = userManager;
        _jwtTokenService = jwtTokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var user = new ApplicationUser
        {
            FullName = dto.FullName,
            Email = dto.Email,
            UserName = dto.Email
        };

        var result = await _userManager.CreateAsync(
            user,
            dto.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        var roleResult = await _userManager.AddToRoleAsync(user, "User");

        if (!roleResult.Succeeded)
            return BadRequest(roleResult.Errors);

        return Ok(new
        {
            message = "User created successfully"
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);

        if (user == null)
            return Unauthorized();

        var validPassword = await _userManager
            .CheckPasswordAsync(user, dto.Password);

        if (!validPassword)
            return Unauthorized();
        
        var roles = await _userManager.GetRolesAsync(user);

        var token = _jwtTokenService.GenerateToken(
            user.Id,
            user.Email!,
            user.FullName!,
            roles);

        return Ok(new
        {
            token
        });
    }

    [Authorize]
    [HttpGet("profile")]
    public IActionResult Profile()
    {
        var userId = User.FindFirstValue(JwtRegisteredClaimNames.Sub);
        var email = User.FindFirstValue(JwtRegisteredClaimNames.Email);
        var fullName = User.FindFirstValue(JwtRegisteredClaimNames.Name);

        return Ok(new
        {
            id = userId,
            fullName,
            email
        });
    }

    [Authorize(Roles = "User")]
    [HttpGet("user")]
    public IActionResult UserOnly()
    {
        return Ok(new
        {
            message = "Welcome User!"
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new
        {
            message = "Welcome Admin!"
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpPost("promote/{email}")]
    public async Task<IActionResult> PromoteToAdmin(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        if (user is null)
            return NotFound();

        if (await _userManager.IsInRoleAsync(user, "Admin"))
            return BadRequest("User is already an administrator.");

        var result = await _userManager.AddToRoleAsync(user, "Admin");

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(new
        {
            email,
            role = "Admin",
            message = "User promoted successfully."
        });
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("users")]
    public async Task<ActionResult<IEnumerable<UserDto>>> GetUsers()
    {
        var users = _userManager.Users
            .OrderBy(u => u.FullName)
            .ToList();

        var result = new List<UserDto>();

        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);

            result.Add(new UserDto
            {
                Id = user.Id,
                FullName = user.FullName,
                Email = user.Email!,
                Roles = roles
            });
        }

        return Ok(result);
    }
}