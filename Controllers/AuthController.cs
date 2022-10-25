using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using TestAspApiApp.Services.UserService;

namespace TestAspApiApp.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly List<User> user;
    private readonly IConfiguration _config;
    private readonly IUserService userService;
    public AuthController(IConfiguration config, List<User> user, IUserService userService)
    {
        this._config = config;
        this.user = user;
        this.userService = userService;
    }

    [HttpGet("GetMe"), Authorize]
    public ActionResult<string?> GetMe() {
        // string? userName = User?.Identity?.Name;
        return userService.GetMyName();
    }

    [HttpGet("GetUsers")]
    public ActionResult<List<User>> GetUsers() => user;

    [HttpPost("Register")]
    public async Task<ActionResult<User>> Register(UserDto userDto) {
        CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

        User newUser = new User {
            Username = userDto.Username,
            PasswordHash = passwordHash,
            PasswordSalt = passwordSalt
        };
        user.Add(newUser);

        return Ok(newUser);
    }

    [HttpPost("Login")]
    public async Task<ActionResult<string>> Login(UserDto userDto) {
        User? usr = user.FirstOrDefault(u => u.Username == userDto.Username);

        if(usr == null || !VerifyPasswordHash(userDto.Password, usr.PasswordHash, usr.PasswordSalt))
            return BadRequest("Invalid credentials");
        
        string token = CreateToken(usr);

        RefreshToken refreshToken = GenerateRefreshToken();
        SetRefreshToken(refreshToken, usr);

        return Ok(token);
    }

    [HttpPost("RefreshToken")]
    public async Task<ActionResult<string>> RefreshTocken() {
        string? refreshToken = Request.Cookies["refreshToken"];

        User? usr = user.FirstOrDefault(u => u.RefreshToken == refreshToken);

        if(usr == null)
            return Unauthorized("Invalid Refresh Token");
        else if(usr.TokenExpires < DateTime.Now)
            return Unauthorized("Token expired");

        string token = CreateToken(usr);
        RefreshToken newRefreshToken = GenerateRefreshToken();
        SetRefreshToken(newRefreshToken, usr);

        return Ok(token);
    }





    private RefreshToken GenerateRefreshToken() => new RefreshToken() {
        Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
        Created = DateTime.Now,
        Expires = DateTime.Now.AddHours(2)
    };

    private void SetRefreshToken(RefreshToken refreshToken, User user) {
        CookieOptions cookie = new() {
            HttpOnly = true,
            Expires = refreshToken.Expires
        };
        Response.Cookies.Append("refreshToken", refreshToken.Token, cookie);
        user.RefreshToken = refreshToken.Token;
        user.TokenCreated = refreshToken.Created;
        user.TokenExpires = refreshToken.Expires;
    } 

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt) {
        using(var hmac = new HMACSHA256()) {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new() {
            new Claim(ClaimTypes.Name, user.Username), 
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value ));

        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature); 

        var token = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: cred);

        string jwt = new JwtSecurityTokenHandler().WriteToken(token); 

        return jwt;
    }

    private bool  VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt) {
        using(var hmac = new HMACSHA256(passwordSalt)) {
            byte[] computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            return computeHash.SequenceEqual(passwordHash);
        }
    }
}
