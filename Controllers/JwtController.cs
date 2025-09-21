using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplicationDemo.Models;

namespace WebApplicationDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class JwtController : ControllerBase
    {
        private readonly IConfiguration _config;

        public JwtController(IConfiguration config)
        {
            _config = config;
        }

        // 模擬登入，產生 JWT
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // 這裡先寫死帳號密碼，後續可以接 DB
            if (request.Username == "admin" && request.Password == "1234")
            {
                var token = GenerateJwtToken(request.Username);
                return Ok(new { token });
            }

            return Unauthorized("帳號或密碼錯誤");
        }

        // 測試需要驗證的 API
        [Authorize]
        [HttpGet("secret")]
        public IActionResult GetSecretData()
        {
            var username = User.Identity?.Name; // 取出 JWT 裡的 "sub" Claim
            return Ok(new { message = $"Hello {username}, this is protected data!" });
        }

        // 建立 JWT Token
        private string GenerateJwtToken(string username)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
