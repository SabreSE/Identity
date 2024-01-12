using IdentityManagerServerApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityManagerServerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _config;

        public AccountController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IConfiguration config)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _config = config;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null)
            {
                var result = await _signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    var token = await GenerateJwtToken(user);
                    return Ok(new { Token = token, Message = "Login successful" });
                }
            }

            return Unauthorized("Invalid login attempt.");
        }


        private async Task<List<string>> GetUserPermissions(UserManager<IdentityUser> userManager, IdentityUser user)
        {
            var permissions = new List<string>();

            var roles = await userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                // Assuming you have a method to get permissions for a role
                var rolePermissions = GetPermissionsForRole(role);
                permissions.AddRange(rolePermissions);
            }

            return permissions.Distinct().ToList();
        }


        private List<string> GetPermissionsForRole(string role)
        {
            // For debugging purposes, manually add permissions based on role
            // In a real application, you would fetch these from a database or some external source

            var permissions = new List<string>();

            switch (role)
            {
                case "SuperAdmin":
                    permissions.Add("Permissions.Products.Create");
                    //permissions.Add("Permissions.Products.View");
                    permissions.Add("Permissions.Products.Edit");
                    permissions.Add("Permissions.Products.Delete");
                    // Add more permissions as needed
                    break;
                case "Admin":
                    //permissions.Add("Permissions.Products.View");
                    permissions.Add("Permissions.Products.Edit");
                    // Add more permissions as needed
                    break;
                case "Basic":
                    //permissions.Add("Permissions.Products.View");
                    // Add more permissions as needed
                    break;
                    // Add more roles and their respective permissions as needed
            }

            return permissions;
        }

        //private List<string> GetPermissionsForRole(string role)
        //{
        //    // Implement logic to get permissions based on role
        //    // For example, query from database or use predefined mappings
        //    return new List<string>(); // Return permissions for the role
        //}


        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                // other claims
            };

            var userPermissions = await GetUserPermissions(_userManager, user);
            foreach (var permission in userPermissions)
            {
                claims.Add(new Claim("Permission", permission));
            }

            var roles = await _userManager.GetRolesAsync(user);
            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["Jwt:Issuer"],
                Audience = _config["Jwt:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}




