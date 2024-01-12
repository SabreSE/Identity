using IdentityManagerServerApi.Constants;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityManagerServerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        public UsersController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        [Authorize(Permissions.Products.View)]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var users = await _userManager.Users
                                          .Select(u => new { u.Id, u.UserName, u.Email }) // Project to a DTO if necessary
                                          .ToListAsync();
            return Ok(users);
        }

        [Authorize]
        [HttpGet("current")]
        public IActionResult GetCurrent()
        {
            // Retrieve the user's identity from HttpContext
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity != null)
            {
                // Get the user's ID or username from the claims
                var userId = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userName = identity.FindFirst(ClaimTypes.Name)?.Value;

                return Ok(new { UserId = userId, UserName = userName });
            }

            return Unauthorized("User is not authenticated.");
        }
    }
}
