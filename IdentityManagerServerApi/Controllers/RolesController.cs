using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagerServerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            return Ok(roles);
        }


        [HttpPost]
        public async Task<IActionResult> AddRole(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                // Return a bad request response with a message
                return BadRequest("Role name is required.");
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName.Trim()));

            if (result.Succeeded)
            {
                // Optionally, return the created role data
                //var createdRole = await _roleManager.FindByNameAsync(roleName.Trim());
                //return CreatedAtAction(nameof(Index), new { id = createdRole.Id }, createdRole);
                return Ok(new { Message = "Roles Added successfully" });
            }
            else
            {
                // If there are errors (like role already exists), return a bad request with the error details
                return BadRequest(result.Errors);
            }
        }

    }
}