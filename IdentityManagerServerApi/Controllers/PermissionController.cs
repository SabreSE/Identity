using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IdentityManagerServerApi.Constants;
using IdentityManagerServerApi.Helpers;
using IdentityManagerServerApi.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManagerServerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "SuperAdmin")]
    public class PermissionController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public PermissionController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        [HttpGet]
        public async Task<ActionResult> Index(string roleId)
        {
            var model = new PermissionViewModel();
            var allPermissions = new List<RoleClaimsViewModel>();
            allPermissions.GetPermissions(typeof(Permissions.Products), roleId);
            var role = await _roleManager.FindByIdAsync(roleId);
            model.RoleId = roleId;
            var claims = await _roleManager.GetClaimsAsync(role);
            var allClaimValues = allPermissions.Select(a => a.Value).ToList();
            var roleClaimValues = claims.Select(a => a.Value).ToList();
            var authorizedClaims = allClaimValues.Intersect(roleClaimValues).ToList();
            foreach (var permission in allPermissions)
            {
                if (authorizedClaims.Any(a => a == permission.Value))
                {
                    permission.Selected = true;
                }
            }
            model.RoleClaims = allPermissions;
            return Ok(model);
        }

        [HttpPut]
        public async Task<IActionResult> Update(PermissionViewModel model)
        {
            var role = await _roleManager.FindByIdAsync(model.RoleId);

            if (role == null)
            {
                return NotFound(); // or return BadRequest() if the input is invalid
            }

            var claims = await _roleManager.GetClaimsAsync(role);
            foreach (var claim in claims)
            {
                await _roleManager.RemoveClaimAsync(role, claim);
            }

            var selectedClaims = model.RoleClaims.Where(a => a.Selected).ToList();
            foreach (var claim in selectedClaims)
            {
                await _roleManager.AddPermissionClaim(role, claim.Value);
            }

            // Optionally, you can return the updated state of the role
            var updatedRoleClaims = await _roleManager.GetClaimsAsync(role);

            // Return a status code like 200 OK or 204 No Content
            // with or without the updated data
            return Ok(new { Message = "Permissions updated successfully", UpdatedClaims = updatedRoleClaims });
        }

    }
}