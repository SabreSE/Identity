using IdentityManagerServerApi.Models;
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
    public class UserRolesController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserRolesController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        [HttpGet("{userId}")] // Assuming 'userId' is the identifier for the user
        public async Task<IActionResult> Index(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"User with ID {userId} not found.");
            }

            var roles = await _roleManager.Roles.ToListAsync();
            var viewModel = new List<UserRolesViewModel>();

            foreach (var role in roles)
            {
                var userRolesViewModel = new UserRolesViewModel
                {
                    RoleName = role.Name,
                    Selected = await _userManager.IsInRoleAsync(user, role.Name)
                };

                viewModel.Add(userRolesViewModel);
            }

            var model = new ManageUserRolesViewModel()
            {
                UserId = userId,
                UserRoles = viewModel
            };

            return Ok(model);
        }


        [HttpPut("{id}")] // Assuming 'id' is the user's ID
        public async Task<IActionResult> Update(string id, ManageUserRolesViewModel model)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound($"User with ID {id} not found.");
            }

            var roles = await _userManager.GetRolesAsync(user);
            var removeFromRolesResult = await _userManager.RemoveFromRolesAsync(user, roles);

            if (!removeFromRolesResult.Succeeded)
            {
                return BadRequest(removeFromRolesResult.Errors);
            }

            var selectedRoles = model.UserRoles.Where(x => x.Selected).Select(y => y.RoleName);
            var addToRolesResult = await _userManager.AddToRolesAsync(user, selectedRoles);

            if (!addToRolesResult.Succeeded)
            {
                return BadRequest(addToRolesResult.Errors);
            }

            var currentUser = await _userManager.GetUserAsync(User);
            await _signInManager.RefreshSignInAsync(currentUser);

            // Re-seeding the super admin should be done with caution and is typically not part of a standard update method
            // await Seeds.DefaultUsers.SeedSuperAdminAsync(_userManager, _roleManager);

            return Ok(new { Message = "User roles updated successfully" });
        }

    }
}