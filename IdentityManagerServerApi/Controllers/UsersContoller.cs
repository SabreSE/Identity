using IdentityManagerServerApi.Constants;
using IdentityManagerServerApi.Models;
using IdentityManagerServerApi.Seeds;
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
    [Authorize(Roles = "SuperAdmin")]
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


        [HttpPost("CreateUser")]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var existingUser = await _userManager.FindByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return BadRequest("User already exists.");
            }

            var newUser = new IdentityUser
            {
                UserName = model.Email, // Or a separate UserName if your model includes it
                Email = model.Email,
                EmailConfirmed = true // Handle email confirmation as per your logic
            };

            var createUserResult = await _userManager.CreateAsync(newUser, model.Password);
            if (!createUserResult.Succeeded)
            {
                return BadRequest(createUserResult.Errors);
            }

            // Add the new user to the "Basic" role
            var addToRoleResult = await _userManager.AddToRoleAsync(newUser, "Basic");
            if (!addToRoleResult.Succeeded)
            {
                // Handle the case where adding to the role fails
                return BadRequest(addToRoleResult.Errors);
            }

            return Ok("User created and added to Basic role successfully.");
        }





        //[HttpPost("CreateUser")]
        //public async Task<IActionResult> CreateUser(string email, string password, string role = "Basic")
        //{
        //    // Validate input
        //    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
        //    {
        //        return BadRequest("Email and password are required.");
        //    }

        //    // Check if the user already exists
        //    var existingUser = await _userManager.FindByEmailAsync(email);
        //    if (existingUser != null)
        //    {
        //        return BadRequest("User already exists.");
        //    }

        //    var newUser = new IdentityUser
        //    {
        //        UserName = email,
        //        Email = email,
        //        EmailConfirmed = true, // You might want to send confirmation email instead
        //        PhoneNumberConfirmed = true // Depends on your requirement
        //    };

        //    var result = await _userManager.CreateAsync(newUser, password);
        //    if (!result.Succeeded)
        //    {
        //        return BadRequest(result.Errors);
        //    }

        //    // Add to role, if role management is necessary
        //    if (!string.IsNullOrEmpty(role))
        //    {
        //        await _userManager.AddToRoleAsync(newUser, role);
        //    }

        //    return Ok("User created successfully.");
        //}
    }
}
