using System.ComponentModel.DataAnnotations;

namespace IdentityManagerServerApi.Models
{
    public class CreateUserModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The password must be at least {2} characters long.", MinimumLength = 6)]
        public string Password { get; set; }

        // Optional: Include other properties as needed, like UserName, PhoneNumber, etc.
        // You can also include role here if you want to set it during user creation.
    }

}
