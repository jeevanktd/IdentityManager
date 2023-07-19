using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Data
{
    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName ("Email")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [DisplayName("Password")]
        public string Password { get; set; }

        [Required]
        [DisplayName("Confirm Password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage ="The Password and Confirmation Password should match")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }
}
