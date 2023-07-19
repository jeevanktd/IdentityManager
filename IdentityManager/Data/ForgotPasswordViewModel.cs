using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace IdentityManager.Data
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName("Email")]
        public string Email { get; set; }
    }
}
