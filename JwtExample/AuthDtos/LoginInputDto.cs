using System.ComponentModel.DataAnnotations;

namespace JwtExample.AuthDtos
{
    public class LoginInputDto
    {
        [Required, StringLength(100)]
        public string Email { get; set; }
        [Required, StringLength(20)]
        public string Password { get; set; }
    }


}
