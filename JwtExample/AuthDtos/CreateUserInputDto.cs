using System.ComponentModel.DataAnnotations;

namespace JwtExample.AuthDtos
{
    public class CreateUserInputDto
    {
        [Required, StringLength(50)]
        public string FirstName { get; set; }
        [Required, StringLength(50)]
        public string LastName { get; set; }
        [Required, StringLength(150)]
        public string UserName { get; set; }
        [Required, StringLength(100)]
        public string Email { get; set; }
        [Required, StringLength(20)]
        public string Password { get; set; }
    }

}
