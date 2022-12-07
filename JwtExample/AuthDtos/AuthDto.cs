using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace JwtExample.AuthDtos
{
    public class AuthDto
    {
        public class GetAuthOutputDto
        {
            public string Message { get; set; }
            public bool IsAuthentication { get; set; }
            public string UserName { get; set; }
            public string Email { get; set; }
            public IList<string> Roles { get; set; }
            public string Token { get; set; }
            //public DateTime ExpireOn { get; set; }
            [JsonIgnore]
            public string RefreshToken { get; set; }
            public DateTime RefreshDateExpiration { get; set; }
        }
        public class CreateUserInputDto
        {
            [Required,StringLength(50)]
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
        public class LoginInputDto
        {
            [Required, StringLength(100)]
            public string Email { get; set; }
            [Required, StringLength(20)]
            public string Password { get; set; }
        }
        public class RevokeTokenInputDto
        {
            public string? Token { get; set; }
        }

    }
}
