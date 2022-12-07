using System.Text.Json.Serialization;

namespace JwtExample.AuthDtos
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


}
