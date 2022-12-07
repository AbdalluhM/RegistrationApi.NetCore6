using JwtExample.AuthDtos;

namespace JwtExample.Auth
{
    public interface IAuthBLL
    {
        Task<GetAuthOutputDto> Register(CreateUserInputDto inputDto);
        Task<GetAuthOutputDto> Login(LoginInputDto inputDto); 
        Task<GetAuthOutputDto> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token);
    }
}
