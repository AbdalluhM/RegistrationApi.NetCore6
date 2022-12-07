using AutoMapper;
using JwtExample.Models;
using static JwtExample.AuthDtos.AuthDto;

namespace JwtExample.Mapper
{
    public class UserProfile:Profile
    {
        public UserProfile()
        {
            CreateMap<CreateUserInputDto, ApplicationUser>();
            CreateMap<ApplicationUser, CreateUserInputDto>();  
        }
    }
}
