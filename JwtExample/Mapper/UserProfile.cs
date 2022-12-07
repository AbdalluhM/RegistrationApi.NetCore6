using AutoMapper;
using JwtExample.AuthDtos;
using JwtExample.Models;

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
