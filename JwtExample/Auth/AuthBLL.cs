using AutoMapper;
using JwtExample.AuthDtos;
using JwtExample.Enums;
using JwtExample.Helpers;
using JwtExample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using static JwtExample.AuthDtos.AuthDto;
using Microsoft.EntityFrameworkCore;

namespace JwtExample.Auth
{
    public class AuthBLL : IAuthBLL
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IMapper _mapper;
        private readonly JWT _jwt;
        public AuthBLL(UserManager<ApplicationUser> userManager, IMapper mapper, IOptions< JWT> jwt)
        {
            _userManager = userManager;
            _mapper = mapper;
            _jwt = jwt.Value;
        }

        public async Task<GetAuthOutputDto> Login(LoginInputDto inputDto)
        {
            var output = new GetAuthOutputDto();
            var user = await _userManager.FindByEmailAsync(inputDto.Email);
            if(user == null || !await _userManager.CheckPasswordAsync(user,inputDto.Password))
            {
                output.Message = "Email or Password is in correct";
                return output;
            }
            var token = await CreateJwtToken(user);
            output.Message = "User Login Successfully";
            output.UserName = user.UserName;
            output.Email = user.Email;
            output.Token = new JwtSecurityTokenHandler().WriteToken(token);
            output.Roles =await _userManager.GetRolesAsync(user);
            //output.ExpireOn = token.ValidTo;
            output.IsAuthentication = true;
            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                output.RefreshToken = refreshToken.Token;
                output.RefreshDateExpiration = refreshToken.ExpiresOn;
            }
            else
            {
                var newRefreshToken = CreateRefreshToken();
                output.RefreshToken=newRefreshToken.Token;
                output.RefreshDateExpiration = newRefreshToken.ExpiresOn;
                user.RefreshTokens.Add(newRefreshToken);
               await _userManager.UpdateAsync(user);
                
            }
            return output;
        }

        public async Task<GetAuthOutputDto> Register(CreateUserInputDto inputDto)
        {
            GetAuthOutputDto output = new GetAuthOutputDto();
            if (await _userManager.FindByEmailAsync(inputDto.Email) is not null)
                return new GetAuthOutputDto { Message = "Email is already Registred !" };
            if (await _userManager.FindByNameAsync(inputDto.UserName) is not null)
                return new GetAuthOutputDto { Message = "UserName is already Registred !" };
            var user = _mapper.Map<ApplicationUser>(inputDto);
            var result = await _userManager.CreateAsync(user,inputDto.Password);
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach(var error in result.Errors)
                {
                    errors += $"{error.Description} ,";
                }
                return new GetAuthOutputDto { Message = errors };
            }
            await _userManager.AddToRoleAsync(user,nameof( RoleEnum.User));
            var token = await CreateJwtToken(user);
            output.Token=new JwtSecurityTokenHandler().WriteToken(token);
            output.Email = user.Email;
            output.UserName = user.UserName;
            output.IsAuthentication = true;
            output.Roles =await _userManager.GetRolesAsync(user);
            output.Message = "User Registred Successfully ";
            //output.ExpireOn = token.ValidTo;
            return output;

        }
        #region CreatTokenJwt And RefreshToken
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audiance,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.ExpireOn),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        public async Task<GetAuthOutputDto> RefreshTokenAsync(string token)
        {
            var output = new GetAuthOutputDto();
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if(user == null)
            {
                output.IsAuthentication = false;
                output.Message = "Invalid Token";
                return output; 
            }
            var refreshToken= user.RefreshTokens?.Single(t=>t.Token== token);
            if (refreshToken!= null && !refreshToken.IsActive)
            {
                output.IsAuthentication = false;
                output.Message = "InActive Token";
                return output;
            }
            refreshToken.RevokedOn = DateTime.UtcNow;
            var newRefreshToken = CreateRefreshToken();
            var jwtToken = await CreateJwtToken(user);
            user.RefreshTokens.Add(newRefreshToken);
            await _userManager.UpdateAsync(user);
            output.IsAuthentication = true;
            output.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            output.Email = user.Email;
            output.UserName = user.UserName;
            output.Roles = await _userManager.GetRolesAsync(user);
            output.RefreshToken = newRefreshToken.Token;
            output.RefreshDateExpiration = newRefreshToken.ExpiresOn;
            return output;
        }
        public async Task<bool> RevokeTokenAsync(string token)
        {
            var output = new GetAuthOutputDto();
            var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
                return false;
            
            var refreshToken = user.RefreshTokens?.Single(t => t.Token == token);
            if (refreshToken != null && !refreshToken.IsActive)
                return false;
            refreshToken.RevokedOn = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);
            return true;
        }
        private RefreshToken CreateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var genrator = new RNGCryptoServiceProvider();
            genrator.GetBytes(randomNumber);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                ExpiresOn = DateTime.UtcNow.AddDays(1),
                CreatedOn = DateTime.UtcNow
            };
        }
        #endregion
    }
}
