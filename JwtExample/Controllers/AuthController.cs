using JwtExample.Auth;
using JwtExample.AuthDtos;
using Microsoft.AspNetCore.Mvc;

namespace JwtExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthBLL _authBLL;

        public AuthController(IAuthBLL authBLL)
        {
            _authBLL = authBLL;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(CreateUserInputDto inputDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authBLL.Register(inputDto);
            if(!result.IsAuthentication)
                return BadRequest(result.Message);
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshDateExpiration);
            return Ok(result);
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginInputDto inputDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await _authBLL.Login(inputDto);
            if (!result.IsAuthentication)
                return BadRequest(result.Message);
            if (!string.IsNullOrEmpty(result.RefreshToken))
                SetRefreshTokenInCookie(result.RefreshToken,result.RefreshDateExpiration);
            return Ok(result);
        }
        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["RefreshToken"];
            var result =await _authBLL.RefreshTokenAsync(refreshToken??"");
        
            if(!result.IsAuthentication)
                return BadRequest(result);
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshDateExpiration);
            return Ok(result);  
        }
        [HttpPost("RevokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody]RevokeTokenInputDto inputDto)
        {
            var token =inputDto.Token ?? Request.Cookies["RefreshToken"];
            if (string.IsNullOrEmpty(token))
                return BadRequest("Token is required");

            var result = await _authBLL.RevokeTokenAsync(token);

            if (!result)
                return BadRequest("Token is invalid");
            return Ok(result);
        }
        private void SetRefreshTokenInCookie(string refreshToken , DateTime expireDate)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expireDate.ToLocalTime(),
            };
            Response.Cookies.Append("RefreshToken",refreshToken,cookieOptions);
        }
    }
}
