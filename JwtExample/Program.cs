using JwtExample.Auth;
using JwtExample.Context;
using JwtExample.Helpers;
using JwtExample.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();



// Add Scoped
builder.Services.AddScoped<IAuthBLL, AuthBLL>();

//Add Identity and DbContext
builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbcontext>();
var conn = builder.Configuration.GetConnectionString("DefaulConnection");
builder.Services.AddDbContext<ApplicationDbcontext>(option =>
     option.UseSqlServer(conn));

// Add Auto Mapper
builder.Services.AddAutoMapper(typeof(Program));
builder.Services.AddControllersWithViews();

//Add Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
      .AddJwtBearer(o =>
       {
         o.RequireHttpsMetadata = false;
         o.SaveToken = false;
         o.TokenValidationParameters = new TokenValidationParameters
              {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidIssuer =builder.Configuration ["JWT:Issuer"],
                ValidAudience = builder.Configuration["JWT:Audiance"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
                ClockSkew = TimeSpan.Zero
              };
       });

// appSetting variables
builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
var app = builder.Build();
//Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
