using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var jwtKey = RSA.Create();  // jwt的密钥，需要写在配置文件中
builder.Services.AddAuthentication("MyBear").AddJwtBearer("MyBear", o => {
	o.TokenValidationParameters = new TokenValidationParameters()
	{
		ValidateIssuer = false,
		IssuerSigningKey = new RsaSecurityKey(jwtKey)
	};
	o.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents()
	{
		OnMessageReceived = (context) =>
		{
			if (context.Request.Query.ContainsKey("token"))
			{
				context.Token = context.Request.Query["token"];
			}
			return Task.CompletedTask;
		}
	};
	
	});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapGet("jwt", () => 
{
	var secret = new RsaSecurityKey(jwtKey);  // 生成一个密钥

	var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor()
	{
		Subject = new System.Security.Claims.ClaimsIdentity(new List<Claim>()
		{
			new Claim("iss","KingSmart"),
			new Claim("sub","learningJWT")
		},"myjwt"),
		SigningCredentials = new SigningCredentials(secret, SecurityAlgorithms.RsaSha256)
	});

	return jwt;
});

app.MapGet("other", (string token, HttpContext context) =>
{
	return context.User.Claims.Any(x => x.Issuer == "KingSmart");
});

app.MapControllers();

app.Run();
