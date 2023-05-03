using JWTAPI.Model;
using JWTAPI.Utility;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
#region Swagger
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(options =>
{
	#region Swagger配置支持Token参数传递 
	options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
	{
		Description = "请输入token,格式为 Bearer jwtToken(注意中间必须有空格)",
		Name = "Authorization",
		In = ParameterLocation.Header,
		Type = SecuritySchemeType.ApiKey,
		BearerFormat = "JWT",
		Scheme = JwtBearerDefaults.AuthenticationScheme
	});//添加安全定义

	options.AddSecurityRequirement(new OpenApiSecurityRequirement {
				{   //添加安全要求
                    new OpenApiSecurityScheme
					{
						Reference =new OpenApiReference()
						{
							Type = ReferenceType.SecurityScheme,
							Id ="Bearer"
						}
					},
					new string[]{ }
				}
				});
	#endregion
});
#endregion


//builder.Services.AddTransient<IJWTTokenService, JWTTokenService>();   // 这一种接口的和下面的有什么区别？
builder.Services.AddTransient<JWTTokenService>();

// 配置文件绑定对象
builder.Services.Configure<JWTOption>(builder.Configuration.GetSection("JWTOptions"));

#region 鉴权
JWTOption tokenOptions = new JWTOption();
builder.Configuration.Bind("JWTOptions", tokenOptions);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options =>
				{
					options.TokenValidationParameters = new TokenValidationParameters
					{
						//JWT有一些默认的属性，就是给鉴权时就可以筛选了
						ValidateIssuer = true,//是否验证Issuer
						ValidateAudience = true,//是否验证Audience
						ValidateLifetime = true,//是否验证失效时间
						ValidateIssuerSigningKey = true,//是否验证SecurityKey

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer，这两项和前面签发jwt的设置一致
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
					};
				})
				;

#endregion

#region 授权
builder.Services.AddAuthorization(options =>
options.AddPolicy("ComplexPolicy", policyBuilder =>
	policyBuilder.RequireRole("Admin")
	.RequireAssertion(context => 
		context.User.HasClaim(c => c.Type == ClaimTypes.Email) && context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value.EndsWith("qq.com")
		)
	)
);


#endregion




var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseAuthentication();    // authentication 鉴权  authenticate v.证明..是真实的;证实
app.UseAuthorization();     // Authorization  批准；授权


app.MapControllers();

app.Run();
