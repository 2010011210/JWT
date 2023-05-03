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
	#region Swagger����֧��Token�������� 
	options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
	{
		Description = "������token,��ʽΪ Bearer jwtToken(ע���м�����пո�)",
		Name = "Authorization",
		In = ParameterLocation.Header,
		Type = SecuritySchemeType.ApiKey,
		BearerFormat = "JWT",
		Scheme = JwtBearerDefaults.AuthenticationScheme
	});//��Ӱ�ȫ����

	options.AddSecurityRequirement(new OpenApiSecurityRequirement {
				{   //��Ӱ�ȫҪ��
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


//builder.Services.AddTransient<IJWTTokenService, JWTTokenService>();   // ��һ�ֽӿڵĺ��������ʲô����
builder.Services.AddTransient<JWTTokenService>();

// �����ļ��󶨶���
builder.Services.Configure<JWTOption>(builder.Configuration.GetSection("JWTOptions"));

#region ��Ȩ
JWTOption tokenOptions = new JWTOption();
builder.Configuration.Bind("JWTOptions", tokenOptions);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options =>
				{
					options.TokenValidationParameters = new TokenValidationParameters
					{
						//JWT��һЩĬ�ϵ����ԣ����Ǹ���Ȩʱ�Ϳ���ɸѡ��
						ValidateIssuer = true,//�Ƿ���֤Issuer
						ValidateAudience = true,//�Ƿ���֤Audience
						ValidateLifetime = true,//�Ƿ���֤ʧЧʱ��
						ValidateIssuerSigningKey = true,//�Ƿ���֤SecurityKey

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer���������ǰ��ǩ��jwt������һ��
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
					};
				})
				;

#endregion

#region ��Ȩ
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

app.UseAuthentication();    // authentication ��Ȩ  authenticate v.֤��..����ʵ��;֤ʵ
app.UseAuthorization();     // Authorization  ��׼����Ȩ


app.MapControllers();

app.Run();
