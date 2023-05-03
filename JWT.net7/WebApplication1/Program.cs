using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using WebApplication1.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

//��Ȩ��IOCע�ᣬ��μ�Ȩ
//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//	 .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
//	 {
//		 options.LoginPath = "/Auth/Index";
//		 options.AccessDeniedPath = "/Auth/Index";
//	 });//ʹ��Cookie�ķ�ʽ


#region UrlToken��Ȩ
//builder.Services.AddAuthentication(options =>
//{
//	options.AddScheme<UrlTokenAuthenticationHandler>(UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme, UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme);

//	options.DefaultAuthenticateScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;//������.Ĭ����UrlTokenScheme
//	options.DefaultChallengeScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultSignInScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultForbidScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultSignOutScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//});

#endregion

#region token��Ȩ
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
						ClockSkew = TimeSpan.FromSeconds(0),    // token���ں�����ʧЧ

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer���������ǰ��ǩ��jwt������һ��
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
					};

					options.Events = new JwtBearerEvents() 
					{
						OnChallenge = context => 
						{
							context.Response.Headers.Add("JWTChallenge","expired");
							return Task.CompletedTask;
						}
					};

				})
				;

#endregion

#region ��Ȩ
builder.Services.AddAuthorization(options => {
	// Develop ���ԣ���ɫ������Develop��
	options.AddPolicy("Develop", policyBuilder => {
		policyBuilder.RequireRole("Develop");
	} );

	// �Զ��帴�Ӳ���
	options.AddPolicy("MultiPolicy", policyBuilder =>
	{
		policyBuilder.RequireRole("Admin")
		.RequireUserName("king")
		.RequireClaim(ClaimTypes.Country, new string[] { "Chinese", "American", "Franch" });
		//.RequireAssertion(context => context.User.Claims.First(c => c.Type.Equals(ClaimTypes.DateOfBirth))?.Value == "1991");
	});

	// �������
	options.AddPolicy("ComplexPolicy", policyBuilder => {
		policyBuilder.AddRequirements(new MultiEmailRequirement());
	});


});

//2��������ѡ
builder.Services.AddSingleton<IAuthorizationHandler, NetEasyHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, QQEmailHandler>();


#endregion

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();    // authentication ��Ȩ  authenticate v.֤��..����ʵ��;֤ʵ
app.UseAuthorization();     // Authorization  ��׼����Ȩ


app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
