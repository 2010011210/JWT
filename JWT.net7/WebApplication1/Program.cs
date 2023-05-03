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

//鉴权的IOC注册，如何鉴权
//builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
//	 .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
//	 {
//		 options.LoginPath = "/Auth/Index";
//		 options.AccessDeniedPath = "/Auth/Index";
//	 });//使用Cookie的方式


#region UrlToken授权
//builder.Services.AddAuthentication(options =>
//{
//	options.AddScheme<UrlTokenAuthenticationHandler>(UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme, UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme);

//	options.DefaultAuthenticateScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;//不能少.默认用UrlTokenScheme
//	options.DefaultChallengeScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultSignInScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultForbidScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//	options.DefaultSignOutScheme = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
//});

#endregion

#region token鉴权
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
						ClockSkew = TimeSpan.FromSeconds(0),    // token过期后立刻失效

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer，这两项和前面签发jwt的设置一致
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

#region 鉴权
builder.Services.AddAuthorization(options => {
	// Develop 策略，角色必须是Develop。
	options.AddPolicy("Develop", policyBuilder => {
		policyBuilder.RequireRole("Develop");
	} );

	// 自定义复杂策略
	options.AddPolicy("MultiPolicy", policyBuilder =>
	{
		policyBuilder.RequireRole("Admin")
		.RequireUserName("king")
		.RequireClaim(ClaimTypes.Country, new string[] { "Chinese", "American", "Franch" });
		//.RequireAssertion(context => context.User.Claims.First(c => c.Type.Equals(ClaimTypes.DateOfBirth))?.Value == "1991");
	});

	// 多个策略
	options.AddPolicy("ComplexPolicy", policyBuilder => {
		policyBuilder.AddRequirements(new MultiEmailRequirement());
	});


});

//2个邮箱任选
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

app.UseAuthentication();    // authentication 鉴权  authenticate v.证明..是真实的;证实
app.UseAuthorization();     // Authorization  批准；授权


app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
