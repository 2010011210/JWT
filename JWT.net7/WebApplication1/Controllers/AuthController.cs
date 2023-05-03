using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using WebApplication1.Models;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;

namespace WebApplication1.Controllers
{
	public class AuthController : Controller
	{
		#region Identity
		private readonly IConfiguration _iConfiguration;
		private readonly ILogger<AuthController> _logger;
		private readonly ILoggerFactory _loggerFactory;

		public AuthController(IConfiguration configuration
			, ILoggerFactory loggerFactory
			, ILogger<AuthController> logger)
		{
			this._iConfiguration = configuration;
			this._logger = logger;
			this._loggerFactory = loggerFactory;
		}
		#endregion

		/// <summary>
		/// 不需要权限就能访问---
		/// http://localhost:5285/auth/index
		/// 但是项目里面总有些数据是要登陆后才能看到的
		/// </summary>
		/// <returns></returns>
		public IActionResult Index()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return View();
		}

		#region Cookie登陆
		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		public IActionResult Info()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return View();
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize(Roles = "Admin")]//表明该Action需要鉴权通过---得有鉴权动作
		public IActionResult InfoAdmin()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");


			return new JsonResult("Admin");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize(Roles = "Admin,Develop")]//表明该Action需要鉴权通过---得有鉴权动作
		public IActionResult InfoAdminOrDevelop()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("Admin,Develop");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize(Roles = "Develop")]//表明该Action需要鉴权通过---得有鉴权动作
		public IActionResult InfoDevelop()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("Develop");
		}

		#region UrlToken
		/// <summary>
		/// http://localhost:5285/Auth/UrlToken
		/// http://localhost:5285/Auth/UrlToken?UrlToken=king123456
		/// </summary>
		/// <returns></returns>
		//没有要求授权
		public async Task<IActionResult> UrlToken()
		{
			var userOrigin = base.HttpContext.User;
			var result = await base.HttpContext.AuthenticateAsync(UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme);
			if (result?.Principal == null)
			{
				return new JsonResult(new
				{
					Result = false,
					Message = "认证失败,用户未登录"
				});
			}
			else {
				base.HttpContext.User = result.Principal;
				StringBuilder strBuilder = new StringBuilder();
				foreach (var item in base.HttpContext.User.Identities.First().Claims) 
				{
					var content = $"InfoGet {item.Type}:{item.Value}";
					Console.WriteLine(content);
					strBuilder.Append(content);
				}

				return new JsonResult(new
				{
					Result = true,
					Message = "认证成功，用户已登录"
				});
			}
		}

		/// <summary>
		/// http://localhost:5285/Auth/UrlToken
		/// http://localhost:5285/Auth/UrlToken?UrlToken=king123456
		/// </summary>
		/// <returns></returns>
		//多个授权，cookie+自定义UrlToken
		public async Task<IActionResult> UrlTokenMulti()
		{
			var userOrigin = base.HttpContext.User;
			var result = await base.HttpContext.AuthenticateAsync(UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme);
			var result2 = await base.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			if (result.Succeeded || result2.Succeeded) 
			{
				base.HttpContext.User = result.Principal;
				StringBuilder strBuilder = new StringBuilder();
				foreach (var item in base.HttpContext.User.Identities.First().Claims)
				{
					var content = $"InfoGet {item.Type}:{item.Value}";
					Console.WriteLine(content);
					strBuilder.Append(content);
				}

				return new JsonResult(new
				{
					Result = true,
					Message = "认证成功，用户已登录"
				});
			}
			else
			{
				
				return new JsonResult(new
				{
					Result = false,
					Message = "认证失败,用户未登录"
				});
			}
		}


		#endregion


		#region  policy
		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Policy = "Develop")]
		[Authorize(AuthenticationSchemes = "Cookies")]
		public IActionResult InfoWithDevelopPolicy()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithDevelopPolicy");
		}

		/// <summary>
		/// 执行复杂的鉴权policy
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Policy = "MultiPolicy")]
		[Authorize(AuthenticationSchemes = "Cookies")]   // 采用cookie的模式进行授权
		//[Authorize(AuthenticationSchemes = "Cookies","Token")]  //只要满足多个scheme中的一个，即可授权成功
		public IActionResult InfoWithMultiPolicy()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is InfoWithMultiPolicy-Index");

			return new JsonResult("InfoWithMultiPolicy");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Policy = "ComplexPolicy")]
		[Authorize(AuthenticationSchemes = "Cookies")]
		public IActionResult InfoWithComplexPolicy()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is InfoWithMultiPolicy-Index");

			return new JsonResult("InfoWithComplexPolicy");
		}



		#endregion



		#region  scheme授权选择不同的scheme进行鉴权
		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Roles = "Develop")]
		[Authorize(AuthenticationSchemes = "Cookies")]
		public IActionResult InfoWithDevelopPolicyCookie()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithDevelopPolicyCookie");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Roles = "Admin")]
		[Authorize(AuthenticationSchemes = "Cookies")]
		public IActionResult InfoWithAdminPolicyCookie()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithAdminPolicy");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Roles = "Admin")]
		[Authorize(AuthenticationSchemes = "UrlToken")]
		public IActionResult InfoWithAdminPolicyUrlToken()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithAdminPolicyUrlToken");
		}

		/// <summary>
		/// Cookies或者UrlToken任意一个通过就可以
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(Roles = "Admin")]
		[Authorize(AuthenticationSchemes = "UrlToken,Cookies")]
		public IActionResult InfoWithAdminPolicyUrlTokenOrCookie()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithAdminPolicyUrlTokenOrCookie");
		}

		/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		[Authorize(AuthenticationSchemes = "UrlToken")]
		[Authorize(AuthenticationSchemes = "Cookies")]
		public IActionResult InfoWithUrlTokenOrCookie()
		{
			this._loggerFactory.CreateLogger<AuthController>().LogWarning("This is AuthController-Index 1");

			return new JsonResult("InfoWithUrlTokenOrCookie");
		}
		#endregion


		/// <summary>
		/// http://localhost:5285/Auth/Login?name=king&password=123456
		/// </summary>
		/// <param name="name"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public async Task<IActionResult> Login(string name, string password)
		{
			if ("king".Equals(name, StringComparison.CurrentCultureIgnoreCase)
				&& password.Equals("123456"))//等同于去数据库校验
			{
				var claimIdentity = new ClaimsIdentity("Custom");
				claimIdentity.AddClaim(new Claim(ClaimTypes.Name, name));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Email, "57265177@qq.com"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Country, "Chinese"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.DateOfBirth, "1991"));

				await base.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimIdentity), new AuthenticationProperties
				{
					ExpiresUtc = DateTime.UtcNow.AddMinutes(30),
				});//登陆默认Scheme，写入Cookie
				return new JsonResult(new
				{
					Result = true,
					Message = "登录成功"
				});
			}
			else
			{
				await Task.CompletedTask;
				return new JsonResult(new
				{
					Result = false,
					Message = "登录失败"
				});
			}
		}

		/// <summary>
		/// http://localhost:5285/Auth/LoginDevelop?name=king&password=123456
		/// </summary>
		/// <param name="name"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public async Task<IActionResult> LoginDevelop(string name, string password)
		{
			if ("king".Equals(name, StringComparison.CurrentCultureIgnoreCase)
				&& password.Equals("123456"))//等同于去数据库校验
			{
				var claimIdentity = new ClaimsIdentity("Custom");
				claimIdentity.AddClaim(new Claim(ClaimTypes.Name, name));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Email, "57265177@test.com"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Role, "Develop"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.Country, "Canada"));
				claimIdentity.AddClaim(new Claim(ClaimTypes.DateOfBirth, "1991"));

				await base.HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimIdentity), new AuthenticationProperties
				{
					ExpiresUtc = DateTime.UtcNow.AddMinutes(30),
				});//登陆默认Scheme，写入Cookie
				return new JsonResult(new
				{
					Result = true,
					Message = "登录成功"
				});
			}
			else
			{
				await Task.CompletedTask;
				return new JsonResult(new
				{
					Result = false,
					Message = "登录失败"
				});
			}
		}

		/// <summary>
		/// 退出登陆
		/// http://localhost:5726/Auth/Logout
		/// </summary>
		/// <returns></returns>
		public async Task<IActionResult> Logout()
		{
			await base.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
			return new JsonResult(new
			{
				Result = true,
				Message = "退出成功"
			});
		}
		#endregion
	}
}
