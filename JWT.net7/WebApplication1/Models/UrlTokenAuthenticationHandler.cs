using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace WebApplication1.Models
{
	public class UrlTokenAuthenticationHandler : IAuthenticationHandler
	{
		private AuthenticationScheme _scheme;
		private HttpContext _httpContext;

		/// <summary>
		/// 初始化
		/// </summary>
		/// <param name="scheme"></param>
		/// <param name="context"></param>
		/// <returns></returns>
		public Task InitializeAsync(AuthenticationScheme scheme, HttpContext context)
		{
			Log("InitializeAsync");
			this._scheme = scheme;
			this._httpContext = context;
			return Task.CompletedTask;
		}

		public Task<AuthenticateResult> AuthenticateAsync()
		{
			Log("AuthenticateAsync");
			var tokenKey = UrlTokenAuthenticationDefaults.DefaultAuthenticationScheme;
			var tokenValue = this._httpContext.Request.Query[tokenKey];
			Log(tokenValue);
			if (string.IsNullOrEmpty(tokenValue))
			{
				Console.WriteLine("token为空");
				return Task.FromResult(AuthenticateResult.NoResult());
			}
			else if ("king123456".Equals(tokenValue))
			{
				var claimsIdentity = new ClaimsIdentity("Custom");
				claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, "king"));
				claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
				claimsIdentity.AddClaim(new Claim(ClaimTypes.DateOfBirth, "2023"));
				claimsIdentity.AddClaim(new Claim(ClaimTypes.MobilePhone, "13644610109"));
				claimsIdentity.AddClaim(new Claim(ClaimTypes.Email, "809406089"));
				ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

				return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, null, _scheme.Name)));
			}
			else {
				return Task.FromResult<AuthenticateResult>(AuthenticateResult.Fail($"Url is wrong:{tokenValue}"));
			}
		}

		public Task ChallengeAsync(AuthenticationProperties? properties)
		{
			Log("ChallengeAsync");
			string redirectUri = "/Home/Index";
			this._httpContext.Response.Redirect(redirectUri);
			return Task.CompletedTask;
		}

		public Task ForbidAsync(AuthenticationProperties? properties)
		{
			Log("ForbidAsync");
			this._httpContext.Response.StatusCode = 403 ;
			return Task.CompletedTask;
		}

		

		private void Log(string actionName) 
		{
			Console.WriteLine($"typeof:{typeof(UrlTokenAuthenticationHandler)}:{actionName}");
			Console.WriteLine($"nameof:{nameof(UrlTokenAuthenticationHandler)}:{actionName}");
		}
	}
}
