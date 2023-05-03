using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
	public class TokenController : Controller
	{
		//[Authorize]
		public IActionResult Index()
		{
			return View();
		}

		[HttpPost]
		public ResultModel<TokenConent> Login(string name, string pwd)
		{
			var result = TokenHelper.IssueToken(name, pwd);
			if (result.IsNullOrEmpty()) 
			{
				return new ResultModel<TokenConent>() {Code="300", Message = "获取token失败" };
			}
			return JsonConvert.DeserializeObject<ResultModel<TokenConent>>(result);
		}

		[HttpPost]
		public ResultModel<TokenConent> RefreshToken(string refreshToken)
		{
            var result = TokenHelper.RefreshToken(refreshToken);
            if (result.IsNullOrEmpty())
            {
                return new ResultModel<TokenConent>() { Code = "300", Message = "刷新token失败" };
            }
            return JsonConvert.DeserializeObject<ResultModel<TokenConent>>(result);
        }

	}
}
