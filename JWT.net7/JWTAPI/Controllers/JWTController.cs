using JWTAPI.Model;
using JWTAPI.Utility;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWTAPI.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class JWTController : Controller
	{
		//private JWTTokenService _JWTTokenService = new JWTTokenService();
		private JWTTokenService _JWTTokenService = null;
		public JWTController(JWTTokenService jWTTokenService)           // 依赖注入为何有问题？
		{
			this._JWTTokenService = jWTTokenService;
		}

		[HttpGet]
		[Route("GetToken")]
		public IActionResult GetToken(string name, string pwd)
		{
			if ("king".Equals(name) && "123456".Equals(pwd))
			{
				var token = this._JWTTokenService.GetToken(name);

				return new JsonResult(new
				{
					Result = true,
					Code = 200,
					Message = "",
					Token = token
				});
			} else 
			{
				return new JsonResult(new
				{
					Result = true,
					Code = 500,
					Message = "密码错误",
					Token = ""
				});
			}
			
		}

		[HttpPost]
		[Route("GetTokenWithRefreshToken")]
		public IActionResult GetTokenWithRefreshToken([FromForm] string name,[FromForm] string pwd)
		{
			if ("king".Equals(name) && "123456".Equals(pwd))
			{
				CurrentUserModel currentUserModel = new CurrentUserModel()
				{
					Id = 1,
					Name = "king",
					Account = "907465688",
					EMail= "1234556@qq.com",
					Sex = 1,
					Age = 32,
					Mobile = "13888866668",
					Role= "Admin"
				};

				var responseContent = this._JWTTokenService.GetTokenWithRefreshToken(currentUserModel);
				TokenConent tokenConent = new TokenConent()
				{
					Token = responseContent.Item1,
					RefreshToken = responseContent.Item2
				};

                return new JsonResult(ResultModel.SetSuccess(tokenConent));
			}
			else
			{
				return new JsonResult(new
				{
					Result = true,
					Code = 500,
					Message = "密码错误",
					Token = ""
				});
			}

		}

		[HttpPost]
		[Route("RefreshToken")]
		public async Task<string> RefreshToken([FromForm] string refreshToken)
		{
			await Task.CompletedTask;
			if (!refreshToken.ValidateRefreshToken()) 
			{
				return JsonConvert.SerializeObject(ResultModel.SetFail("", "1001", "RefreshToken过期"));
			}

			CurrentUserModel currentUserModel = new CurrentUserModel()
			{
				Id = 1,
				Name = "king",
				Account = "907465688",
				EMail = "1234556@qq.com",
				Sex = 1,
				Age = 32,
				Mobile = "13888866668",
				Role = "Admin"
			};

			var responseContent = this._JWTTokenService.RefreshToken(refreshToken);
            TokenConent tokenConent = new TokenConent()
            {
                Token = responseContent.Item1,
                RefreshToken = responseContent.Item2
            };
            if (string.IsNullOrEmpty(responseContent.Item1)) 
			{
				return JsonConvert.SerializeObject(ResultModel.SetFail("", "1001", "RefreshToken失败"));
			}
			return JsonConvert.SerializeObject(ResultModel.SetSuccess(tokenConent));
		}

	}
}
