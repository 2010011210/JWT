using JWTAPI.Model;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic.FileIO;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAPI.Utility
{
	public class CurrentUserModel
	{
		public int Id { get; set; }
		public string Name { get; set; }
		public string Account { get; set; }
		public string Mobile { get; set; }
		public string EMail { get; set; }
		//public string Password { get; set; }
		public string Role { get; set; }
		public int Age { get; set; }
		/// <summary>
		/// 0女 1男
		/// </summary>
		public byte Sex { get; set; }
	}


	public class JWTTokenService : IJWTTokenService
	{
		private static Dictionary<string, CurrentUserModel> TokenCache = new Dictionary<string, CurrentUserModel>();

		private JWTOption _JWTTokenOption = null;

		public  JWTTokenService(IOptions<JWTOption> options) 
		{
			this._JWTTokenOption = options.Value;
		}
		public string GetToken(string name)
		{
			// 1.组装Claim
			var claims = new Claim[] 
			{
				new Claim(ClaimTypes.Name, name),
				new Claim(ClaimTypes.Email, "123434@qq.com"),
				new Claim(ClaimTypes.StreetAddress, "SiJing"),
				new Claim(ClaimTypes.Role, "Admin"),
				new Claim("Job", "Programmer")
			};

			// 2.密钥处理
			var secretKey = this._JWTTokenOption.SecurityKey;
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));  // 密码要从配置文件中读取，或者从数据库读取
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// 3.
			/**
             * Claims (Payload)
                Claims 部分包含了一些跟这个 token 有关的重要信息。 JWT 标准规定了一些字段，下面节选一些字段:
                iss: The issuer of the token，token 是给谁的
                sub: The subject of the token，token 主题
                exp: Expiration Time。 token 过期时间，Unix 时间戳格式
                iat: Issued At。 token 创建时间， Unix 时间戳格式
                jti: JWT ID。针对当前 token 的唯一标识
                除了规定的字段外，可以包含其他任何 JSON 兼容的字段。
             * */
			var token = new JwtSecurityToken(
				issuer: this._JWTTokenOption.Issuer,		 //this._JWTTokenOptions.Issuer,
				audience: this._JWTTokenOption.Audience,   //this._JWTTokenOptions.Audience,
				claims: claims,
				expires: DateTime.Now.AddSeconds(60 * 1),//10分钟有效期
				notBefore: DateTime.Now,//立即生效  DateTime.Now.AddMilliseconds(30),//30s后有效
				signingCredentials: creds);

			string returnToken = new JwtSecurityTokenHandler().WriteToken(token);
			return returnToken;
		}

		/// <summary>
		/// 获取token和refreshToken
		/// </summary>
		/// <param name="userModel"></param>
		/// <returns></returns>
		public Tuple<string, string> GetTokenWithRefreshToken(CurrentUserModel userModel) 
		{
			string token = this.IssueToken(userModel);
			string refreshToken = this.IssueToken(userModel, 60*60*24*7);
			TokenCache[refreshToken] = userModel;

			return Tuple.Create(token, refreshToken);
		}

		/// <summary>
		/// 获取token和refreshToken
		/// </summary>
		/// <param name="userModel"></param>
		/// <returns></returns>
		public Tuple<string, string> RefreshToken(string refreshToken)
		{
			if (TokenCache.TryGetValue(refreshToken, out CurrentUserModel userModel)) 
			{
				string token = this.IssueToken(userModel);
				string refreshTokenContent = this.IssueToken(userModel, 60 * 60 * 24 * 7);
				TokenCache[refreshToken] = userModel;
                return Tuple.Create(token, refreshToken);
            }
			return  Tuple.Create("", ""); ;
		}

		private string IssueToken(CurrentUserModel userModel, int second = 60)
		{
			var claims = new[]
			{
				   new Claim(ClaimTypes.Name, userModel.Name),
				   new Claim("EMail", userModel.EMail),
				   new Claim("Account", userModel.Account),
				   new Claim("Age", userModel.Age.ToString()),
				   new Claim("Id", userModel.Id.ToString()),
				   new Claim("Mobile", userModel.Mobile),
				   new Claim(ClaimTypes.Role,userModel.Role),
				   new Claim("Role", "Assistant"),//这个不能默认角色授权，动态角色授权
                   new Claim("Sex", userModel.Sex.ToString())//各种信息拼装
            };
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this._JWTTokenOption.SecurityKey));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
			/**
             * Claims (Payload)
                Claims 部分包含了一些跟这个 token 有关的重要信息。 JWT 标准规定了一些字段，下面节选一些字段:
                iss: The issuer of the token，token 是给谁的
                sub: The subject of the token，token 主题
                exp: Expiration Time。 token 过期时间，Unix 时间戳格式
                iat: Issued At。 token 创建时间， Unix 时间戳格式
                jti: JWT ID。针对当前 token 的唯一标识
                除了规定的字段外，可以包含其他任何 JSON 兼容的字段。
             * */
			var token = new JwtSecurityToken(
				issuer: this._JWTTokenOption.Issuer,
				audience: this._JWTTokenOption.Audience,
				claims: claims,
				expires: DateTime.Now.AddSeconds(second),//10分钟有效期
				notBefore: DateTime.Now,//立即生效  DateTime.Now.AddMilliseconds(30),//30s后有效
				signingCredentials: creds);
			string returnToken = new JwtSecurityTokenHandler().WriteToken(token);
			return returnToken;
		}


	}
}
