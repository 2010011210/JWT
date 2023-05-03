using WebApplication1.Utility;

namespace WebApplication1.Models
{
	public class TokenHelper
	{
		private const string tokenUrl = "http://localhost:5084/JWT/";
		/// <summary>
		/// 
		/// </summary>
		/// <param name="name"></param>
		/// <param name="pwd"></param>
		/// <returns></returns>
		public static string IssueToken(string name, string pwd) 
		{
			var param = new Dictionary<string, string>() 
			{
				{ "name",name},
				{ "pwd", pwd},
			};
			var response = HttpClientUtility.Post($"{tokenUrl}GetTokenWithRefreshToken", param);

			return response.Result;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="name"></param>
		/// <param name="pwd"></param>
		/// <returns></returns>
		public static string RefreshToken(string refreshToken)
		{
			var param = new Dictionary<string, string>()
			{
				{ "refreshToken",refreshToken},
			};
			var response = HttpClientUtility.Post($"{tokenUrl}RefreshToken", param);

			return response.Result;
		}

	}
}
