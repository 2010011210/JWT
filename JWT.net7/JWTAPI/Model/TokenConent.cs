namespace JWTAPI.Model
{
	public class TokenConent
	{
		public string Token { get; set; }
		public string RefreshToken { get; set; }
		public string Scopes { get; set; }
	}
}
