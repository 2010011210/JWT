namespace JWTAPI.Model
{
	public class ResultModel
	{
		/// <summary>
		/// 是否成功
		/// </summary>
		public bool Success { get; set; }

		/// <summary>
		/// 200为成功，其他为失败
		/// </summary>
		public string Code { get; set; }

		/// <summary>
		/// 失败消息
		/// </summary>
		public string Message { get; set; }

		/// <summary>
		/// 报文内容
		/// </summary>
		public object Data { get; set; }

		public static ResultModel SetSuccess(object data)
		{ 
			return new ResultModel { Success = true, Code = "200", Data= data };
		}

		public static ResultModel SetFail(object data, string code, string message)
		{
			return new ResultModel { Success = false, Code = code, Data = data };
		}




	}

	
}
