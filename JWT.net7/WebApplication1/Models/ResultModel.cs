namespace WebApplication1.Models
{
    public class ResultModel<T>
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
        public T Data { get; set; }

    }
}
