using JWTAPI.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAPI.Controllers
{
	[ApiController]
	[Route("[controller]")]
	public class OrderController: Controller
	{
		[HttpGet]
		[Authorize]
		public IActionResult Order() 
		{
			return new JsonResult(ResultModel.SetSuccess("成功"));
		}

		[HttpPost]
		[Route("DeleteOrder")]
		[Authorize(Roles ="Admin")]
		public IActionResult DeleteOrder()
		{
			return new JsonResult(ResultModel.SetSuccess("删除订单成功"));
		}

		[HttpPost]
		[Route("ModifyOrder")]
		[Authorize(Roles = "Custom,Admin")]
		public IActionResult ModifyOrder()
		{
			return new JsonResult(ResultModel.SetSuccess("修改订单成功"));
		}

		[HttpPost]
		[Route("CopyOrder")]
		[Authorize(Policy = "ComplexPolicy")]
		public IActionResult CopyOrder()
		{
			return new JsonResult(ResultModel.SetSuccess("复制订单成功"));
		}
	}
}
