using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace WebApplication1.Models
{
	/// <summary>
	/// IAuthorizationRequirement接口标识
	/// </summary>
	public class MultiEmailRequirement : IAuthorizationRequirement
	{
	}

	public class QQEmailHandler : AuthorizationHandler<MultiEmailRequirement>
	{
		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MultiEmailRequirement requirement)
		{
			if (context.User != null && context.User.HasClaim(c => c.Type == ClaimTypes.Email)) 
			{
				var emailList = context.User.FindAll(c => c.Type == ClaimTypes.Email);  //支持多Scheme
				if (emailList.Any(c => c.Value.EndsWith("@qq.com", StringComparison.OrdinalIgnoreCase)))
				{
					context.Succeed(requirement);
				}
				else {
					//context.Fail();//不设置失败 交给其他处理
				}
			}
			return Task.CompletedTask;
		}
	}

	public class NetEasyHandler : AuthorizationHandler<MultiEmailRequirement>
	{
		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MultiEmailRequirement requirement)
		{
			if (context.User != null && context.User.HasClaim(c => c.Type == ClaimTypes.Email))
			{
				var emailList = context.User.FindAll(c => c.Type == ClaimTypes.Email);  //支持多Scheme
				if (emailList.Any(c => c.Value.EndsWith("@163.com", StringComparison.OrdinalIgnoreCase)))
				{
					context.Succeed(requirement);
				}
				else
				{
					//context.Fail();//不设置失败 交给其他处理
				}
			}
			return Task.CompletedTask;
		}
	}
}
