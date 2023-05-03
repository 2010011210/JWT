# JWT  
## 1.授权中心  
### 1.1  在Program类中注册授权服务为token, 并启用鉴权UseAuthentication()和授权UseAuthorization()中间件

```  符号在esc左下角
JWTOption tokenOptions = new JWTOption();
builder.Configuration.Bind("JWTOptions", tokenOptions);  // 加密码存放在配置文件中，应该放在数据库

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options =>
				{
					options.TokenValidationParameters = new TokenValidationParameters
					{
						//JWT有一些默认的属性，就是给鉴权时就可以筛选了
						ValidateIssuer = true,//是否验证Issuer
						ValidateAudience = true,//是否验证Audience
						ValidateLifetime = true,//是否验证失效时间
						ValidateIssuerSigningKey = true,//是否验证SecurityKey
						ClockSkew = TimeSpan.FromSeconds(0),    // token过期后立刻失效

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer，这两项和前面签发jwt的设置一致
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
					};

					options.Events = new JwtBearerEvents() 
					{
						OnChallenge = context => 
						{
							context.Response.Headers.Add("JWTChallenge","expired");
							return Task.CompletedTask;
						}
					};

				})
				;   
                   
                   app.UseAuthentication();    // authentication 鉴authenticate v.证明..是真实的;证实   
                   app.UseAuthorization();     // Authorization  批准；授权

                
```   
### 1.2 controller方法中带有Authorize特性的方法，没有授权，是无法访问的   
```   
/// <summary>
		/// 要求登陆后才能看到，没登陆是不能看的
		/// </summary>
		/// <returns></returns>
		[Authorize]//表明该Action需要鉴权通过---得有鉴权动作
		public IActionResult Info()
		{
			return View();
		}
```   

### 1.3 获取token   
```   
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

```

### 1.4  授权，比如必须Role是Admin的账户，才有权限访问   
```   
        [HttpPost]
		[Route("DeleteOrder")]
		[Authorize(Roles ="Admin")]   // 多个Role可以访问，用逗号建个，例如"Admin,Custom"
		public IActionResult DeleteOrder()
		{
			return new JsonResult(ResultModel.SetSuccess("删除订单成功"));
		}
```   

### 1.5 复杂授权策略，可以自定义   
```   
        [HttpPost]
		[Route("CopyOrder")]
		[Authorize(Policy = "ComplexPolicy")]
		public IActionResult CopyOrder()
		{
			return new JsonResult(ResultModel.SetSuccess("复制订单成功"));
		}

        // 在program.cs中注册复杂授权的policy   
        builder.Services.AddAuthorization(options =>
            options.AddPolicy("ComplexPolicy", policyBuilder =>
                policyBuilder.RequireRole("Admin")
                .RequireAssertion(context => 
                    context.User.HasClaim(c => c.Type == ClaimTypes.Email) && context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value.EndsWith("qq.com")
                    )
                )
        );


```  

# 二.前端调用   
### 2.1 钱多获取token，保存在前端的localStorage   
```   
$("#loginBtn").on("click",function(){
                $.ajax({
                    url:"/Token/Login",
                    type:"post",
                    data:{"name":"king","pwd":"123456"},
                    success:function(data){
                        if (data.data.token) {
                            console.log(data);
                            localStorage["token"] = data.data.token;
                            localStorage["refreshToken"] = data.data.refreshToken;
                        }
                    }
                });
            });

// 通过http请求颁发token的服务器
public static async Task<string> Post(string url, Dictionary<string,string> data) 
		{
			var response = await httpClient.PostAsync(url,new FormUrlEncodedContent(data));  // FormData是这个FormUrlEncodedContent，json是 new StringContent(
                                                                                             //    Newtonsoft.Json.JsonConvert.SerializeObject(new { Name = "小明", Id = 1 }),
                                                                                             //Encoding.UTF8,
                                                                                             //"application/json")


            var result = await response.Content.ReadAsStringAsync();
			return result;
		}

        
```   
### 2.2 前端访问接口，带上token .ajax是在beforeSend中，从 localStorage中取出token，放在header头中。
```   
    $("#authInfo").on("click", function () {
                $.ajax({
                    url: "/Auth/Info",
                    type: "post",
                    data: { "name": "king", "pwd": "123456" },
                    beforeSend:function(XHR)
                    {
                        XHR.setRequestHeader("Authorization","Bearer " + localStorage["token"]);
                    },
                    success: function (data) {
                        console.log(data);
                    }
                });
            });
```   

### 2.3 token过期，前端触发时间失败后，自动刷新token，刷新完后再触发时间调用后端接口。   
```   
/// 前端后端要配合使用，根据过期的请求头，判断是否需要刷新  
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options =>
				{
					options.TokenValidationParameters = new TokenValidationParameters
					{
						//JWT有一些默认的属性，就是给鉴权时就可以筛选了
						ValidateIssuer = true,//是否验证Issuer
						ValidateAudience = true,//是否验证Audience
						ValidateLifetime = true,//是否验证失效时间
						ValidateIssuerSigningKey = true,//是否验证SecurityKey
						ClockSkew = TimeSpan.FromSeconds(0),    // token过期后立刻失效

						ValidAudience = tokenOptions.Audience,//
						ValidIssuer = tokenOptions.Issuer,//Issuer，这两项和前面签发jwt的设置一致
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.SecurityKey))
					};

					options.Events = new JwtBearerEvents() 
					{
						OnChallenge = context => 
						{
							context.Response.Headers.Add("JWTChallenge","expired");
							return Task.CompletedTask;
						}
					};

				})

                
        // 前端js  
          $("#autoRefreshToken").on("click", function () {
                $.ajax({
                    url: "/Auth/Info",
                    type: "post",
                    data: { "name": "king", "pwd": "123456" },
                    beforeSend:function(XHR)
                    {
                        XHR.setRequestHeader("Authorization","Bearer " + localStorage["token"]);
                    },
                    success: function (data) {
                        console.log(data);
                    },
                    error: function(xhr, status, error){
                        console.log(status);
                        console.log(xhr.getAllResponseHeaders());
                        if(xhr.getAllResponseHeaders().indexOf("jwtchallenge: expired") > 0)
                        {
                            RefreshToken($("#autoRefreshToken"));
                        }
                    }
                });
            });

            function RefreshToken(callback)
        {
            $.ajax({
                    url: "/Token/RefreshToken",
                    type: "post",
                    data: { "refreshToken": localStorage["refreshToken"] },
                    beforeSend:function(XHR)
                    {
                        XHR.setRequestHeader("Authorization","Bearer " + localStorage["refreshToken"]);
                    },
                    success: function (data) {
                        if (data.data.token) {
                            localStorage["token"] = data.data.token;
                            localStorage["refreshToken"] = data.data.refreshToken;
                            callback.trigger("click");
                        }
                    }
                });
        
        }


```   

# 三，配置文件和swagger
### 3.1 配置文件   
```
{
  "AllowedHosts": "*",
  "JWTOptions": {
    "Audience": "http://localhost:7200",
    "Issuer": "http://localhost:7200",
    "SecurityKey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI2a2EJ7m872v0afyoSDJT2o1+SitIeJSWtLJU8/Wz2m7gStexajkeD+Lka6DSTy8gt9UwfgVQo6uKjVLG5Ex7PiGOODVqAEghBuS7JzIYU5RvI543nNDAPfnJsas96mSA7L/mD7RTE2drj6hf3oZjJpMPZUQI/B1Qjb5H3K3PNwIDAQAB"
  }
}   
```   

### 3.2 如果swagger要带token访问，需要再program中配置一下  
```  
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(options =>
{
	#region Swagger配置支持Token参数传递 
	options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
	{
		Description = "请输入token,格式为 Bearer jwtToken(注意中间必须有空格)",
		Name = "Authorization",
		In = ParameterLocation.Header,
		Type = SecuritySchemeType.ApiKey,
		BearerFormat = "JWT",
		Scheme = JwtBearerDefaults.AuthenticationScheme
	});//添加安全定义

	options.AddSecurityRequirement(new OpenApiSecurityRequirement {
				{   //添加安全要求
                    new OpenApiSecurityScheme
					{
						Reference =new OpenApiReference()
						{
							Type = ReferenceType.SecurityScheme,
							Id ="Bearer"
						}
					},
					new string[]{ }
				}
				});
	#endregion
}); 
```  










