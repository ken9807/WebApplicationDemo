using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WebApplicationDemo.Models;
using WebApplicationDemo.Services;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ------------------- 讀取 JWT Key -------------------
string jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? string.Empty;

// 開發環境 fallback
if (string.IsNullOrWhiteSpace(jwtKey))
{
    if (builder.Environment.IsDevelopment())
    {
        jwtKey = "DevFallbackKey_MustBeAtLeast32BytesLong!!"; // 開發使用
        Console.WriteLine("⚠️ Using development fallback JWT key");
    }
    else
    {
        throw new Exception("JWT_KEY environment variable not set or too short (min 32 chars) in production!");
    }
}

// 確保 Key 足夠長
if (jwtKey.Length < 32)
    throw new Exception("JWT key too short, must be at least 32 characters");
else
    builder.Configuration["Jwt:Key"] = jwtKey;

// ------------------- 讀取 Issuer / Audience -------------------
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "DemoIssuer";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "DemoAudience";

// ------------------- Swagger -------------------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "JWT Demo API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "請輸入 JWT Token: Bearer {token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

// ------------------- JWT 驗證 -------------------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

// ------------------- 其他服務 -------------------
// 這裡用建構式注入將 Key / Issuer / Audience 傳給 JwtService
builder.Services.AddSingleton<IJwtService>(new JwtService(jwtKey, jwtIssuer, jwtAudience));

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

// ------------------- Middleware -------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "JWT Demo API V1"));
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();
