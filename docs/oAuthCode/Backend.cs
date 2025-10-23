namespace YourAPI.Models
{
    public class TokenClaims
    {
        public string UserId { get; set; }
        public string SponsorId { get; set; }
        public string SubscriberId { get; set; }
        public string[] Roles { get; set; }
        public List<string> Permissions { get; set; }
        public Dictionary<string, string> AdditionalClaims { get; set; }
        public DateTime IssuedAt { get; set; }
        public DateTime ValidUntil { get; set; }
    }
}

namespace YourAPI.Models
{
    public class RefreshTokenData
    {
        public string UserId { get; set; }
        public string SponsorId { get; set; }
        public string SubscriberId { get; set; }
        public string RefreshToken { get; set; }
        public string[] Roles { get; set; }
        public List<string> Permissions { get; set; }
        public Dictionary<string, string> AdditionalClaims { get; set; }
        public DateTime MaxValidUntil { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}

//using System.ComponentModel.DataAnnotations;

namespace YourAPI.Models
{
    public class AuthenticateRequest
    {
        [Required]
        public string Token { get; set; }
    }
}

namespace YourAPI.Models
{
    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public DateTime SessionExpiresAt { get; set; }
        public List<string> Permissions { get; set; }
        public string SponsorId { get; set; }
        public string SubscriberId { get; set; }
        public string TokenType { get; set; } = "Bearer";
    }

    public class SessionInfoResponse
    {
        public int RemainingSeconds { get; set; }
        public DateTime ExpiresAt { get; set; }
        public List<string> Permissions { get; set; }
        public string SponsorId { get; set; }
        public string SubscriberId { get; set; }
    }

    public class SponsorSessionsResponse
    {
        public string SponsorId { get; set; }
        public int ActiveSessionCount { get; set; }
        public List<SessionDetail> Sessions { get; set; }
    }

    public class SessionDetail
    {
        public string SubscriberId { get; set; }
        public string UserId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public List<string> Permissions { get; set; }
    }
}

// using YourAPI.Models;

namespace YourAPI.Services
{
    public interface ITokenService
    {
        Task<TokenClaims> ValidateAndConsumeInitialToken(string token);
        string GenerateAccessToken(TokenClaims claims, DateTime maxValidUntil);
        string GenerateRefreshToken();
        Task StoreRefreshToken(TokenClaims claims, string refreshToken);
        Task<TokenClaims> ValidateAndGetClaimsFromRefreshToken(string refreshToken);
        Task<RefreshTokenData> GetRefreshTokenData(string sponsorId, string subscriberId);
        Task RevokeRefreshToken(string sponsorId, string subscriberId);
        Task RevokeRefreshTokenByValue(string refreshToken);
        Task<List<RefreshTokenData>> GetAllSessionsForSponsor(string sponsorId);
        Task RevokeAllSessionsForSponsor(string sponsorId);
        Task<TimeSpan?> GetRemainingSessionTime(string sponsorId, string subscriberId);
    }
}

// using Microsoft.IdentityModel.Tokens;
// using StackExchange.Redis;
// using System.IdentityModel.Tokens.Jwt;
// using System.Security.Claims;
// using System.Security.Cryptography;
// using System.Text;
// using System.Text.Json;
// using YourAPI.Models;

// Implementation


namespace YourAPI.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConnectionMultiplexer _redis;
        private readonly IConfiguration _configuration;
        private readonly string _jwtSecret;
        private readonly string _jwtIssuer;
        private readonly string _refreshTokenSecretKey;
        private readonly ILogger<TokenService> _logger;

        public TokenService(
            IConnectionMultiplexer redis,
            IConfiguration configuration,
            ILogger<TokenService> logger)
        {
            _redis = redis;
            _configuration = configuration;
            _jwtSecret = configuration["Jwt:Secret"]
                ?? throw new ArgumentNullException("Jwt:Secret configuration is missing");
            _jwtIssuer = configuration["Jwt:Issuer"]
                ?? throw new ArgumentNullException("Jwt:Issuer configuration is missing");
            _refreshTokenSecretKey = configuration["RefreshToken:SecretKey"] ?? "RT";
            _logger = logger;
        }

        public async Task<TokenClaims> ValidateAndConsumeInitialToken(string token)
        {
            var db = _redis.GetDatabase();
            var claimsJson = await db.StringGetAsync(token);

            if (claimsJson.IsNullOrEmpty)
            {
                _logger.LogWarning("Invalid or expired initial token attempted");
                throw new UnauthorizedAccessException("Invalid or expired token");
            }

            var claims = JsonSerializer.Deserialize<TokenClaims>(claimsJson);

            if (claims == null)
            {
                _logger.LogError("Failed to deserialize token claims");
                throw new UnauthorizedAccessException("Invalid token format");
            }

            // Validate required fields
            if (string.IsNullOrEmpty(claims.SponsorId) || string.IsNullOrEmpty(claims.SubscriberId))
            {
                _logger.LogWarning("Token missing sponsor or subscriber information");
                throw new UnauthorizedAccessException("Invalid token: missing sponsor or subscriber information");
            }

            // Check expiration
            if (claims.ValidUntil < DateTime.UtcNow)
            {
                await db.KeyDeleteAsync(token);
                _logger.LogWarning("Expired token attempted for Sponsor: {SponsorId}, Subscriber: {SubscriberId}",
                    claims.SponsorId, claims.SubscriberId);
                throw new UnauthorizedAccessException("Token has expired");
            }

            // Delete original token after first use (one-time use)
            await db.KeyDeleteAsync(token);

            _logger.LogInformation("Initial token validated and consumed for User: {UserId}, Sponsor: {SponsorId}, Subscriber: {SubscriberId}",
                claims.UserId, claims.SponsorId, claims.SubscriberId);

            return claims;
        }

        public string GenerateAccessToken(TokenClaims claims, DateTime maxValidUntil)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSecret);

            // Access token expires in 15 minutes OR when session ends (whichever is sooner)
            var accessTokenExpiry = DateTime.UtcNow.AddMinutes(15);
            if (accessTokenExpiry > maxValidUntil)
            {
                accessTokenExpiry = maxValidUntil;
            }

            // Build claims list
            var claimsList = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, claims.UserId),
                new Claim("sponsor_id", claims.SponsorId),
                new Claim("subscriber_id", claims.SubscriberId),
                new Claim(ClaimTypes.Role, string.Join(",", claims.Roles ?? Array.Empty<string>())),
                new Claim("max_valid_until", maxValidUntil.ToString("o"))
            };

            // Add permissions as claims
            foreach (var permission in claims.Permissions ?? new List<string>())
            {
                claimsList.Add(new Claim("permission", permission));
            }

            // Add additional claims
            if (claims.AdditionalClaims != null)
            {
                foreach (var kvp in claims.AdditionalClaims)
                {
                    claimsList.Add(new Claim(kvp.Key, kvp.Value));
                }
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claimsList),
                Expires = accessTokenExpiry,
                Issuer = _jwtIssuer,
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        private string BuildRefreshTokenKey(string sponsorId, string subscriberId)
        {
            return $"{_refreshTokenSecretKey}:{sponsorId}:{subscriberId}";
        }

        public async Task StoreRefreshToken(TokenClaims claims, string refreshToken)
        {
            var db = _redis.GetDatabase();

            var key = BuildRefreshTokenKey(claims.SponsorId, claims.SubscriberId);

            var refreshTokenData = new RefreshTokenData
            {
                UserId = claims.UserId,
                SponsorId = claims.SponsorId,
                SubscriberId = claims.SubscriberId,
                RefreshToken = refreshToken,
                Roles = claims.Roles,
                Permissions = claims.Permissions,
                AdditionalClaims = claims.AdditionalClaims,
                MaxValidUntil = claims.ValidUntil,
                CreatedAt = DateTime.UtcNow
            };

            var refreshTokenJson = JsonSerializer.Serialize(refreshTokenData);

            var timeUntilExpiry = claims.ValidUntil - DateTime.UtcNow;

            if (timeUntilExpiry.TotalSeconds <= 0)
            {
                throw new UnauthorizedAccessException("Original token has expired");
            }

            await db.StringSetAsync(key, refreshTokenJson, timeUntilExpiry);

            _logger.LogInformation("Refresh token stored for Sponsor: {SponsorId}, Subscriber: {SubscriberId}, Expires: {ExpiresAt}",
                claims.SponsorId, claims.SubscriberId, claims.ValidUntil);
        }

        public async Task<TokenClaims> ValidateAndGetClaimsFromRefreshToken(string refreshToken)
        {
            var db = _redis.GetDatabase();
            var server = _redis.GetServer(_redis.GetEndPoints().First());

            var pattern = $"{_refreshTokenSecretKey}:*";

            await foreach (var key in server.KeysAsync(pattern: pattern))
            {
                var storedDataJson = await db.StringGetAsync(key);
                if (storedDataJson.IsNullOrEmpty) continue;

                var storedData = JsonSerializer.Deserialize<RefreshTokenData>(storedDataJson);

                if (storedData?.RefreshToken == refreshToken)
                {
                    if (storedData.MaxValidUntil < DateTime.UtcNow)
                    {
                        await db.KeyDeleteAsync(key);
                        _logger.LogWarning("Expired refresh token attempted for Sponsor: {SponsorId}, Subscriber: {SubscriberId}",
                            storedData.SponsorId, storedData.SubscriberId);
                        throw new UnauthorizedAccessException("Session has expired");
                    }

                    var claims = new TokenClaims
                    {
                        UserId = storedData.UserId,
                        SponsorId = storedData.SponsorId,
                        SubscriberId = storedData.SubscriberId,
                        Roles = storedData.Roles,
                        Permissions = storedData.Permissions,
                        AdditionalClaims = storedData.AdditionalClaims,
                        ValidUntil = storedData.MaxValidUntil
                    };

                    return claims;
                }
            }

            _logger.LogWarning("Invalid refresh token attempted");
            throw new UnauthorizedAccessException("Invalid refresh token");
        }

        public async Task<RefreshTokenData> GetRefreshTokenData(string sponsorId, string subscriberId)
        {
            var db = _redis.GetDatabase();
            var key = BuildRefreshTokenKey(sponsorId, subscriberId);

            var dataJson = await db.StringGetAsync(key);
            if (dataJson.IsNullOrEmpty)
            {
                return null;
            }

            return JsonSerializer.Deserialize<RefreshTokenData>(dataJson);
        }

        public async Task RevokeRefreshToken(string sponsorId, string subscriberId)
        {
            var db = _redis.GetDatabase();
            var key = BuildRefreshTokenKey(sponsorId, subscriberId);

            await db.KeyDeleteAsync(key);
            _logger.LogInformation("Refresh token revoked for Sponsor: {SponsorId}, Subscriber: {SubscriberId}",
                sponsorId, subscriberId);
        }

        public async Task RevokeRefreshTokenByValue(string refreshToken)
        {
            var db = _redis.GetDatabase();
            var server = _redis.GetServer(_redis.GetEndPoints().First());

            var pattern = $"{_refreshTokenSecretKey}:*";

            await foreach (var key in server.KeysAsync(pattern: pattern))
            {
                var dataJson = await db.StringGetAsync(key);
                if (dataJson.IsNullOrEmpty) continue;

                var data = JsonSerializer.Deserialize<RefreshTokenData>(dataJson);
                if (data?.RefreshToken == refreshToken)
                {
                    await db.KeyDeleteAsync(key);
                    _logger.LogInformation("Refresh token revoked by value for Sponsor: {SponsorId}, Subscriber: {SubscriberId}",
                        data.SponsorId, data.SubscriberId);
                    return;
                }
            }
        }

        public async Task<List<RefreshTokenData>> GetAllSessionsForSponsor(string sponsorId)
        {
            var db = _redis.GetDatabase();
            var server = _redis.GetServer(_redis.GetEndPoints().First());

            var pattern = $"{_refreshTokenSecretKey}:{sponsorId}:*";
            var sessions = new List<RefreshTokenData>();

            await foreach (var key in server.KeysAsync(pattern: pattern))
            {
                var dataJson = await db.StringGetAsync(key);
                if (!dataJson.IsNullOrEmpty)
                {
                    var data = JsonSerializer.Deserialize<RefreshTokenData>(dataJson);
                    if (data != null)
                    {
                        sessions.Add(data);
                    }
                }
            }

            return sessions;
        }

        public async Task RevokeAllSessionsForSponsor(string sponsorId)
        {
            var db = _redis.GetDatabase();
            var server = _redis.GetServer(_redis.GetEndPoints().First());

            var pattern = $"{_refreshTokenSecretKey}:{sponsorId}:*";
            var count = 0;

            await foreach (var key in server.KeysAsync(pattern: pattern))
            {
                await db.KeyDeleteAsync(key);
                count++;
            }

            _logger.LogWarning("All sessions revoked for Sponsor: {SponsorId}, Count: {Count}", sponsorId, count);
        }

        public async Task<TimeSpan?> GetRemainingSessionTime(string sponsorId, string subscriberId)
        {
            var data = await GetRefreshTokenData(sponsorId, subscriberId);
            if (data == null) return null;

            var remaining = data.MaxValidUntil - DateTime.UtcNow;
            return remaining.TotalSeconds > 0 ? remaining : null;
        }
    }
}

// using Microsoft.AspNetCore.Authorization;

namespace YourAPI.Authorization
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }
}


// using Microsoft.AspNetCore.Authorization;

namespace YourAPI.Authorization
{
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            PermissionRequirement requirement)
        {
            var permissions = context.User.FindAll("permission").Select(c => c.Value);

            if (permissions.Contains(requirement.Permission))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}

// using System.Net;
// using System.Text.Json;

namespace YourAPI.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized access attempt");
                await HandleExceptionAsync(context, ex, HttpStatusCode.Unauthorized);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unhandled exception occurred");
                await HandleExceptionAsync(context, ex, HttpStatusCode.InternalServerError);
            }
        }

        private static Task HandleExceptionAsync(HttpContext context, Exception exception, HttpStatusCode statusCode)
        {
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)statusCode;

            var response = new
            {
                message = exception.Message,
                statusCode = (int)statusCode
            };

            return context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}

// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;
// using System.Security.Claims;
// using YourAPI.Models;
// using YourAPI.Services;

namespace YourAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ITokenService tokenService, ILogger<AuthController> logger)
        {
            _tokenService = tokenService;
            _logger = logger;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] AuthenticateRequest request)
        {
            try
            {
                var claims = await _tokenService.ValidateAndConsumeInitialToken(request.Token);

                _logger.LogInformation(
                    "User {UserId} authenticated for Sponsor {SponsorId}, Subscriber {SubscriberId} with permissions: {Permissions}",
                    claims.UserId,
                    claims.SponsorId,
                    claims.SubscriberId,
                    string.Join(", ", claims.Permissions ?? new List<string>())
                );

                var refreshToken = _tokenService.GenerateRefreshToken();
                await _tokenService.StoreRefreshToken(claims, refreshToken);

                var accessToken = _tokenService.GenerateAccessToken(claims, claims.ValidUntil);

                var expiresIn = (int)Math.Min(
                    900,
                    (claims.ValidUntil - DateTime.UtcNow).TotalSeconds
                );

                Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = claims.ValidUntil
                });

                return Ok(new TokenResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiresIn = expiresIn,
                    SessionExpiresAt = claims.ValidUntil,
                    Permissions = claims.Permissions,
                    SponsorId = claims.SponsorId,
                    SubscriberId = claims.SubscriberId
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning("Authentication failed: {Message}", ex.Message);
                return Unauthorized(new { message = ex.Message });
            }
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"]
                    ?? Request.Headers["X-Refresh-Token"].ToString();

                if (string.IsNullOrEmpty(refreshToken))
                {
                    return Unauthorized(new { message = "Refresh token not provided" });
                }

                var claims = await _tokenService.ValidateAndGetClaimsFromRefreshToken(refreshToken);

                _logger.LogInformation(
                    "Access token refreshed for Sponsor {SponsorId}, Subscriber {SubscriberId}",
                    claims.SponsorId,
                    claims.SubscriberId
                );

                var accessToken = _tokenService.GenerateAccessToken(claims, claims.ValidUntil);

                var expiresIn = (int)Math.Min(
                    900,
                    (claims.ValidUntil - DateTime.UtcNow).TotalSeconds
                );

                return Ok(new TokenResponse
                {
                    AccessToken = accessToken,
                    ExpiresIn = expiresIn,
                    SessionExpiresAt = claims.ValidUntil,
                    Permissions = claims.Permissions,
                    SponsorId = claims.SponsorId,
                    SubscriberId = claims.SubscriberId
                });
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning("Token refresh failed: {Message}", ex.Message);
                Response.Cookies.Delete("refreshToken");
                return Unauthorized(new { message = ex.Message });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var sponsorId = User.FindFirst("sponsor_id")?.Value;
                var subscriberId = User.FindFirst("subscriber_id")?.Value;

                if (!string.IsNullOrEmpty(sponsorId) && !string.IsNullOrEmpty(subscriberId))
                {
                    await _tokenService.RevokeRefreshToken(sponsorId, subscriberId);
                    _logger.LogInformation(
                        "User logged out: Sponsor {SponsorId}, Subscriber {SubscriberId}",
                        sponsorId,
                        subscriberId
                    );
                }

                Response.Cookies.Delete("refreshToken");

                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Logout failed");
                return StatusCode(500, new { message = "Logout failed" });
            }
        }

        [HttpGet("session-info")]
        [Authorize]
        public async Task<IActionResult> GetSessionInfo()
        {
            try
            {
                var sponsorId = User.FindFirst("sponsor_id")?.Value;
                var subscriberId = User.FindFirst("subscriber_id")?.Value;

                if (string.IsNullOrEmpty(sponsorId) || string.IsNullOrEmpty(subscriberId))
                {
                    return Unauthorized(new { message = "Invalid session" });
                }

                var remainingTime = await _tokenService.GetRemainingSessionTime(sponsorId, subscriberId);

                if (!remainingTime.HasValue)
                {
                    return Unauthorized(new { message = "Session expired" });
                }

                var permissions = User.FindAll("permission").Select(c => c.Value).ToList();

                return Ok(new SessionInfoResponse
                {
                    RemainingSeconds = (int)remainingTime.Value.TotalSeconds,
                    ExpiresAt = DateTime.UtcNow.Add(remainingTime.Value),
                    Permissions = permissions,
                    SponsorId = sponsorId,
                    SubscriberId = subscriberId
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get session info");
                return StatusCode(500, new { message = "Failed to retrieve session info" });
            }
        }

        [HttpGet("admin/sponsor/{sponsorId}/sessions")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetSponsorSessions(string sponsorId)
        {
            try
            {
                var sessions = await _tokenService.GetAllSessionsForSponsor(sponsorId);

                return Ok(new SponsorSessionsResponse
                {
                    SponsorId = sponsorId,
                    ActiveSessionCount = sessions.Count,
                    Sessions = sessions.Select(s => new SessionDetail
                    {
                        SubscriberId = s.SubscriberId,
                        UserId = s.UserId,
                        CreatedAt = s.CreatedAt,
                        ExpiresAt = s.MaxValidUntil,
                        Permissions = s.Permissions
                    }).ToList()
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get sponsor sessions");
                return StatusCode(500, new { message = "Failed to retrieve sessions" });
            }
        }

        [HttpPost("admin/sponsor/{sponsorId}/revoke-all")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> RevokeSponsorSessions(string sponsorId)
        {
            try
            {
                await _tokenService.RevokeAllSessionsForSponsor(sponsorId);

                _logger.LogWarning("All sessions revoked for Sponsor {SponsorId}", sponsorId);

                return Ok(new { message = $"All sessions revoked for sponsor {sponsorId}" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to revoke sponsor sessions");
                return StatusCode(500, new { message = "Failed to revoke sessions" });
            }
        }
    }
}

// Program.cs

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.Text;
using YourAPI.Authorization;
using YourAPI.Middleware;
using YourAPI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Redis Configuration
var redisConnection = builder.Configuration.GetConnectionString("Redis")
    ?? "localhost:6379";
builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(redisConnection)
);

// JWT Authentication
var jwtSecret = builder.Configuration["Jwt:Secret"]
    ?? throw new InvalidOperationException("JWT Secret is not configured");
var jwtIssuer = builder.Configuration["Jwt:Issuer"]
    ?? throw new InvalidOperationException("JWT Issuer is not configured");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSecret)),
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

// Authorization Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CanAccessDashboard", policy =>
        policy.Requirements.Add(new PermissionRequirement("CanAccessDashboard")));

    options.AddPolicy("CanViewReports", policy =>
        policy.Requirements.Add(new PermissionRequirement("CanViewReports")));

    options.AddPolicy("CanEditSettings", policy =>
        policy.Requirements.Add(new PermissionRequirement("CanEditSettings")));
});

builder.Services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

// Register Services
builder.Services.AddScoped<ITokenService, TokenService>();

// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://localhost:5173") // React dev servers
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseMiddleware<ExceptionHandlingMiddleware>();

app.UseHttpsRedirection();

app.UseCors("AllowFrontend");

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();

// ### 13. appsettings.json
// ```json
// {
//   "Logging": {
//     "LogLevel": {
//       "Default": "Information",
//       "Microsoft.AspNetCore": "Warning"
//     }
//   },
//   "AllowedHosts": "*",
//   "ConnectionStrings": {
//     "Redis": "localhost:6379"
//   },
//   "Jwt": {
//     "Secret": "your-secret-key-must-be-at-least-32-characters-long-for-security",
//     "Issuer": "YourAPI"
//   },
//   "RefreshToken": {
//     "SecretKey": "RT"
//   }
// }
// ```

// ### 14. appsettings.Development.json
// ```json
// {
//   "Logging": {
//     "LogLevel": {
//       "Default": "Debug",
//       "Microsoft.AspNetCore": "Warning"
//     }
//   },
//   "ConnectionStrings": {
//     "Redis": "localhost:6379"
//   }
// }
// ```

// ### 15. YourAPI.csproj (Package References)
// ```xml
// <Project Sdk="Microsoft.NET.Sdk.Web">

//   <PropertyGroup>
//     <TargetFramework>net8.0</TargetFramework>
//     <Nullable>enable</Nullable>
//     <ImplicitUsings>enable</ImplicitUsings>
//   </PropertyGroup>

//   <ItemGroup>
//     <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
//     <PackageReference Include="StackExchange.Redis" Version="2.7.10" />
//     <PackageReference Include="Swashbuckle.AspNetCore" Version="6.5.0" />
//     <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.3" />
//   </ItemGroup>

// </Project>