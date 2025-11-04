public class TokenService
{
    private readonly IDistributedCache _localCache;
    private readonly IDistributedCache _enterpriseCache;
    private readonly IIntrospectApi _introspectApi;
    private readonly IConfiguration _configuration;

    public async Task<TokenPair> CreateTokensFromGuid(string guidToken)
    {
        // 1. Validate GUID and get token details
        var tokenDetails = await GetTokenDetails(guidToken);

        if (tokenDetails.ExpiresAt <= DateTime.UtcNow)
            throw new TokenExpiredException("GUID token has expired");

        // 2. Create short-lived access token (JWT)
        var accessToken = CreateAccessToken(new TokenClaims
        {
            UserId = tokenDetails.UserId,
            Email = tokenDetails.Email,
            Roles = tokenDetails.Roles,
            Scopes = tokenDetails.Scopes,
            ExpiresAt = DateTime.UtcNow.AddMinutes(15) // Short-lived
        });

        // 3. Create long-lived refresh token with embedded GUID reference
        var refreshToken = CreateRefreshToken(new RefreshTokenPayload
        {
            OriginalGuidToken = guidToken,
            UserId = tokenDetails.UserId,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = tokenDetails.ExpiresAt // Same as GUID token
        });

        // 4. Store refresh token for revocation capability
        await StoreRefreshToken(refreshToken, guidToken, tokenDetails.ExpiresAt);

        return new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = 900, // 15 minutes in seconds
            RefreshExpiresIn = (int)(tokenDetails.ExpiresAt - DateTime.UtcNow).TotalSeconds
        };
    }

    private string CreateAccessToken(TokenClaims claims)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, claims.UserId),
                new Claim(ClaimTypes.Email, claims.Email),
                new Claim("token_type", "access")
            }),
            Expires = claims.ExpiresAt,
            SigningCredentials = credentials,
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        // Add roles
        foreach (var role in claims.Roles)
        {
            tokenDescriptor.Subject.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private string CreateRefreshToken(RefreshTokenPayload payload)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_configuration["Jwt:RefreshSecret"]));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("user_id", payload.UserId),
                new Claim("guid_token", payload.OriginalGuidToken), // Embed GUID
                new Claim("issued_at", payload.IssuedAt.ToString("o")),
                new Claim("token_type", "refresh")
            }),
            Expires = payload.ExpiresAt, // Same as GUID token expiration
            SigningCredentials = credentials,
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private async Task StoreRefreshToken(string refreshToken, string guidToken, DateTime expiresAt)
    {
        // Extract token ID (jti) or use hash of token
        var tokenId = ComputeTokenHash(refreshToken);

        var refreshTokenData = new RefreshTokenData
        {
            TokenHash = tokenId,
            GuidToken = guidToken,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            IsRevoked = false
        };

        // Store in your local cache/database
        await _localCache.SetStringAsync(
            $"refresh:{tokenId}",
            JsonSerializer.Serialize(refreshTokenData),
            new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = expiresAt
            }
        );
    }

    public async Task<TokenRefreshResult> RefreshAccessToken(string refreshToken)
    {
        // 1. Validate and decode refresh token
        var refreshPayload = ValidateAndDecodeRefreshToken(refreshToken);

        // 2. Check if refresh token is revoked
        var tokenId = ComputeTokenHash(refreshToken);
        var storedToken = await GetStoredRefreshToken(tokenId);

        if (storedToken == null)
            throw new InvalidRefreshTokenException("Refresh token not found");

        if (storedToken.IsRevoked)
            throw new InvalidRefreshTokenException("Refresh token has been revoked");

        // 3. Extract and validate original GUID token
        var guidToken = refreshPayload.Claims
            .FirstOrDefault(c => c.Type == "guid_token")?.Value;

        if (string.IsNullOrEmpty(guidToken))
            throw new InvalidRefreshTokenException("Invalid refresh token format");

        // 4. Re-validate GUID token is still valid
        TokenDetails tokenDetails;
        try
        {
            tokenDetails = await GetTokenDetails(guidToken);
        }
        catch (Exception ex)
        {
            // GUID token is no longer valid, revoke refresh token
            await RevokeRefreshToken(tokenId);
            throw new InvalidRefreshTokenException("Original token is no longer valid", ex);
        }

        if (tokenDetails.ExpiresAt <= DateTime.UtcNow)
        {
            await RevokeRefreshToken(tokenId);
            throw new TokenExpiredException("Original GUID token has expired");
        }

        // 5. Create new access token
        var newAccessToken = CreateAccessToken(new TokenClaims
        {
            UserId = tokenDetails.UserId,
            Email = tokenDetails.Email,
            Roles = tokenDetails.Roles,
            Scopes = tokenDetails.Scopes,
            ExpiresAt = DateTime.UtcNow.AddMinutes(15)
        });

        return new TokenRefreshResult
        {
            AccessToken = newAccessToken,
            RefreshToken = refreshToken, // Return same refresh token
            ExpiresIn = 900
        };
    }

    private ClaimsPrincipal ValidateAndDecodeRefreshToken(string refreshToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:RefreshSecret"]);

        try
        {
            var principal = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            // Verify it's a refresh token
            var tokenTypeClaim = principal.Claims
                .FirstOrDefault(c => c.Type == "token_type")?.Value;

            if (tokenTypeClaim != "refresh")
                throw new InvalidRefreshTokenException("Token is not a refresh token");

            return principal;
        }
        catch (Exception ex)
        {
            throw new InvalidRefreshTokenException("Invalid refresh token", ex);
        }
    }

    private async Task<TokenDetails> GetTokenDetails(string guidToken)
    {
        // Try enterprise cache first
        try
        {
            var cached = await _enterpriseCache.GetStringAsync(guidToken);
            if (!string.IsNullOrEmpty(cached))
            {
                return JsonSerializer.Deserialize<TokenDetails>(cached);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Enterprise cache unavailable for GUID {Guid}", guidToken);
        }

        // Fallback to introspect API
        var details = await _introspectApi.IntrospectAsync(guidToken);

        if (!details.Active)
            throw new TokenExpiredException("GUID token is not active");

        // Try to update cache (best effort)
        _ = Task.Run(async () =>
        {
            try
            {
                await _enterpriseCache.SetStringAsync(
                    guidToken,
                    JsonSerializer.Serialize(details),
                    new DistributedCacheEntryOptions
                    {
                        AbsoluteExpiration = details.ExpiresAt
                    }
                );
            }
            catch { /* Ignore cache update failures */ }
        });

        return details;
    }

    private async Task<RefreshTokenData> GetStoredRefreshToken(string tokenId)
    {
        var json = await _localCache.GetStringAsync($"refresh:{tokenId}");
        return string.IsNullOrEmpty(json)
            ? null
            : JsonSerializer.Deserialize<RefreshTokenData>(json);
    }

    private async Task RevokeRefreshToken(string tokenId)
    {
        var stored = await GetStoredRefreshToken(tokenId);
        if (stored != null)
        {
            stored.IsRevoked = true;
            await _localCache.SetStringAsync(
                $"refresh:{tokenId}",
                JsonSerializer.Serialize(stored),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpiration = stored.ExpiresAt
                }
            );
        }
    }

    private string ComputeTokenHash(string token)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hashBytes);
    }
}

// Supporting classes
public class TokenClaims
{
    public string UserId { get; set; }
    public string Email { get; set; }
    public List<string> Roles { get; set; }
    public List<string> Scopes { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class RefreshTokenPayload
{
    public string OriginalGuidToken { get; set; }
    public string UserId { get; set; }
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public class RefreshTokenData
{
    public string TokenHash { get; set; }
    public string GuidToken { get; set; }
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
}

public class TokenPair
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
    public int RefreshExpiresIn { get; set; }
}

public class TokenRefreshResult
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
}

public class TokenDetails
{
    public string UserId { get; set; }
    public string Email { get; set; }
    public List<string> Roles { get; set; }
    public List<string> Scopes { get; set; }
    public bool Active { get; set; }
    public DateTime ExpiresAt { get; set; }
}

// Controller
[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(TokenService tokenService, ILogger<AuthController> logger)
    {
        _tokenService = tokenService;
        _logger = logger;
    }

    [HttpPost("token")]
    [ProducesResponseType(typeof(TokenResponse), 200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<TokenResponse>> CreateToken([FromBody] TokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.GuidToken))
            return BadRequest(new { error = "invalid_request", error_description = "GUID token is required" });

        try
        {
            var tokens = await _tokenService.CreateTokensFromGuid(request.GuidToken);

            return Ok(new TokenResponse
            {
                AccessToken = tokens.AccessToken,
                RefreshToken = tokens.RefreshToken,
                TokenType = "Bearer",
                ExpiresIn = tokens.ExpiresIn,
                RefreshExpiresIn = tokens.RefreshExpiresIn
            });
        }
        catch (TokenExpiredException ex)
        {
            _logger.LogWarning(ex, "Expired GUID token: {Guid}", request.GuidToken);
            return Unauthorized(new { error = "token_expired", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating tokens from GUID");
            return StatusCode(500, new { error = "server_error", error_description = "An error occurred processing your request" });
        }
    }

    [HttpPost("refresh")]
    [ProducesResponseType(typeof(TokenResponse), 200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<ActionResult<TokenResponse>> RefreshToken([FromBody] RefreshRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "invalid_request", error_description = "Refresh token is required" });

        try
        {
            var result = await _tokenService.RefreshAccessToken(request.RefreshToken);

            return Ok(new TokenResponse
            {
                AccessToken = result.AccessToken,
                RefreshToken = result.RefreshToken,
                TokenType = "Bearer",
                ExpiresIn = result.ExpiresIn
            });
        }
        catch (InvalidRefreshTokenException ex)
        {
            _logger.LogWarning(ex, "Invalid refresh token attempt");
            return Unauthorized(new { error = "invalid_grant", error_description = ex.Message });
        }
        catch (TokenExpiredException ex)
        {
            _logger.LogWarning(ex, "Expired token during refresh");
            return Unauthorized(new { error = "token_expired", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing token");
            return StatusCode(500, new { error = "server_error", error_description = "An error occurred processing your request" });
        }
    }

    [HttpPost("revoke")]
    [Authorize]
    [ProducesResponseType(200)]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeRequest request)
    {
        // Implementation for token revocation
        return Ok();
    }
}

public class TokenRequest
{
    public string GuidToken { get; set; }
}

public class RefreshRequest
{
    public string RefreshToken { get; set; }
}

public class RevokeRequest
{
    public string RefreshToken { get; set; }
}

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_expires_in")]
    public int? RefreshExpiresIn { get; set; }
}