// {
//   "Jwt": {
//     "Secret": "your-access-token-secret-key-min-32-chars",
//     "RefreshSecret": "your-refresh-token-secret-key-different-from-access",
//     "Issuer": "your-api",
//     "Audience": "your-frontend-app"
//   }
// }

public class TokenService
{
    public async Task<TokenPair> CreateTokensFromGuid(string guidToken)
    {
        var tokenDetails = await GetTokenDetails(guidToken);

        // Create access token (short-lived)
        var accessToken = CreateAccessToken(tokenDetails);

        // Create refresh token with GUID embedded (long-lived)
        var refreshToken = CreateRefreshToken(new RefreshTokenPayload
        {
            OriginalGuidToken = guidToken,
            UserId = tokenDetails.UserId,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = tokenDetails.ExpiresAt
        });

        // NO STORAGE NEEDED! Token is self-contained

        return new TokenPair
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = 900
        };
    }

    public async Task<string> RefreshAccessToken(string refreshToken)
    {
        // 1. Validate JWT signature and expiration
        var payload = ValidateAndDecodeRefreshToken(refreshToken);

        // 2. Extract GUID from the claims
        var guidToken = payload.Claims
            .FirstOrDefault(c => c.Type == "guid_token")?.Value;

        // 3. Validate original GUID is still valid
        var tokenDetails = await GetTokenDetails(guidToken);

        if (tokenDetails.ExpiresAt <= DateTime.UtcNow)
            throw new TokenExpiredException();

        // 4. Create new access token
        return CreateAccessToken(tokenDetails);
    }

    private ClaimsPrincipal ValidateAndDecodeRefreshToken(string refreshToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:RefreshSecret"]);

        var principal = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = _configuration["Jwt:Audience"],
            ValidateLifetime = true, // This checks expiration automatically
            ClockSkew = TimeSpan.Zero
        }, out _);

        return principal;
    }
}