using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Domain.Entities;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Services;

/// <summary>
/// JWT Service: Handles JWT token generation, validation, and management
/// Implements IJwtGenerator interface from Application layer
/// Provides secure token operations with configurable settings
/// Thread-safe implementation for concurrent access
/// </summary>
public class JwtService : IJwtGenerator
{
    private readonly JwtConfiguration _jwtConfig;
    private readonly TokenBlacklistService _blacklistService;
    private readonly ILogger<JwtService> _logger;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SigningCredentials _signingCredentials;
    private readonly TokenValidationParameters _tokenValidationParameters;

    /// <summary>
    /// Constructor: Initializes JWT service with configuration and dependencies
    /// Sets up token handler, signing credentials, and validation parameters
    /// Validates configuration on startup for security
    /// </summary>
    public JwtService(
        IOptions<JwtConfiguration> jwtOptions,
        TokenBlacklistService blacklistService,
        ILogger<JwtService> logger)
    {
        _jwtConfig = jwtOptions.Value;
        _blacklistService = blacklistService;
        _logger = logger;
        _tokenHandler = new JwtSecurityTokenHandler();

        // Validate configuration on startup
        _jwtConfig.Validate();

        // Setup signing credentials
        _signingCredentials = CreateSigningCredentials();

        // Setup token validation parameters
        _tokenValidationParameters = CreateTokenValidationParameters();

        _logger.LogInformation("JWT Service initialized with algorithm: {Algorithm}, " +
            "Access token expiration: {AccessExpiration}, Refresh token expiration: {RefreshExpiration}",
            _jwtConfig.Algorithm, _jwtConfig.AccessTokenExpiration, _jwtConfig.RefreshTokenExpiration);
    }

    /// <summary>
    /// Generates JWT access token with user claims, roles, and permissions
    /// Creates short-lived token for API access
    /// Includes security claims and custom user information
    /// </summary>
    public async Task<string> GenerateAccessTokenAsync(User user, IEnumerable<string> roles, IEnumerable<string> permissions)
    {
        try
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var now = DateTime.UtcNow;
            var expiration = now.Add(_jwtConfig.AccessTokenExpiration);

            // Create claims for the token
            var claims = new List<Claim>
            {
                // Standard JWT claims
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new(JwtRegisteredClaimNames.Exp, new DateTimeOffset(expiration).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),

                // Custom user claims
                new($"{_jwtConfig.ClaimsPrefix}user_id", user.Id.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}username", user.Username),
                new($"{_jwtConfig.ClaimsPrefix}email", user.Email),
                new($"{_jwtConfig.ClaimsPrefix}email_confirmed", user.EmailConfirmed.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}two_factor_enabled", user.TwoFactorEnabled.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}security_stamp", user.SecurityStamp ?? string.Empty),
                new($"{_jwtConfig.ClaimsPrefix}token_type", "access")
            };

            // Add optional user information
            // Note: FirstName and LastName are not currently in the User entity
            // They can be added later if needed

            if (user.PhoneNumberConfirmed && !string.IsNullOrEmpty(user.PhoneNumber))
                claims.Add(new($"{_jwtConfig.ClaimsPrefix}phone", user.PhoneNumber));

            // Add role claims
            foreach (var role in roles)
            {
                claims.Add(new(ClaimTypes.Role, role));
                claims.Add(new($"{_jwtConfig.ClaimsPrefix}role", role));
            }

            // Add permission claims
            foreach (var permission in permissions)
            {
                claims.Add(new($"{_jwtConfig.ClaimsPrefix}permission", permission));
            }

            // Create token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiration,
                Issuer = _jwtConfig.Issuer,
                Audience = _jwtConfig.Audience,
                SigningCredentials = _signingCredentials
            };

            // Generate token
            var token = _tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = _tokenHandler.WriteToken(token);

            _logger.LogDebug("Access token generated successfully for user {UserId} with {RoleCount} roles and {PermissionCount} permissions",
                user.Id, roles.Count(), permissions.Count());

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while generating access token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Generates refresh token for obtaining new access tokens
    /// Creates long-lived token with minimal claims
    /// Used for token renewal without re-authentication
    /// </summary>
    public async Task<string> GenerateRefreshTokenAsync(User user)
    {
        try
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var now = DateTime.UtcNow;
            var expiration = now.Add(_jwtConfig.RefreshTokenExpiration);

            // Create minimal claims for refresh token
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new($"{_jwtConfig.ClaimsPrefix}user_id", user.Id.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}security_stamp", user.SecurityStamp ?? string.Empty),
                new($"{_jwtConfig.ClaimsPrefix}token_type", "refresh")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiration,
                Issuer = _jwtConfig.Issuer,
                Audience = _jwtConfig.Audience,
                SigningCredentials = _signingCredentials
            };

            var token = _tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = _tokenHandler.WriteToken(token);

            _logger.LogDebug("Refresh token generated successfully for user {UserId}", user.Id);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while generating refresh token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Generates password reset token for secure password reset operations
    /// Creates medium-lived token with reset-specific claims
    /// Used for password reset workflows
    /// </summary>
    public async Task<(string Token, DateTime ExpiresAt)> GenerateResetTokenAsync(User user)
    {
        try
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var now = DateTime.UtcNow;
            var expiration = now.Add(_jwtConfig.ResetTokenExpiration);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new($"{_jwtConfig.ClaimsPrefix}user_id", user.Id.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}email", user.Email),
                new($"{_jwtConfig.ClaimsPrefix}security_stamp", user.SecurityStamp ?? string.Empty),
                new($"{_jwtConfig.ClaimsPrefix}token_type", "reset")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiration,
                Issuer = _jwtConfig.Issuer,
                Audience = _jwtConfig.Audience,
                SigningCredentials = _signingCredentials
            };

            var token = _tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = _tokenHandler.WriteToken(token);

            _logger.LogDebug("Reset token generated successfully for user {UserId}", user.Id);

            return (tokenString, expiration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while generating reset token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Generates email confirmation token for account verification
    /// Creates long-lived token with confirmation-specific claims
    /// Used for email verification workflows
    /// </summary>
    public async Task<(string Token, DateTime ExpiresAt)> GenerateConfirmationTokenAsync(User user)
    {
        try
        {
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var now = DateTime.UtcNow;
            var expiration = now.Add(_jwtConfig.ConfirmationTokenExpiration);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new($"{_jwtConfig.ClaimsPrefix}user_id", user.Id.ToString()),
                new($"{_jwtConfig.ClaimsPrefix}email", user.Email),
                new($"{_jwtConfig.ClaimsPrefix}security_stamp", user.SecurityStamp ?? string.Empty),
                new($"{_jwtConfig.ClaimsPrefix}token_type", "confirmation")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiration,
                Issuer = _jwtConfig.Issuer,
                Audience = _jwtConfig.Audience,
                SigningCredentials = _signingCredentials
            };

            var token = _tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = _tokenHandler.WriteToken(token);

            _logger.LogDebug("Confirmation token generated successfully for user {UserId}", user.Id);

            return (tokenString, expiration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while generating confirmation token for user {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Validates JWT token and checks blacklist status
    /// Verifies token signature, expiration, and claims
    /// Checks if token is revoked or blacklisted
    /// </summary>
    public async Task<bool> ValidateTokenAsync(string token, string tokenType)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                return false;

            // Check if token is blacklisted
            if (await _blacklistService.IsTokenBlacklistedAsync(token))
            {
                _logger.LogDebug("Token validation failed: Token is blacklisted");
                return false;
            }

            // Validate token structure and signature
            var principal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out var validatedToken);

            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                _logger.LogDebug("Token validation failed: Invalid token format");
                return false;
            }

            // Verify token type if specified
            if (!string.IsNullOrEmpty(tokenType))
            {
                var tokenTypeClaim = principal.FindFirst($"{_jwtConfig.ClaimsPrefix}token_type")?.Value;
                if (tokenTypeClaim != tokenType)
                {
                    _logger.LogDebug("Token validation failed: Token type mismatch. Expected: {ExpectedType}, Actual: {ActualType}",
                        tokenType, tokenTypeClaim);
                    return false;
                }
            }

            // Check user-specific token blacklist
            var userIdClaim = principal.FindFirst($"{_jwtConfig.ClaimsPrefix}user_id")?.Value;
            if (Guid.TryParse(userIdClaim, out var userId))
            {
                var issuedAtClaim = principal.FindFirst(JwtRegisteredClaimNames.Iat)?.Value;
                if (long.TryParse(issuedAtClaim, out var issuedAtUnix))
                {
                    var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtUnix).DateTime;
                    if (await _blacklistService.AreUserTokensBlacklistedAsync(userId, issuedAt))
                    {
                        _logger.LogDebug("Token validation failed: User tokens are blacklisted");
                        return false;
                    }
                }
            }

            _logger.LogDebug("Token validated successfully");
            return true;
        }
        catch (SecurityTokenExpiredException)
        {
            _logger.LogDebug("Token validation failed: Token has expired");
            return false;
        }
        catch (SecurityTokenInvalidSignatureException)
        {
            _logger.LogDebug("Token validation failed: Invalid token signature");
            return false;
        }
        catch (SecurityTokenValidationException ex)
        {
            _logger.LogDebug("Token validation failed: {Message}", ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while validating token");
            return false;
        }
    }

    /// <summary>
    /// Extracts user ID from JWT token
    /// Returns null if token is invalid or user ID cannot be extracted
    /// </summary>
    public async Task<Guid?> GetUserIdFromTokenAsync(string token)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                return null;

            var principal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out _);
            var userIdClaim = principal.FindFirst($"{_jwtConfig.ClaimsPrefix}user_id")?.Value;

            return Guid.TryParse(userIdClaim, out var userId) ? userId : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error occurred while extracting user ID from token");
            return null;
        }
    }

    /// <summary>
    /// Extracts all claims from JWT token
    /// Returns dictionary of claim names and values
    /// </summary>
    public async Task<Dictionary<string, object>> GetTokenClaimsAsync(string token)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                return new Dictionary<string, object>();

            var principal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out _);
            var claims = new Dictionary<string, object>();

            foreach (var claim in principal.Claims)
            {
                if (claims.ContainsKey(claim.Type))
                {
                    // Handle multiple claims with same type (e.g., roles)
                    if (claims[claim.Type] is List<string> existingList)
                    {
                        existingList.Add(claim.Value);
                    }
                    else
                    {
                        claims[claim.Type] = new List<string> { claims[claim.Type].ToString()!, claim.Value };
                    }
                }
                else
                {
                    claims[claim.Type] = claim.Value;
                }
            }

            return claims;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error occurred while extracting claims from token");
            return new Dictionary<string, object>();
        }
    }

    /// <summary>
    /// Revokes a specific token by adding it to blacklist
    /// Token will be rejected in future validation attempts
    /// </summary>
    public async Task RevokeTokenAsync(string token)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Token cannot be null or empty", nameof(token));

            // Extract expiration time from token
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            var expirationTime = jwtToken.ValidTo;

            // Add to blacklist
            await _blacklistService.BlacklistTokenAsync(token, expirationTime);

            _logger.LogDebug("Token revoked successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while revoking token");
            throw;
        }
    }

    /// <summary>
    /// Revokes all tokens for a specific user
    /// Used when user changes password or account is compromised
    /// </summary>
    public async Task RevokeAllUserTokensAsync(Guid userId)
    {
        try
        {
            var now = DateTime.UtcNow;
            await _blacklistService.BlacklistAllUserTokensAsync(userId, now);

            _logger.LogInformation("All tokens revoked for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while revoking all tokens for user {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Checks if a token is revoked/blacklisted
    /// </summary>
    public async Task<bool> IsTokenRevokedAsync(string token)
    {
        return await _blacklistService.IsTokenBlacklistedAsync(token);
    }

    /// <summary>
    /// Gets remaining lifetime of a token
    /// Returns TimeSpan until token expires
    /// </summary>
    public async Task<TimeSpan> GetTokenRemainingLifetimeAsync(string token)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                return TimeSpan.Zero;

            var jwtToken = _tokenHandler.ReadJwtToken(token);
            var now = DateTime.UtcNow;
            var expiration = jwtToken.ValidTo;

            return expiration > now ? expiration - now : TimeSpan.Zero;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error occurred while getting token remaining lifetime");
            return TimeSpan.Zero;
        }
    }

    /// <summary>
    /// Creates signing credentials based on configuration
    /// Supports HS256 and RS256 algorithms
    /// </summary>
    private SigningCredentials CreateSigningCredentials()
    {
        switch (_jwtConfig.Algorithm)
        {
            case "HS256":
                var hmacKey = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
                return new SigningCredentials(new SymmetricSecurityKey(hmacKey), SecurityAlgorithms.HmacSha256);

            case "RS256":
                // For RS256, you would need to implement RSA key loading
                throw new NotImplementedException("RS256 algorithm support not implemented yet");

            default:
                throw new InvalidOperationException($"Unsupported algorithm: {_jwtConfig.Algorithm}");
        }
    }

    /// <summary>
    /// Creates token validation parameters based on configuration
    /// Used for token validation and security checks
    /// </summary>
    private TokenValidationParameters CreateTokenValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = _jwtConfig.ValidateIssuer,
            ValidateAudience = _jwtConfig.ValidateAudience,
            ValidateLifetime = _jwtConfig.ValidateLifetime,
            ValidateIssuerSigningKey = _jwtConfig.ValidateIssuerSigningKey,
            RequireExpirationTime = _jwtConfig.RequireExpirationTime,
            RequireSignedTokens = _jwtConfig.RequireSignedTokens,
            
            ValidIssuer = _jwtConfig.Issuer,
            ValidAudience = _jwtConfig.Audience,
            IssuerSigningKey = _signingCredentials.Key,
            
            ClockSkew = _jwtConfig.ClockSkew
        };
    }
}