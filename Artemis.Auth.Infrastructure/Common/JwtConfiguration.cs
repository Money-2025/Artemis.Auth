using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Infrastructure.Common;

/// <summary>
/// JWT Configuration: Contains all JWT-related settings for token generation and validation
/// Implements validation attributes to ensure secure configuration
/// Used by JwtService for token operations and security settings
/// </summary>
public class JwtConfiguration
{
    /// <summary>
    /// Secret key used for signing JWT tokens
    /// Must be at least 256 bits (32 characters) for HS256 algorithm
    /// Should be stored securely in configuration, never hardcoded
    /// </summary>
    [Required]
    [MinLength(32, ErrorMessage = "JWT Secret must be at least 32 characters long for security")]
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Token issuer - identifies who issued the token
    /// Should be your authentication service identifier
    /// Used for token validation to ensure tokens came from trusted source
    /// </summary>
    [Required]
    [MinLength(1, ErrorMessage = "JWT Issuer is required")]
    public string Issuer { get; set; } = "Artemis.Auth";

    /// <summary>
    /// Token audience - identifies who the token is intended for
    /// Can be your application identifier or client identifier
    /// Used for token validation to ensure tokens are used by intended recipients
    /// </summary>
    [Required]
    [MinLength(1, ErrorMessage = "JWT Audience is required")]
    public string Audience { get; set; } = "Artemis.Auth.Client";

    /// <summary>
    /// Access token expiration time
    /// Short-lived tokens (15-30 minutes) for better security
    /// Balance between security and user experience
    /// </summary>
    [Range(1, 1440, ErrorMessage = "Access token expiration must be between 1 and 1440 minutes")]
    public int AccessTokenExpirationMinutes { get; set; } = 15;

    /// <summary>
    /// Refresh token expiration time
    /// Longer-lived tokens (7-30 days) for user convenience
    /// Used to obtain new access tokens without re-authentication
    /// </summary>
    [Range(1, 43200, ErrorMessage = "Refresh token expiration must be between 1 and 43200 minutes (30 days)")]
    public int RefreshTokenExpirationMinutes { get; set; } = 10080; // 7 days

    /// <summary>
    /// Reset token expiration time (password reset, etc.)
    /// Short-lived tokens (15-60 minutes) for security
    /// Used for sensitive operations like password reset
    /// </summary>
    [Range(1, 1440, ErrorMessage = "Reset token expiration must be between 1 and 1440 minutes")]
    public int ResetTokenExpirationMinutes { get; set; } = 60;

    /// <summary>
    /// Email confirmation token expiration time
    /// Longer-lived tokens (24-72 hours) for user convenience
    /// Used for email verification and account confirmation
    /// </summary>
    [Range(1, 4320, ErrorMessage = "Confirmation token expiration must be between 1 and 4320 minutes (72 hours)")]
    public int ConfirmationTokenExpirationMinutes { get; set; } = 1440; // 24 hours

    /// <summary>
    /// Signing algorithm for JWT tokens
    /// HS256 (HMAC-SHA256) is recommended for symmetric key signing
    /// RS256 (RSA-SHA256) for asymmetric key signing (more complex setup)
    /// </summary>
    [Required]
    public string Algorithm { get; set; } = "HS256";

    /// <summary>
    /// Clock skew tolerance for token validation
    /// Allows for small time differences between servers
    /// Helps prevent token validation issues due to clock drift
    /// </summary>
    [Range(0, 300, ErrorMessage = "Clock skew must be between 0 and 300 seconds")]
    public int ClockSkewSeconds { get; set; } = 30;

    /// <summary>
    /// Whether to validate token lifetime during validation
    /// Should always be true in production for security
    /// Can be disabled for testing scenarios
    /// </summary>
    public bool ValidateLifetime { get; set; } = true;

    /// <summary>
    /// Whether to validate token issuer during validation
    /// Should always be true in production for security
    /// Ensures tokens came from trusted issuer
    /// </summary>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Whether to validate token audience during validation
    /// Should always be true in production for security
    /// Ensures tokens are used by intended audience
    /// </summary>
    public bool ValidateAudience { get; set; } = true;

    /// <summary>
    /// Whether to validate token signature during validation
    /// Should always be true in production for security
    /// Ensures tokens haven't been tampered with
    /// </summary>
    public bool ValidateIssuerSigningKey { get; set; } = true;

    /// <summary>
    /// Whether to require token expiration claim
    /// Should always be true in production for security
    /// Ensures all tokens have expiration times
    /// </summary>
    public bool RequireExpirationTime { get; set; } = true;

    /// <summary>
    /// Whether to require token signature
    /// Should always be true in production for security
    /// Ensures all tokens are properly signed
    /// </summary>
    public bool RequireSignedTokens { get; set; } = true;

    /// <summary>
    /// Token type for access tokens
    /// Standard value is "Bearer" for OAuth 2.0 compliance
    /// Used in Authorization header: "Bearer <token>"
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Custom claims prefix to avoid conflicts
    /// Used to namespace custom claims in JWT payload
    /// Helps prevent claim name collisions
    /// </summary>
    public string ClaimsPrefix { get; set; } = "artemis:";

    /// <summary>
    /// Maximum number of refresh tokens per user
    /// Prevents token accumulation and potential abuse
    /// Old tokens are cleaned up when limit is reached
    /// </summary>
    [Range(1, 100, ErrorMessage = "Max refresh tokens per user must be between 1 and 100")]
    public int MaxRefreshTokensPerUser { get; set; } = 5;

    /// <summary>
    /// Whether to enable token blacklisting
    /// Allows for immediate token revocation
    /// Requires additional storage and validation overhead
    /// </summary>
    public bool EnableTokenBlacklisting { get; set; } = true;

    /// <summary>
    /// Token blacklist cleanup interval in minutes
    /// How often to clean up expired blacklisted tokens
    /// Prevents blacklist storage from growing indefinitely
    /// </summary>
    [Range(1, 1440, ErrorMessage = "Blacklist cleanup interval must be between 1 and 1440 minutes")]
    public int BlacklistCleanupIntervalMinutes { get; set; } = 60;

    /// <summary>
    /// Validates the configuration for security and consistency
    /// Called during startup to ensure secure configuration
    /// Throws validation exceptions if configuration is invalid
    /// </summary>
    public void Validate()
    {
        var context = new ValidationContext(this);
        var results = new List<ValidationResult>();
        
        if (!Validator.TryValidateObject(this, context, results, true))
        {
            var errors = string.Join("; ", results.Select(r => r.ErrorMessage));
            throw new InvalidOperationException($"JWT Configuration validation failed: {errors}");
        }

        // Additional business logic validation
        if (AccessTokenExpirationMinutes >= RefreshTokenExpirationMinutes)
        {
            throw new InvalidOperationException("Access token expiration must be less than refresh token expiration");
        }

        if (Algorithm != "HS256" && Algorithm != "RS256")
        {
            throw new InvalidOperationException("Only HS256 and RS256 algorithms are supported");
        }
    }

    /// <summary>
    /// Gets access token expiration as TimeSpan
    /// Helper method for token generation
    /// </summary>
    public TimeSpan AccessTokenExpiration => TimeSpan.FromMinutes(AccessTokenExpirationMinutes);

    /// <summary>
    /// Gets refresh token expiration as TimeSpan
    /// Helper method for token generation
    /// </summary>
    public TimeSpan RefreshTokenExpiration => TimeSpan.FromMinutes(RefreshTokenExpirationMinutes);

    /// <summary>
    /// Gets reset token expiration as TimeSpan
    /// Helper method for token generation
    /// </summary>
    public TimeSpan ResetTokenExpiration => TimeSpan.FromMinutes(ResetTokenExpirationMinutes);

    /// <summary>
    /// Gets confirmation token expiration as TimeSpan
    /// Helper method for token generation
    /// </summary>
    public TimeSpan ConfirmationTokenExpiration => TimeSpan.FromMinutes(ConfirmationTokenExpirationMinutes);

    /// <summary>
    /// Gets clock skew as TimeSpan
    /// Helper method for token validation
    /// </summary>
    public TimeSpan ClockSkew => TimeSpan.FromSeconds(ClockSkewSeconds);
}