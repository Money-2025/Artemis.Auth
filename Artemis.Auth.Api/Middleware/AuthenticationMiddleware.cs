using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Api.Middleware;

/// <summary>
/// Custom JWT authentication middleware for enhanced security and logging
/// </summary>
public class CustomJwtAuthenticationMiddleware : IMiddleware
{
    private readonly ILogger<CustomJwtAuthenticationMiddleware> _logger;
    private readonly IJwtGenerator _jwtGenerator;
    private readonly JwtConfiguration _jwtConfig;

    /// <summary>
    /// Initializes the custom JWT authentication middleware
    /// </summary>
    public CustomJwtAuthenticationMiddleware(
        ILogger<CustomJwtAuthenticationMiddleware> logger,
        IJwtGenerator jwtGenerator,
        IOptions<JwtConfiguration> jwtConfig)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _jwtGenerator = jwtGenerator ?? throw new ArgumentNullException(nameof(jwtGenerator));
        _jwtConfig = jwtConfig.Value ?? throw new ArgumentNullException(nameof(jwtConfig));
    }

    /// <summary>
    /// Processes the request and validates JWT tokens
    /// </summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            // Skip authentication for certain paths
            if (ShouldSkipAuthentication(context.Request.Path))
            {
                await next(context);
                return;
            }

            var token = ExtractTokenFromRequest(context.Request);
            
            if (string.IsNullOrEmpty(token))
            {
                await next(context);
                return;
            }

            // Validate token
            var isValid = await _jwtGenerator.ValidateTokenAsync(token, "access");
            
            if (!isValid)
            {
                _logger.LogWarning("Invalid JWT token from IP: {IpAddress}", 
                    context.Connection.RemoteIpAddress?.ToString());
                
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid or expired token");
                return;
            }

            // Extract claims from token
            var principal = GetPrincipalFromToken(token);
            if (principal != null)
            {
                context.User = principal;
                
                // Log successful authentication
                var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                _logger.LogDebug("User authenticated successfully: {UserId}", userId);
            }

            await next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in JWT authentication middleware");
            context.Response.StatusCode = 500;
            await context.Response.WriteAsync("Authentication error");
        }
    }

    /// <summary>
    /// Determines if authentication should be skipped for the given path
    /// </summary>
    private static bool ShouldSkipAuthentication(PathString path)
    {
        var skipPaths = new[]
        {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh",
            "/api/v1/auth/forgot-password",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/verify-email",
            "/api/v1/auth/resend-verification",
            "/health",
            "/swagger",
            "/favicon.ico"
        };

        return skipPaths.Any(skipPath => path.StartsWithSegments(skipPath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Extracts JWT token from the request
    /// </summary>
    private static string? ExtractTokenFromRequest(HttpRequest request)
    {
        // Check Authorization header
        var authHeader = request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader.Substring(7);
        }

        // Check query parameter (for websockets or special cases)
        var queryToken = request.Query["token"].FirstOrDefault();
        if (!string.IsNullOrEmpty(queryToken))
        {
            return queryToken;
        }

        // Check cookie
        var cookieToken = request.Cookies["access_token"];
        if (!string.IsNullOrEmpty(cookieToken))
        {
            return cookieToken;
        }

        return null;
    }

    /// <summary>
    /// Extracts claims principal from JWT token
    /// </summary>
    private ClaimsPrincipal? GetPrincipalFromToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = _jwtConfig.ValidateIssuer,
                ValidateAudience = _jwtConfig.ValidateAudience,
                ValidateLifetime = _jwtConfig.ValidateLifetime,
                ValidateIssuerSigningKey = _jwtConfig.ValidateIssuerSigningKey,
                ValidIssuer = _jwtConfig.Issuer,
                ValidAudience = _jwtConfig.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = _jwtConfig.ClockSkew,
                RequireExpirationTime = _jwtConfig.RequireExpirationTime,
                RequireSignedTokens = _jwtConfig.RequireSignedTokens
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            return principal;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error extracting principal from JWT token");
            return null;
        }
    }
}

/// <summary>
/// JWT authentication scheme handler for ASP.NET Core authentication
/// </summary>
public class CustomJwtAuthenticationSchemeHandler : AuthenticationHandler<JwtBearerOptions>
{
    private readonly IJwtGenerator _jwtGenerator;
    private readonly JwtConfiguration _jwtConfig;

    /// <summary>
    /// Initializes the JWT authentication scheme handler
    /// </summary>
    public CustomJwtAuthenticationSchemeHandler(
        IOptionsMonitor<JwtBearerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IJwtGenerator jwtGenerator,
        IOptions<JwtConfiguration> jwtConfig)
        : base(options, logger, encoder, clock)
    {
        _jwtGenerator = jwtGenerator ?? throw new ArgumentNullException(nameof(jwtGenerator));
        _jwtConfig = jwtConfig.Value ?? throw new ArgumentNullException(nameof(jwtConfig));
    }

    /// <summary>
    /// Handles the authentication
    /// </summary>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var token = ExtractTokenFromRequest();
            
            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.NoResult();
            }

            // Validate token using our JWT service
            var isValid = await _jwtGenerator.ValidateTokenAsync(token, "access");
            
            if (!isValid)
            {
                Logger.LogWarning("Invalid JWT token from IP: {IpAddress}", 
                    Request.HttpContext.Connection.RemoteIpAddress?.ToString());
                
                return AuthenticateResult.Fail("Invalid or expired token");
            }

            // Extract claims
            var principal = GetPrincipalFromToken(token);
            if (principal == null)
            {
                return AuthenticateResult.Fail("Unable to extract claims from token");
            }

            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error in JWT authentication handler");
            return AuthenticateResult.Fail("Authentication error");
        }
    }

    /// <summary>
    /// Extracts JWT token from the request
    /// </summary>
    private string? ExtractTokenFromRequest()
    {
        // Check Authorization header
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader.Substring(7);
        }

        return null;
    }

    /// <summary>
    /// Extracts claims principal from JWT token
    /// </summary>
    private ClaimsPrincipal? GetPrincipalFromToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = _jwtConfig.ValidateIssuer,
                ValidateAudience = _jwtConfig.ValidateAudience,
                ValidateLifetime = _jwtConfig.ValidateLifetime,
                ValidateIssuerSigningKey = _jwtConfig.ValidateIssuerSigningKey,
                ValidIssuer = _jwtConfig.Issuer,
                ValidAudience = _jwtConfig.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = _jwtConfig.ClockSkew,
                RequireExpirationTime = _jwtConfig.RequireExpirationTime,
                RequireSignedTokens = _jwtConfig.RequireSignedTokens
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            return principal;
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "Error extracting principal from JWT token");
            return null;
        }
    }
}