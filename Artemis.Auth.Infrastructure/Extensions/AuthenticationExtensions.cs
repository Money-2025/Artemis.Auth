using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Artemis.Auth.Infrastructure.Common;

namespace Artemis.Auth.Infrastructure.Extensions;

/// <summary>
/// Authentication Extensions: Configures JWT authentication middleware
/// Provides secure JWT authentication setup for ASP.NET Core
/// Integrates with your JWT configuration and security settings
/// </summary>
public static class AuthenticationExtensions
{
    /// <summary>
    /// Adds JWT authentication to the service collection
    /// Configures JWT Bearer authentication with secure defaults
    /// Uses your JWT configuration for token validation
    /// </summary>
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Get JWT configuration
        var jwtConfig = configuration.GetSection("Jwt").Get<JwtConfiguration>() ?? new JwtConfiguration();
        
        // Validate configuration
        jwtConfig.Validate();

        // Configure JWT authentication
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            // Token validation parameters
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = jwtConfig.ValidateIssuer,
                ValidateAudience = jwtConfig.ValidateAudience,
                ValidateLifetime = jwtConfig.ValidateLifetime,
                ValidateIssuerSigningKey = jwtConfig.ValidateIssuerSigningKey,
                RequireExpirationTime = jwtConfig.RequireExpirationTime,
                RequireSignedTokens = jwtConfig.RequireSignedTokens,
                
                ValidIssuer = jwtConfig.Issuer,
                ValidAudience = jwtConfig.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Secret)),
                
                ClockSkew = jwtConfig.ClockSkew
            };

            // Configure bearer token options
            options.SaveToken = false; // Don't save token in AuthenticationProperties for security
            options.RequireHttpsMetadata = true; // Require HTTPS in production
            options.IncludeErrorDetails = false; // Don't include error details for security

            // Configure events for custom token validation
            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    // Additional custom validation can be added here
                    var jwtGenerator = context.HttpContext.RequestServices.GetRequiredService<Application.Contracts.Infrastructure.IJwtGenerator>();
                    var token = context.Request.Headers["Authorization"]
                        .FirstOrDefault()?.Split(" ").Last();
                    
                    if (!string.IsNullOrEmpty(token))
                    {
                        // Check if token is revoked
                        var isRevoked = await jwtGenerator.IsTokenRevokedAsync(token);
                        if (isRevoked)
                        {
                            context.Fail("Token has been revoked");
                            return;
                        }

                        // Additional custom validation logic can be added here
                        // For example: checking user status, additional claims validation, etc.
                    }
                },

                OnChallenge = context =>
                {
                    // Custom challenge response
                    context.HandleResponse();
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    
                    var response = new
                    {
                        error = "unauthorized",
                        message = "Access token is missing or invalid"
                    };
                    
                    return context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response), context.HttpContext.RequestAborted);
                },

                OnForbidden = context =>
                {
                    // Custom forbidden response
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    
                    var response = new
                    {
                        error = "forbidden",
                        message = "Access denied. Insufficient permissions"
                    };
                    
                    return context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response), context.HttpContext.RequestAborted);
                },

                OnAuthenticationFailed = context =>
                {
                    // Log authentication failures for security monitoring
                    var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                    var logger = loggerFactory.CreateLogger("JwtAuthentication");
                    logger.LogWarning("JWT authentication failed: {Exception}", context.Exception.Message);
                    
                    // Don't include exception details in response for security
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";
                    
                    var response = new
                    {
                        error = "unauthorized",
                        message = "Token validation failed"
                    };
                    
                    return context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(response), context.HttpContext.RequestAborted);
                }
            };
        });

        return services;
    }

    /// <summary>
    /// Adds authorization policies for role-based and permission-based access control
    /// Configures common authorization policies for your authentication system
    /// </summary>
    public static IServiceCollection AddAuthorizationPolicies(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            // Default policy requires authenticated user
            options.DefaultPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();

            // Admin policy requires Admin role
            options.AddPolicy("AdminPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireRole("Admin");
            });

            // User management policy requires specific permission
            options.AddPolicy("UserManagementPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("artemis:permission", "user.manage");
            });

            // Role management policy requires specific permission
            options.AddPolicy("RoleManagementPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("artemis:permission", "role.manage");
            });

            // Email confirmed policy requires confirmed email
            options.AddPolicy("EmailConfirmedPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("artemis:email_confirmed", "True");
            });

            // Two-factor policy requires 2FA enabled
            options.AddPolicy("TwoFactorPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("artemis:two_factor_enabled", "True");
            });

            // API access policy for external API consumers
            options.AddPolicy("ApiAccessPolicy", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("artemis:token_type", "access");
            });
        });

        return services;
    }

    /// <summary>
    /// Adds comprehensive authentication and authorization configuration
    /// Combines JWT authentication with authorization policies
    /// One-stop method for complete auth setup
    /// </summary>
    public static IServiceCollection AddAuthenticationAndAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        return services
            .AddJwtAuthentication(configuration)
            .AddAuthorizationPolicies();
    }
}