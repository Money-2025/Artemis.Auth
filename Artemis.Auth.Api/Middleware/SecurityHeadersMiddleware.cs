using Microsoft.Extensions.Options;

namespace Artemis.Auth.Api.Middleware;

/// <summary>
/// Security headers middleware for enhanced security
/// </summary>
public class SecurityHeadersMiddleware : IMiddleware
{
    private readonly ILogger<SecurityHeadersMiddleware> _logger;
    private readonly SecurityHeadersOptions _options;

    /// <summary>
    /// Initializes the security headers middleware
    /// </summary>
    public SecurityHeadersMiddleware(
        ILogger<SecurityHeadersMiddleware> logger,
        IOptions<SecurityHeadersOptions> options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Adds security headers to the response
    /// </summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        
        // Add security headers to the response
        AddSecurityHeaders(context);
        
        // Process the request
        await next(context);
    }

    /// <summary>
    /// Adds security headers to the HTTP response
    /// </summary>
    private void AddSecurityHeaders(HttpContext context)
    {
        var headers = context.Response.Headers;

        // X-Frame-Options - Prevent clickjacking
        if (_options.XFrameOptions.Enabled)
        {
            headers["X-Frame-Options"] = _options.XFrameOptions.Value;
        }

        // X-Content-Type-Options - Prevent MIME type sniffing
        if (_options.XContentTypeOptions.Enabled)
        {
            headers["X-Content-Type-Options"] = _options.XContentTypeOptions.Value;
        }

        // X-XSS-Protection - Enable XSS filtering
        if (_options.XXssProtection.Enabled)
        {
            headers["X-XSS-Protection"] = _options.XXssProtection.Value;
        }

        // Referrer-Policy - Control referrer information
        if (_options.ReferrerPolicy.Enabled)
        {
            headers["Referrer-Policy"] = _options.ReferrerPolicy.Value;
        }

        // Content-Security-Policy - Control resource loading
        if (_options.ContentSecurityPolicy.Enabled)
        {
            headers["Content-Security-Policy"] = _options.ContentSecurityPolicy.Value;
        }

        // Strict-Transport-Security - Enforce HTTPS
        if (_options.StrictTransportSecurity.Enabled && context.Request.IsHttps)
        {
            headers["Strict-Transport-Security"] = _options.StrictTransportSecurity.Value;
        }

        // Permissions-Policy - Control browser features
        if (_options.PermissionsPolicy.Enabled)
        {
            headers["Permissions-Policy"] = _options.PermissionsPolicy.Value;
        }

        // X-Robots-Tag - Control search engine indexing
        if (_options.XRobotsTag.Enabled)
        {
            headers["X-Robots-Tag"] = _options.XRobotsTag.Value;
        }

        // Server - Hide server information
        if (_options.ServerHeader.Enabled)
        {
            headers["Server"] = _options.ServerHeader.Value;
        }

        // X-Powered-By - Remove framework information
        if (_options.RemoveXPoweredBy)
        {
            headers.Remove("X-Powered-By");
        }

        // Cache-Control for security-sensitive endpoints
        if (_options.CacheControl.Enabled && IsSecuritySensitiveEndpoint(context))
        {
            headers["Cache-Control"] = _options.CacheControl.Value;
            headers["Pragma"] = "no-cache";
            headers["Expires"] = "0";
        }

        _logger.LogDebug("Security headers added to response for path: {Path}", context.Request.Path);
    }

    /// <summary>
    /// Determines if the current endpoint is security-sensitive
    /// </summary>
    private static bool IsSecuritySensitiveEndpoint(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant();
        return path?.Contains("/auth/") == true || 
               path?.Contains("/user/") == true || 
               path?.Contains("/admin/") == true || 
               path?.Contains("/mfa/") == true;
    }
}

/// <summary>
/// Security headers configuration options
/// </summary>
public class SecurityHeadersOptions
{
    /// <summary>
    /// X-Frame-Options header configuration
    /// </summary>
    public SecurityHeaderOption XFrameOptions { get; set; } = new()
    {
        Enabled = true,
        Value = "DENY"
    };

    /// <summary>
    /// X-Content-Type-Options header configuration
    /// </summary>
    public SecurityHeaderOption XContentTypeOptions { get; set; } = new()
    {
        Enabled = true,
        Value = "nosniff"
    };

    /// <summary>
    /// X-XSS-Protection header configuration
    /// </summary>
    public SecurityHeaderOption XXssProtection { get; set; } = new()
    {
        Enabled = true,
        Value = "1; mode=block"
    };

    /// <summary>
    /// Referrer-Policy header configuration
    /// </summary>
    public SecurityHeaderOption ReferrerPolicy { get; set; } = new()
    {
        Enabled = true,
        Value = "strict-origin-when-cross-origin"
    };

    /// <summary>
    /// Content-Security-Policy header configuration
    /// </summary>
    public SecurityHeaderOption ContentSecurityPolicy { get; set; } = new()
    {
        Enabled = true,
        Value = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    };

    /// <summary>
    /// Strict-Transport-Security header configuration
    /// </summary>
    public SecurityHeaderOption StrictTransportSecurity { get; set; } = new()
    {
        Enabled = true,
        Value = "max-age=31536000; includeSubDomains; preload"
    };

    /// <summary>
    /// Permissions-Policy header configuration
    /// </summary>
    public SecurityHeaderOption PermissionsPolicy { get; set; } = new()
    {
        Enabled = true,
        Value = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=()"
    };

    /// <summary>
    /// X-Robots-Tag header configuration
    /// </summary>
    public SecurityHeaderOption XRobotsTag { get; set; } = new()
    {
        Enabled = true,
        Value = "noindex, nofollow, noarchive, nosnippet"
    };

    /// <summary>
    /// Server header configuration
    /// </summary>
    public SecurityHeaderOption ServerHeader { get; set; } = new()
    {
        Enabled = true,
        Value = "Web Server"
    };

    /// <summary>
    /// Cache-Control header configuration for security-sensitive endpoints
    /// </summary>
    public SecurityHeaderOption CacheControl { get; set; } = new()
    {
        Enabled = true,
        Value = "no-store, no-cache, must-revalidate, private"
    };

    /// <summary>
    /// Whether to remove the X-Powered-By header
    /// </summary>
    public bool RemoveXPoweredBy { get; set; } = true;
}

/// <summary>
/// Security header option configuration
/// </summary>
public class SecurityHeaderOption
{
    /// <summary>
    /// Whether the header is enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The header value
    /// </summary>
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// Extension methods for security headers middleware
/// </summary>
public static class SecurityHeadersExtensions
{
    /// <summary>
    /// Adds security headers services to the DI container
    /// </summary>
    public static IServiceCollection AddSecurityHeaders(this IServiceCollection services, Action<SecurityHeadersOptions>? configureOptions = null)
    {
        services.Configure<SecurityHeadersOptions>(options =>
        {
            configureOptions?.Invoke(options);
        });

        services.AddTransient<SecurityHeadersMiddleware>();
        
        return services;
    }

    /// <summary>
    /// Uses security headers middleware in the pipeline
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }
}