using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Versioning;

namespace Artemis.Auth.Api.Configuration;

/// <summary>
/// API versioning configuration
/// </summary>
public static class ApiVersioningConfiguration
{
    /// <summary>
    /// Configures API versioning
    /// </summary>
    public static IServiceCollection AddApiVersioningConfiguration(this IServiceCollection services)
    {
        services.AddApiVersioning(options =>
        {
            // Set default API version
            options.DefaultApiVersion = new ApiVersion(1, 0);
            
            // Assume default version when not specified
            options.AssumeDefaultVersionWhenUnspecified = true;
            
            // Support versioning via URL path, query string, and header
            options.ApiVersionReader = ApiVersionReader.Combine(
                new UrlSegmentApiVersionReader(),
                new QueryStringApiVersionReader("version"),
                new HeaderApiVersionReader("X-API-Version")
            );
            
            // Report API versions in response headers
            options.ReportApiVersions = true;
        });

        services.AddVersionedApiExplorer(options =>
        {
            // Group name format for API versions
            options.GroupNameFormat = "'v'VVV";
            
            // Automatically substitute version in controller names
            options.SubstituteApiVersionInUrl = true;
        });

        return services;
    }
}

/// <summary>
/// API versioning middleware configuration
/// </summary>
public static class ApiVersioningMiddleware
{
    /// <summary>
    /// Configures API versioning middleware
    /// </summary>
    public static IApplicationBuilder UseApiVersioningConfiguration(this IApplicationBuilder app)
    {
        app.UseApiVersioning();
        
        return app;
    }
}