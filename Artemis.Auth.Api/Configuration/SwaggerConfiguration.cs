using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Reflection;

namespace Artemis.Auth.Api.Configuration;

/// <summary>
/// Swagger/OpenAPI configuration
/// </summary>
public static class SwaggerConfiguration
{
    /// <summary>
    /// Configures Swagger services
    /// </summary>
    public static IServiceCollection AddSwaggerConfiguration(this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            // Configure Swagger options
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Version = "v1",
                Title = "Artemis Authentication API",
                Description = "A comprehensive authentication and authorization microservice built with ASP.NET Core",
                Contact = new OpenApiContact
                {
                    Name = "Artemis Authentication Team",
                    Email = "auth@artemis.com"
                },
                License = new OpenApiLicense
                {
                    Name = "MIT License",
                    Url = new Uri("https://opensource.org/licenses/MIT")
                }
            });

            // Add JWT Bearer authentication
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            });

            // Include XML comments
            var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            if (File.Exists(xmlPath))
            {
                options.IncludeXmlComments(xmlPath);
            }

            // Custom operation filter for enhanced documentation
            options.OperationFilter<SwaggerOperationFilter>();
            
            // Custom schema filter for DTOs
            options.SchemaFilter<SwaggerSchemaFilter>();
        });

        services.AddTransient<IConfigureOptions<SwaggerGenOptions>, ConfigureSwaggerOptions>();

        return services;
    }

    /// <summary>
    /// Configures Swagger middleware
    /// </summary>
    public static IApplicationBuilder UseSwaggerConfiguration(this IApplicationBuilder app, IApiVersionDescriptionProvider provider)
    {
        app.UseSwagger(options =>
        {
            options.RouteTemplate = "api-docs/{documentName}/swagger.json";
        });

        app.UseSwaggerUI(options =>
        {
            options.RoutePrefix = "api-docs";
            options.DocumentTitle = "Artemis Authentication API";
            
            // Create a swagger endpoint for each API version
            foreach (var description in provider.ApiVersionDescriptions)
            {
                options.SwaggerEndpoint(
                    $"/api-docs/{description.GroupName}/swagger.json",
                    $"Artemis Authentication API {description.GroupName.ToUpperInvariant()}");
            }

            // Customize UI
            options.DefaultModelExpandDepth(2);
            options.DefaultModelRendering(Swashbuckle.AspNetCore.SwaggerUI.ModelRendering.Model);
            options.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.None);
            options.EnableDeepLinking();
            options.DisplayOperationId();
            options.DisplayRequestDuration();
            options.EnableValidator();
            options.EnableFilter();
            options.ShowExtensions();
            options.ShowCommonExtensions();
        });

        return app;
    }
}

/// <summary>
/// Configure Swagger options for API versioning
/// </summary>
public class ConfigureSwaggerOptions : IConfigureOptions<SwaggerGenOptions>
{
    private readonly IApiVersionDescriptionProvider _provider;

    public ConfigureSwaggerOptions(IApiVersionDescriptionProvider provider)
    {
        _provider = provider;
    }

    public void Configure(SwaggerGenOptions options)
    {
        foreach (var description in _provider.ApiVersionDescriptions)
        {
            options.SwaggerDoc(description.GroupName, CreateInfoForApiVersion(description));
        }
    }

    private static OpenApiInfo CreateInfoForApiVersion(ApiVersionDescription description)
    {
        var info = new OpenApiInfo
        {
            Title = "Artemis Authentication API",
            Version = description.ApiVersion.ToString(),
            Description = "A comprehensive authentication and authorization microservice built with ASP.NET Core",
            Contact = new OpenApiContact
            {
                Name = "Artemis Authentication Team",
                Email = "auth@artemis.com"
            },
            License = new OpenApiLicense
            {
                Name = "MIT License",
                Url = new Uri("https://opensource.org/licenses/MIT")
            }
        };

        if (description.IsDeprecated)
        {
            info.Description += " This API version has been deprecated.";
        }

        return info;
    }
}

/// <summary>
/// Custom operation filter for Swagger documentation
/// </summary>
public class SwaggerOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        // Add rate limiting information
        var rateLimitingAttribute = context.MethodInfo.GetCustomAttribute<Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute>();
        if (rateLimitingAttribute != null)
        {
            operation.Description += $"\n\n**Rate Limiting**: This endpoint is rate limited using policy '{rateLimitingAttribute.PolicyName}'.";
        }

        // Add authorization information
        var authorizeAttribute = context.MethodInfo.GetCustomAttribute<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>();
        if (authorizeAttribute != null)
        {
            operation.Description += $"\n\n**Authorization**: This endpoint requires authentication.";
            if (!string.IsNullOrEmpty(authorizeAttribute.Policy))
            {
                operation.Description += $" Policy: {authorizeAttribute.Policy}";
            }
        }

        // Add response headers information
        if (operation.Responses.ContainsKey("200"))
        {
            operation.Responses["200"].Headers = new Dictionary<string, OpenApiHeader>
            {
                ["X-RateLimit-Limit"] = new OpenApiHeader
                {
                    Description = "The number of allowed requests in the current period",
                    Schema = new OpenApiSchema { Type = "integer" }
                },
                ["X-RateLimit-Remaining"] = new OpenApiHeader
                {
                    Description = "The number of remaining requests in the current period",
                    Schema = new OpenApiSchema { Type = "integer" }
                },
                ["X-RateLimit-Reset"] = new OpenApiHeader
                {
                    Description = "The time at which the current rate limit period resets",
                    Schema = new OpenApiSchema { Type = "integer" }
                }
            };
        }
    }
}

/// <summary>
/// Custom schema filter for Swagger documentation
/// </summary>
public class SwaggerSchemaFilter : ISchemaFilter
{
    public void Apply(OpenApiSchema schema, SchemaFilterContext context)
    {
        // Add examples for common DTOs
        if (context.Type.Name.Contains("Request") || context.Type.Name.Contains("Response"))
        {
            schema.Description ??= $"Data transfer object for {context.Type.Name}";
        }

        // Mark sensitive fields
        if (schema.Properties != null)
        {
            foreach (var property in schema.Properties)
            {
                if (property.Key.ToLower().Contains("password") || 
                    property.Key.ToLower().Contains("secret") ||
                    property.Key.ToLower().Contains("token"))
                {
                    property.Value.Description = (property.Value.Description ?? "") + " (Sensitive data)";
                    property.Value.Format = "password";
                }
            }
        }
    }
}