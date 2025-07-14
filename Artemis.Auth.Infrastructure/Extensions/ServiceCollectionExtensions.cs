using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Artemis.Auth.Infrastructure.Common;
using Artemis.Auth.Infrastructure.Persistence;
using Artemis.Auth.Infrastructure.Services;
using Artemis.Auth.Infrastructure.Security;
using Artemis.Auth.Infrastructure.Performance;

namespace Artemis.Auth.Infrastructure.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Database configuration
        var databaseConfig = configuration.GetSection("Database").Get<DatabaseConfiguration>() ?? new DatabaseConfiguration();
        services.AddSingleton(databaseConfig);
        
        // Security configuration
        var securityConfig = configuration.GetSection("Security").Get<SecurityConfiguration>() ?? new SecurityConfiguration();
        services.AddSingleton(securityConfig);
        
        // Add HttpContextAccessor for audit interceptor
        services.AddHttpContextAccessor();
        
        // Register interceptors
        services.AddScoped<AuditInterceptor>();
        services.AddScoped<SecurityConstraintInterceptor>();
        services.AddScoped<QueryOptimizationInterceptor>();
        
        // Database context
        services.AddDbContext<AuthDbContext>((serviceProvider, options) =>
        {
            var config = serviceProvider.GetRequiredService<DatabaseConfiguration>();
            var auditInterceptor = serviceProvider.GetRequiredService<AuditInterceptor>();
            var securityInterceptor = serviceProvider.GetRequiredService<SecurityConstraintInterceptor>();
            var queryInterceptor = serviceProvider.GetRequiredService<QueryOptimizationInterceptor>();
            
            ConfigureDatabase(options, config);
            
            // Add interceptors
            options.AddInterceptors(auditInterceptor, securityInterceptor, queryInterceptor);
        });
        
        // Infrastructure services
        services.AddScoped<SoftDeleteService>();
        services.AddHostedService<DatabaseMigrationService>();
        
        return services;
    }
    
    private static void ConfigureDatabase(DbContextOptionsBuilder options, DatabaseConfiguration config)
    {
        switch (config.Provider)
        {
            case DatabaseProvider.PostgreSQL:
                options.UseNpgsql(config.ConnectionString, npgsql =>
                {
                    npgsql.EnableRetryOnFailure(
                        maxRetryCount: config.MaxRetryCount,
                        maxRetryDelay: config.MaxRetryDelay,
                        errorCodesToAdd: null);
                });
                break;
                
            case DatabaseProvider.SqlServer:
            case DatabaseProvider.MySQL:
            case DatabaseProvider.SQLite:
                throw new NotSupportedException($"Database provider {config.Provider} is not currently supported in this build. Only PostgreSQL is supported.");
                
            default:
                throw new NotSupportedException($"Database provider {config.Provider} is not supported");
        }
        
        // Common configurations
        options.EnableSensitiveDataLogging(config.EnableSensitiveDataLogging);
        options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
        
        // Security settings
        options.EnableServiceProviderCaching(false);
        options.EnableDetailedErrors(false);
    }
}