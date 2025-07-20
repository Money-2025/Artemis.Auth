using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Artemis.Auth.Application.Contracts.Infrastructure;
using Artemis.Auth.Application.Contracts.Persistence;
using Artemis.Auth.Infrastructure.Common;
using Artemis.Auth.Infrastructure.Persistence;
using Artemis.Auth.Infrastructure.Persistence.Repositories;
using Artemis.Auth.Infrastructure.Services;
using Artemis.Auth.Infrastructure.Security;
using Artemis.Auth.Infrastructure.Performance;

namespace Artemis.Auth.Infrastructure.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // Database configuration
        var databaseConfig = new DatabaseConfiguration
        {
            Provider                  = configuration
                .GetValue<DatabaseProvider>("Database:Provider"),
            MaxRetryCount             = configuration
                .GetValue<int>("Database:MaxRetryCount"),
            MaxRetryDelay             = configuration
                .GetValue<TimeSpan>("Database:MaxRetryDelay"),
            EnableSensitiveDataLogging = configuration
                .GetValue<bool>("Database:EnableSensitiveDataLogging"),
            ConnectionString          = configuration.GetConnectionString("AuthDb")!
        };
        services.AddSingleton(databaseConfig);
        
        // Security configuration
        var securityConfig = configuration.GetSection("Security").Get<SecurityConfiguration>() ?? new SecurityConfiguration();
        services.AddSingleton(securityConfig);
        
        // JWT configuration
        var jwtConfig = configuration.GetSection("Jwt").Get<JwtConfiguration>() ?? new JwtConfiguration();
        services.Configure<JwtConfiguration>(configuration.GetSection("Jwt"));
        services.AddSingleton(jwtConfig);
        
        // Email configuration
        var emailConfig = configuration.GetSection("Email").Get<EmailConfiguration>() ?? new EmailConfiguration();
        services.Configure<EmailConfiguration>(configuration.GetSection("Email"));
        services.AddSingleton(emailConfig);
        
        // Add HttpContextAccessor for audit interceptor
        services.AddHttpContextAccessor();
        
        // Register interceptors
        services.AddScoped<AuditInterceptor>();
        services.AddScoped<SecurityConstraintInterceptor>();
        services.AddScoped<QueryOptimizationInterceptor>();
        
        // Database context
        services.AddDbContext<AuthDbContext>((sp, options) =>
        {
            var config = sp.GetRequiredService<DatabaseConfiguration>();

            // 1. Connection, retry & custom history table
            options.UseNpgsql(
                    config.ConnectionString,
                    npgsql =>
                    {
                        npgsql.EnableRetryOnFailure(
                            maxRetryCount: config.MaxRetryCount,
                            maxRetryDelay: config.MaxRetryDelay,
                            errorCodesToAdd: null
                        );
                        // Migrations history tablosunu snake_case ve public schema’da oluştur
                        npgsql.MigrationsHistoryTable("__EFMigrationsHistory", "public");
                    }
                )
                // 2. Entity’lerinizin ve EF’in kendi tablolarının sütunlarını snake_case’e çevir
                .UseSnakeCaseNamingConvention();

            // 3. Interceptor’lar
            var auditInterceptor    = sp.GetRequiredService<AuditInterceptor>();
            var securityInterceptor = sp.GetRequiredService<SecurityConstraintInterceptor>();
            var queryInterceptor    = sp.GetRequiredService<QueryOptimizationInterceptor>();
            options.AddInterceptors(auditInterceptor, securityInterceptor, queryInterceptor);
        });


        
        // Repository implementations
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        
        // JWT and security services
        services.AddSingleton<TokenBlacklistService>();
        services.AddScoped<IJwtGenerator, JwtService>();
        
        // Email services
        services.AddSingleton<EmailQueueService>();
        services.AddScoped<EmailService>();
        services.AddScoped<IEmailSender, EmailService>();
        services.AddHostedService<EmailBackgroundService>();
        
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