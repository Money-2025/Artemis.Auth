using Artemis.Auth.Application;
using Artemis.Auth.Infrastructure.Extensions;
using Artemis.Auth.Api.Configuration;
using Artemis.Auth.Api.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AutoMapper;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
// Order matters: Application -> Infrastructure -> API

// 1. Application layer services (CQRS, Validation, Mapping)
builder.Services.AddApplication();

// 2. Infrastructure layer services (Database, External Services)
builder.Services.AddInfrastructure(builder.Configuration);

// 3. API layer services
builder.Services.AddControllers();

// AutoMapper configuration
builder.Services.AddAutoMapper(typeof(Program).Assembly);

// MediatR registration
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(Program).Assembly));

// API Versioning
builder.Services.AddApiVersioningConfiguration();

// Rate Limiting
builder.Services.AddCustomRateLimiting();

// Security Headers
builder.Services.AddSecurityHeaders(options =>
{
    options.ContentSecurityPolicy.Value = 
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
});

// JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"] ?? throw new InvalidOperationException("JWT Secret Key is not configured"))),
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                var result = System.Text.Json.JsonSerializer.Serialize(new { error = "Invalid token" });
                return context.Response.WriteAsync(result);
            },
            OnChallenge = context =>
            {
                context.HandleResponse();
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                var result = System.Text.Json.JsonSerializer.Serialize(new { error = "Authentication required" });
                return context.Response.WriteAsync(result);
            }
        };
    });

// Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));
    
    options.AddPolicy("UserManagement", policy =>
        policy.RequireRole("Admin", "UserManager"));
    
    options.AddPolicy("SystemAccess", policy =>
        policy.RequireRole("Admin", "System"));
    
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// CORS policy for microservice architecture
builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", policy =>
    {
        policy.WithOrigins("https://localhost:3000", "https://localhost:4200", "https://artemis-web.com")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
    
    options.AddPolicy("ApiPolicy", policy =>
    {
        policy.AllowAnyOrigin()
              .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
              .AllowAnyHeader();
    });
});

// Health checks for monitoring
builder.Services.AddHealthChecks()
    .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy())
    .AddDbContextCheck<Artemis.Auth.Infrastructure.Persistence.AuthDbContext>();

// Swagger/OpenAPI configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerConfiguration();

// Custom middleware services
builder.Services.AddTransient<ErrorHandlingMiddleware>();
builder.Services.AddTransient<CustomJwtAuthenticationMiddleware>();
builder.Services.AddTransient<SecurityHeadersMiddleware>();
builder.Services.AddTransient<RateLimitingMiddleware>();

var app = builder.Build();

// Configure the HTTP request pipeline
// Order is critical for security and functionality

// 1. Error handling (should be first)
app.UseMiddleware<ErrorHandlingMiddleware>();

// 2. Security headers
app.UseSecurityHeaders();

// 3. HTTPS redirection and security
app.UseHsts();
app.UseHttpsRedirection();

// 4. CORS
app.UseCors("DefaultPolicy");

// 5. Rate limiting
app.UseRateLimiter();

// 6. Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// 7. API versioning
app.UseApiVersioningConfiguration();

// 8. Swagger (development only)
if (app.Environment.IsDevelopment())
{
    var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
    app.UseSwaggerConfiguration(provider);
}

// 9. Health checks endpoint
app.MapHealthChecks("/health");

// 10. Map controllers
app.MapControllers();

app.Run();