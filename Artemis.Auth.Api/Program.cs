using Artemis.Auth.Application;
using Artemis.Auth.Infrastructure.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
// Order matters: Application -> Infrastructure -> API

// 1. Application layer services (CQRS, Validation, Mapping)
builder.Services.AddApplication();

// 2. Infrastructure layer services (Database, External Services)
builder.Services.AddInfrastructure(builder.Configuration);

// 3. API layer services
builder.Services.AddControllers();

// CORS policy for microservice architecture
builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Health checks for monitoring
builder.Services.AddHealthChecks();

// TODO: Add API versioning in future iterations

// Swagger/OpenAPI configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Artemis Auth API",
        Version = "v1",
        Description = "Authentication and Authorization Microservice",
        Contact = new Microsoft.OpenApi.Models.OpenApiContact
        {
            Name = "Artemis Auth Team",
            Email = "auth-team@artemis.com"
        }
    });

    // JWT Bearer token configuration for Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Artemis Auth API v1");
        c.RoutePrefix = string.Empty; // Serve Swagger UI at the app's root
    });
}

// Security headers
app.UseHsts();
app.UseHttpsRedirection();

// CORS
app.UseCors("DefaultPolicy");

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// Health checks endpoint
app.MapHealthChecks("/health");

// Map controllers
app.MapControllers();

app.Run();