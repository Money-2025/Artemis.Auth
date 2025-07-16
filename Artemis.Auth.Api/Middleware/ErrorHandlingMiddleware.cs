using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Common.Exceptions;

namespace Artemis.Auth.Api.Middleware;

/// <summary>
/// Global error handling middleware for consistent error responses
/// </summary>
public class ErrorHandlingMiddleware : IMiddleware
{
    private readonly ILogger<ErrorHandlingMiddleware> _logger;
    private readonly IWebHostEnvironment _environment;

    /// <summary>
    /// Initializes the error handling middleware
    /// </summary>
    public ErrorHandlingMiddleware(
        ILogger<ErrorHandlingMiddleware> logger,
        IWebHostEnvironment environment)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _environment = environment ?? throw new ArgumentNullException(nameof(environment));
    }

    /// <summary>
    /// Handles errors and returns consistent error responses
    /// </summary>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex)
        {
            await HandleExceptionAsync(context, ex);
        }
    }

    /// <summary>
    /// Handles exceptions and creates appropriate error responses
    /// </summary>
    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        var traceId = context.TraceIdentifier;
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        
        // Log the exception with context
        _logger.LogError(exception, 
            "Error occurred. TraceId: {TraceId}, IP: {IpAddress}, Path: {Path}, Method: {Method}",
            traceId, ipAddress, context.Request.Path, context.Request.Method);

        var errorResponse = exception switch
        {
            ValidationException validationEx => CreateValidationErrorResponse(validationEx, traceId),
            UnauthorizedException unauthorizedEx => CreateUnauthorizedErrorResponse(unauthorizedEx, traceId),
            ForbiddenException forbiddenEx => CreateForbiddenErrorResponse(forbiddenEx, traceId),
            NotFoundException notFoundEx => CreateNotFoundErrorResponse(notFoundEx, traceId),
            ConflictException conflictEx => CreateConflictErrorResponse(conflictEx, traceId),
            BusinessRuleException businessEx => CreateBusinessRuleErrorResponse(businessEx, traceId),
            RateLimitException rateLimitEx => CreateRateLimitErrorResponse(rateLimitEx, traceId),
            _ => CreateInternalServerErrorResponse(exception, traceId)
        };

        context.Response.StatusCode = errorResponse.StatusCode;
        context.Response.ContentType = "application/json";

        var jsonResponse = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });

        await context.Response.WriteAsync(jsonResponse);
    }

    /// <summary>
    /// Creates validation error response
    /// </summary>
    private ErrorResponse CreateValidationErrorResponse(ValidationException exception, string traceId)
    {
        var validationErrors = exception.ValidationErrors?.ToDictionary(
            kvp => kvp.Key, 
            kvp => kvp.Value.ToArray()
        );

        return new ErrorResponse
        {
            Code = "VALIDATION_ERROR",
            Message = "One or more validation errors occurred",
            Details = exception.Message,
            StatusCode = (int)HttpStatusCode.BadRequest,
            TraceId = traceId,
            ValidationErrors = validationErrors,
            Meta = new Dictionary<string, object>
            {
                ["ValidationFailures"] = exception.ValidationErrors?.Count ?? 0
            }
        };
    }

    /// <summary>
    /// Creates unauthorized error response
    /// </summary>
    private ErrorResponse CreateUnauthorizedErrorResponse(UnauthorizedException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "UNAUTHORIZED",
            Message = exception.Message,
            Details = "Authentication is required to access this resource",
            StatusCode = (int)HttpStatusCode.Unauthorized,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RequiredAuthentication"] = true
            }
        };
    }

    /// <summary>
    /// Creates forbidden error response
    /// </summary>
    private ErrorResponse CreateForbiddenErrorResponse(ForbiddenException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "FORBIDDEN",
            Message = exception.Message,
            Details = "You don't have permission to access this resource",
            StatusCode = (int)HttpStatusCode.Forbidden,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RequiredPermission"] = exception.RequiredPermission ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates not found error response
    /// </summary>
    private ErrorResponse CreateNotFoundErrorResponse(NotFoundException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "NOT_FOUND",
            Message = exception.Message,
            Details = "The requested resource was not found",
            StatusCode = (int)HttpStatusCode.NotFound,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ResourceType"] = exception.EntityName ?? "Unknown",
                ["ResourceId"] = exception.EntityId?.ToString() ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates conflict error response
    /// </summary>
    private ErrorResponse CreateConflictErrorResponse(ConflictException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "CONFLICT",
            Message = exception.Message,
            Details = "The request conflicts with the current state of the resource",
            StatusCode = (int)HttpStatusCode.Conflict,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ConflictType"] = exception.ConflictType ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates business rule error response
    /// </summary>
    private ErrorResponse CreateBusinessRuleErrorResponse(BusinessRuleException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "BUSINESS_RULE_VIOLATION",
            Message = exception.Message,
            Details = exception.Details,
            StatusCode = (int)HttpStatusCode.BadRequest,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RuleType"] = exception.RuleType ?? "Unknown"
            }
        };
    }

    /// <summary>
    /// Creates rate limit error response
    /// </summary>
    private ErrorResponse CreateRateLimitErrorResponse(RateLimitException exception, string traceId)
    {
        return new ErrorResponse
        {
            Code = "RATE_LIMIT_EXCEEDED",
            Message = exception.Message,
            Details = "Too many requests. Please try again later.",
            StatusCode = (int)HttpStatusCode.TooManyRequests,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["RetryAfter"] = exception.RetryAfter?.TotalSeconds ?? 60,
                ["Limit"] = exception.Limit,
                ["Window"] = exception.Window?.TotalSeconds ?? 60
            }
        };
    }

    /// <summary>
    /// Creates internal server error response
    /// </summary>
    private ErrorResponse CreateInternalServerErrorResponse(Exception exception, string traceId)
    {
        var message = _environment.IsDevelopment() 
            ? exception.Message 
            : "An internal server error occurred";
            
        var details = _environment.IsDevelopment() 
            ? exception.ToString() 
            : "Please contact support if the problem persists";

        return new ErrorResponse
        {
            Code = "INTERNAL_SERVER_ERROR",
            Message = message,
            Details = details,
            StatusCode = (int)HttpStatusCode.InternalServerError,
            TraceId = traceId,
            Meta = new Dictionary<string, object>
            {
                ["ExceptionType"] = exception.GetType().Name,
                ["IsDevelopment"] = _environment.IsDevelopment()
            }
        };
    }
}

/// <summary>
/// Rate limit exception for rate limiting middleware
/// </summary>
public class RateLimitException : Exception
{
    public int Limit { get; }
    public TimeSpan? Window { get; }
    public TimeSpan? RetryAfter { get; }

    public RateLimitException(string message, int limit, TimeSpan? window = null, TimeSpan? retryAfter = null) 
        : base(message)
    {
        Limit = limit;
        Window = window;
        RetryAfter = retryAfter;
    }
}