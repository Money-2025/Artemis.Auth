using System.Text.Json.Serialization;

namespace Artemis.Auth.Api.DTOs.Common;

/// <summary>
/// Standardized error response DTO
/// </summary>
public class ErrorResponse
{
    /// <summary>
    /// Error code
    /// </summary>
    public string Code { get; set; } = string.Empty;

    /// <summary>
    /// Error message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Detailed error description
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// Error source/field
    /// </summary>
    public string? Source { get; set; }

    /// <summary>
    /// HTTP status code
    /// </summary>
    public int StatusCode { get; set; }

    /// <summary>
    /// Error timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Trace ID for debugging
    /// </summary>
    public string? TraceId { get; set; }

    /// <summary>
    /// Additional error metadata
    /// </summary>
    public Dictionary<string, object> Meta { get; set; } = new();

    /// <summary>
    /// Validation errors (if applicable)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string[]>? ValidationErrors { get; set; }

    /// <summary>
    /// Inner errors (for nested error scenarios)
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<ErrorResponse>? InnerErrors { get; set; }

    /// <summary>
    /// Creates a validation error response
    /// </summary>
    public static ErrorResponse ValidationError(Dictionary<string, string[]> validationErrors, string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "VALIDATION_ERROR",
            Message = "One or more validation errors occurred",
            StatusCode = 400,
            ValidationErrors = validationErrors,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates an authentication error response
    /// </summary>
    public static ErrorResponse AuthenticationError(string message = "Authentication failed", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "AUTHENTICATION_ERROR",
            Message = message,
            StatusCode = 401,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates an authorization error response
    /// </summary>
    public static ErrorResponse AuthorizationError(string message = "Access denied", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "AUTHORIZATION_ERROR",
            Message = message,
            StatusCode = 403,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates a not found error response
    /// </summary>
    public static ErrorResponse NotFoundError(string message = "Resource not found", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "NOT_FOUND",
            Message = message,
            StatusCode = 404,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates a conflict error response
    /// </summary>
    public static ErrorResponse ConflictError(string message = "Resource conflict", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "CONFLICT",
            Message = message,
            StatusCode = 409,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates a rate limit error response
    /// </summary>
    public static ErrorResponse RateLimitError(string message = "Rate limit exceeded", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "RATE_LIMIT_EXCEEDED",
            Message = message,
            StatusCode = 429,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates an internal server error response
    /// </summary>
    public static ErrorResponse InternalServerError(string message = "Internal server error", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "INTERNAL_SERVER_ERROR",
            Message = message,
            StatusCode = 500,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates a service unavailable error response
    /// </summary>
    public static ErrorResponse ServiceUnavailableError(string message = "Service unavailable", string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = "SERVICE_UNAVAILABLE",
            Message = message,
            StatusCode = 503,
            TraceId = traceId
        };
    }

    /// <summary>
    /// Creates a custom error response
    /// </summary>
    public static ErrorResponse CustomError(string code, string message, int statusCode, string? traceId = null)
    {
        return new ErrorResponse
        {
            Code = code,
            Message = message,
            StatusCode = statusCode,
            TraceId = traceId
        };
    }
}

/// <summary>
/// Error response with multiple errors
/// </summary>
public class MultipleErrorResponse : ErrorResponse
{
    /// <summary>
    /// List of errors
    /// </summary>
    public List<ErrorResponse> Errors { get; set; } = new();

    /// <summary>
    /// Creates a multiple error response
    /// </summary>
    public static MultipleErrorResponse CreateMultipleErrors(List<ErrorResponse> errors, string? traceId = null)
    {
        return new MultipleErrorResponse
        {
            Code = "MULTIPLE_ERRORS",
            Message = "Multiple errors occurred",
            StatusCode = 400,
            Errors = errors,
            TraceId = traceId
        };
    }
}