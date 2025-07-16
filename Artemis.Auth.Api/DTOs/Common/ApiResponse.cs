using System.Text.Json.Serialization;

namespace Artemis.Auth.Api.DTOs.Common;

/// <summary>
/// Generic API response wrapper
/// </summary>
/// <typeparam name="T">Response data type</typeparam>
public class ApiResponse<T>
{
    /// <summary>
    /// Success flag
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Response message
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Response data
    /// </summary>
    public T? Data { get; set; }

    /// <summary>
    /// Error details
    /// </summary>
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// Additional metadata
    /// </summary>
    public Dictionary<string, object> Meta { get; set; } = new();

    /// <summary>
    /// Response timestamp
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Trace ID for debugging
    /// </summary>
    public string? TraceId { get; set; }

    /// <summary>
    /// API version
    /// </summary>
    public string ApiVersion { get; set; } = "1.0";

    /// <summary>
    /// Creates a successful response
    /// </summary>
    public static ApiResponse<T> SuccessResponse(T data, string message = "Success")
    {
        return new ApiResponse<T>
        {
            Success = true,
            Message = message,
            Data = data
        };
    }

    /// <summary>
    /// Creates an error response
    /// </summary>
    public static ApiResponse<T> ErrorResponse(string message, List<string>? errors = null)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Errors = errors ?? new List<string>()
        };
    }

    /// <summary>
    /// Creates an error response with single error
    /// </summary>
    public static ApiResponse<T> ErrorResponse(string message, string error)
    {
        return new ApiResponse<T>
        {
            Success = false,
            Message = message,
            Errors = new List<string> { error }
        };
    }

    /// <summary>
    /// Creates a validation error response
    /// </summary>
    public static ApiResponse<T> ValidationErrorResponse(Dictionary<string, string[]> validationErrors)
    {
        var errors = new List<string>();
        foreach (var error in validationErrors)
        {
            errors.AddRange(error.Value);
        }

        return new ApiResponse<T>
        {
            Success = false,
            Message = "Validation failed",
            Errors = errors,
            Meta = new Dictionary<string, object>
            {
                ["ValidationErrors"] = validationErrors
            }
        };
    }
}

/// <summary>
/// Non-generic API response
/// </summary>
public class ApiResponse : ApiResponse<object>
{
    /// <summary>
    /// Creates a successful response without data
    /// </summary>
    public static ApiResponse SuccessResponse(string message = "Success")
    {
        return new ApiResponse
        {
            Success = true,
            Message = message
        };
    }

    /// <summary>
    /// Creates an error response without data
    /// </summary>
    public static new ApiResponse ErrorResponse(string message, List<string>? errors = null)
    {
        return new ApiResponse
        {
            Success = false,
            Message = message,
            Errors = errors ?? new List<string>()
        };
    }

    /// <summary>
    /// Creates an error response with single error
    /// </summary>
    public static new ApiResponse ErrorResponse(string message, string error)
    {
        return new ApiResponse
        {
            Success = false,
            Message = message,
            Errors = new List<string> { error }
        };
    }
}

/// <summary>
/// Paginated API response
/// </summary>
/// <typeparam name="T">Response data type</typeparam>
public class PaginatedApiResponse<T> : ApiResponse<List<T>>
{
    /// <summary>
    /// Current page number
    /// </summary>
    public int CurrentPage { get; set; }

    /// <summary>
    /// Total number of pages
    /// </summary>
    public int TotalPages { get; set; }

    /// <summary>
    /// Page size
    /// </summary>
    public int PageSize { get; set; }

    /// <summary>
    /// Total number of items
    /// </summary>
    public int TotalItems { get; set; }

    /// <summary>
    /// Whether there are more pages
    /// </summary>
    public bool HasNextPage { get; set; }

    /// <summary>
    /// Whether there are previous pages
    /// </summary>
    public bool HasPreviousPage { get; set; }

    /// <summary>
    /// First item index on current page
    /// </summary>
    public int FirstItemIndex => (CurrentPage - 1) * PageSize + 1;

    /// <summary>
    /// Last item index on current page
    /// </summary>
    public int LastItemIndex => Math.Min(CurrentPage * PageSize, TotalItems);

    /// <summary>
    /// Creates a successful paginated response
    /// </summary>
    public static PaginatedApiResponse<T> SuccessResponse(
        List<T> data,
        int currentPage,
        int totalPages,
        int pageSize,
        int totalItems,
        string message = "Success")
    {
        return new PaginatedApiResponse<T>
        {
            Success = true,
            Message = message,
            Data = data,
            CurrentPage = currentPage,
            TotalPages = totalPages,
            PageSize = pageSize,
            TotalItems = totalItems,
            HasNextPage = currentPage < totalPages,
            HasPreviousPage = currentPage > 1
        };
    }

    /// <summary>
    /// Creates an error paginated response
    /// </summary>
    public static PaginatedApiResponse<T> ErrorResponse(string message, List<string>? errors = null)
    {
        return new PaginatedApiResponse<T>
        {
            Success = false,
            Message = message,
            Errors = errors ?? new List<string>(),
            Data = new List<T>()
        };
    }
}