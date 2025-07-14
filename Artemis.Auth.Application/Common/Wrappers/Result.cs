namespace Artemis.Auth.Application.Common.Wrappers;

public class Result
{
    public bool IsSuccess { get; init; }
    public string? Message { get; init; }
    public List<string> Errors { get; init; } = new();
    
    protected Result(bool isSuccess, string? message = null, List<string>? errors = null)
    {
        IsSuccess = isSuccess;
        Message = message;
        Errors = errors ?? new List<string>();
    }
    
    public static Result Success(string? message = null) => new(true, message);
    public static Result Failure(string error) => new(false, null, new List<string> { error });
    public static Result Failure(List<string> errors) => new(false, null, errors);
    public static Result Failure(string? message, List<string> errors) => new(false, message, errors);
}

public class Result<T> : Result
{
    public T? Data { get; init; }
    
    protected Result(bool isSuccess, T? data = default, string? message = null, List<string>? errors = null)
        : base(isSuccess, message, errors)
    {
        Data = data;
    }
    
    public static Result<T> Success(T data, string? message = null) => new(true, data, message);
    public static Result<T> Success(string? message = null) => new(true, default, message);
    public static new Result<T> Failure(string error) => new(false, default, null, new List<string> { error });
    public static new Result<T> Failure(List<string> errors) => new(false, default, null, errors);
    public static new Result<T> Failure(string? message, List<string> errors) => new(false, default, message, errors);
}

public class PagedResult<T> : Result<T>
{
    public int CurrentPage { get; init; }
    public int PageSize { get; init; }
    public int TotalPages { get; init; }
    public int TotalCount { get; init; }
    public bool HasPrevious => CurrentPage > 1;
    public bool HasNext => CurrentPage < TotalPages;
    
    protected PagedResult(bool isSuccess, T? data, int currentPage, int pageSize, int totalCount, string? message = null, List<string>? errors = null)
        : base(isSuccess, data, message, errors)
    {
        CurrentPage = currentPage;
        PageSize = pageSize;
        TotalCount = totalCount;
        TotalPages = (int)Math.Ceiling(totalCount / (double)pageSize);
    }
    
    public static PagedResult<T> Success(T data, int currentPage, int pageSize, int totalCount, string? message = null)
        => new(true, data, currentPage, pageSize, totalCount, message);
    
    public static PagedResult<T> Failure(int currentPage, int pageSize, string error)
        => new(false, default, currentPage, pageSize, 0, null, new List<string> { error });
    
    public static PagedResult<T> Failure(int currentPage, int pageSize, List<string> errors)
        => new(false, default, currentPage, pageSize, 0, null, errors);
}

public class ValidationResult : Result
{
    public Dictionary<string, List<string>> ValidationErrors { get; init; } = new();
    
    protected ValidationResult(bool isSuccess, Dictionary<string, List<string>> validationErrors, string? message = null)
        : base(isSuccess, message, validationErrors.SelectMany(x => x.Value).ToList())
    {
        ValidationErrors = validationErrors;
    }
    
    public static ValidationResult Success(string? message = null) => new(true, new Dictionary<string, List<string>>(), message);
    public static ValidationResult Failure(Dictionary<string, List<string>> validationErrors, string? message = null) => new(false, validationErrors, message);
    public static ValidationResult Failure(string property, string error) => new(false, new Dictionary<string, List<string>> { { property, new List<string> { error } } });
}

public class ValidationResult<T> : Result<T>
{
    public Dictionary<string, List<string>> ValidationErrors { get; init; } = new();
    
    protected ValidationResult(bool isSuccess, T? data, Dictionary<string, List<string>> validationErrors, string? message = null)
        : base(isSuccess, data, message, validationErrors.SelectMany(x => x.Value).ToList())
    {
        ValidationErrors = validationErrors;
    }
    
    public static ValidationResult<T> Success(T data, string? message = null) => new(true, data, new Dictionary<string, List<string>>(), message);
    public static ValidationResult<T> Success(string? message = null) => new(true, default, new Dictionary<string, List<string>>(), message);
    public static ValidationResult<T> Failure(Dictionary<string, List<string>> validationErrors, string? message = null) => new(false, default, validationErrors, message);
    public static ValidationResult<T> Failure(string property, string error) => new(false, default, new Dictionary<string, List<string>> { { property, new List<string> { error } } });
}