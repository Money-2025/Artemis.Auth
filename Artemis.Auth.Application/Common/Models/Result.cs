namespace Artemis.Auth.Application.Common.Models;

/// <summary>
/// Represents the result of an operation without return data
/// </summary>
public class Result
{
    public bool Success { get; private set; }
    public string Message { get; private set; }
    public List<string> Errors { get; private set; }

    protected Result(bool success, string message, List<string> errors)
    {
        Success = success;
        Message = message;
        Errors = errors;
    }

    public static Result SuccessResult(string message = "Operation completed successfully")
    {
        return new Result(true, message, new List<string>());
    }

    public static Result FailureResult(string message, List<string>? errors = null)
    {
        return new Result(false, message, errors ?? new List<string>());
    }

    public static Result FailureResult(string message, string error)
    {
        return new Result(false, message, new List<string> { error });
    }

    public static Result FailureResult(List<string> errors)
    {
        return new Result(false, "Operation failed", errors);
    }

    public static implicit operator Result(bool success)
    {
        return success ? SuccessResult() : FailureResult("Operation failed");
    }
}

/// <summary>
/// Represents the result of an operation with return data
/// </summary>
public class Result<T> : Result
{
    public T? Data { get; private set; }

    private Result(bool success, string message, List<string> errors, T? data = default)
        : base(success, message, errors)
    {
        Data = data;
    }

    public static Result<T> SuccessResult(T data, string message = "Operation completed successfully")
    {
        return new Result<T>(true, message, new List<string>(), data);
    }

    public static new Result<T> FailureResult(string message, List<string>? errors = null)
    {
        return new Result<T>(false, message, errors ?? new List<string>());
    }

    public static new Result<T> FailureResult(string message, string error)
    {
        return new Result<T>(false, message, new List<string> { error });
    }

    public static new Result<T> FailureResult(List<string> errors)
    {
        return new Result<T>(false, "Operation failed", errors);
    }

    public static implicit operator Result<T>(T data)
    {
        return SuccessResult(data);
    }

}

/// <summary>
/// Extensions for Result handling
/// </summary>
public static class ResultExtensions
{
    public static Result<TOut> Map<TIn, TOut>(this Result<TIn> result, Func<TIn, TOut> mapping)
    {
        if (!result.Success)
        {
            return Result<TOut>.FailureResult(result.Message, result.Errors);
        }

        if (result.Data == null)
        {
            return Result<TOut>.FailureResult("Data is null");
        }

        var mappedData = mapping(result.Data);
        return Result<TOut>.SuccessResult(mappedData, result.Message);
    }

    public static async Task<Result<TOut>> MapAsync<TIn, TOut>(this Result<TIn> result, Func<TIn, Task<TOut>> mapping)
    {
        if (!result.Success)
        {
            return Result<TOut>.FailureResult(result.Message, result.Errors);
        }

        if (result.Data == null)
        {
            return Result<TOut>.FailureResult("Data is null");
        }

        var mappedData = await mapping(result.Data);
        return Result<TOut>.SuccessResult(mappedData, result.Message);
    }

    public static Result<T> Ensure<T>(this Result<T> result, Func<T, bool> predicate, string errorMessage)
    {
        if (!result.Success)
        {
            return result;
        }

        if (result.Data == null)
        {
            return Result<T>.FailureResult("Data is null");
        }

        if (!predicate(result.Data))
        {
            return Result<T>.FailureResult(errorMessage);
        }

        return result;
    }

    public static Result<T> OnSuccess<T>(this Result<T> result, Action<T> action)
    {
        if (result.Success && result.Data != null)
        {
            action(result.Data);
        }

        return result;
    }

    public static Result<T> OnFailure<T>(this Result<T> result, Action<string, List<string>> action)
    {
        if (!result.Success)
        {
            action(result.Message, result.Errors);
        }

        return result;
    }
}