namespace Artemis.Auth.Domain.Common;

public class ValidationResult
{
    public bool IsValid { get; init; }
    public List<ValidationError> Errors { get; init; } = new();
    
    public static ValidationResult Success() => new() { IsValid = true };
    
    public static ValidationResult Failure(params ValidationError[] errors) => new()
    {
        IsValid = false,
        Errors = errors.ToList()
    };
    
    public static ValidationResult Failure(string property, string message) => new()
    {
        IsValid = false,
        Errors = new List<ValidationError> { new(property, message) }
    };
}

public record ValidationError(string Property, string Message);