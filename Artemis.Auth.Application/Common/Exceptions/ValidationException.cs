using FluentValidation.Results;

namespace Artemis.Auth.Application.Common.Exceptions;

public class ValidationException : Exception
{
    public Dictionary<string, List<string>> ValidationErrors { get; }
    
    public ValidationException() 
        : base("One or more validation failures have occurred.")
    {
        ValidationErrors = new Dictionary<string, List<string>>();
    }
    
    public ValidationException(string message) 
        : base(message)
    {
        ValidationErrors = new Dictionary<string, List<string>>();
    }
    
    public ValidationException(IEnumerable<ValidationFailure> failures) 
        : this()
    {
        ValidationErrors = failures
            .GroupBy(e => e.PropertyName, e => e.ErrorMessage)
            .ToDictionary(failureGroup => failureGroup.Key, failureGroup => failureGroup.ToList());
    }
    
    public ValidationException(Dictionary<string, List<string>> validationErrors) 
        : this()
    {
        ValidationErrors = validationErrors;
    }
    
    public ValidationException(string property, string error) 
        : this()
    {
        ValidationErrors.Add(property, new List<string> { error });
    }
    
    public ValidationException(string property, List<string> errors) 
        : this()
    {
        ValidationErrors.Add(property, errors);
    }
    
    public static ValidationException ForProperty(string property, string error)
    {
        return new ValidationException(property, error);
    }
    
    public static ValidationException ForProperties(Dictionary<string, List<string>> validationErrors)
    {
        return new ValidationException(validationErrors);
    }
    
    public static ValidationException UsernameTaken(string username)
    {
        return new ValidationException(nameof(username), $"Username '{username}' is already taken.");
    }
    
    public static ValidationException EmailTaken(string email)
    {
        return new ValidationException(nameof(email), $"Email '{email}' is already taken.");
    }
    
    public static ValidationException PhoneNumberTaken(string phoneNumber)
    {
        return new ValidationException(nameof(phoneNumber), $"Phone number '{phoneNumber}' is already taken.");
    }
    
    public static ValidationException WeakPassword()
    {
        return new ValidationException("Password", "Password does not meet security requirements.");
    }
    
    public static ValidationException PasswordMismatch()
    {
        return new ValidationException("Password", "Password and confirmation password do not match.");
    }
    
    public static ValidationException InvalidEmailFormat(string email)
    {
        return new ValidationException("Email", $"'{email}' is not a valid email format.");
    }
    
    public static ValidationException InvalidPhoneNumberFormat(string phoneNumber)
    {
        return new ValidationException("PhoneNumber", $"'{phoneNumber}' is not a valid phone number format.");
    }
    
    public static ValidationException RoleNotFound(string roleName)
    {
        return new ValidationException("Role", $"Role '{roleName}' was not found.");
    }
    
    public static ValidationException RoleAlreadyExists(string roleName)
    {
        return new ValidationException("Role", $"Role '{roleName}' already exists.");
    }
    
    public static ValidationException PermissionNotFound(string permission)
    {
        return new ValidationException("Permission", $"Permission '{permission}' was not found.");
    }
}