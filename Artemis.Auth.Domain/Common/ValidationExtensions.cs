using System.Text.RegularExpressions;

namespace Artemis.Auth.Domain.Common;

public static class ValidationExtensions
{
    private static readonly Regex EmailRegex = new(
        @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    
    private static readonly Regex PhoneRegex = new(
        @"^\+?[1-9]\d{1,14}$",
        RegexOptions.Compiled);
    
    private static readonly Regex UsernameRegex = new(
        @"^[a-zA-Z0-9_\-\.]{3,50}$",
        RegexOptions.Compiled);
    
    public static bool IsValidEmail(this string email)
    {
        return !string.IsNullOrWhiteSpace(email) && EmailRegex.IsMatch(email);
    }
    
    public static bool IsValidPhoneNumber(this string phone)
    {
        return !string.IsNullOrWhiteSpace(phone) && PhoneRegex.IsMatch(phone);
    }
    
    public static bool IsValidUsername(this string username)
    {
        return !string.IsNullOrWhiteSpace(username) && UsernameRegex.IsMatch(username);
    }
    
    public static bool IsStrongPassword(this string password)
    {
        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
            return false;
            
        var hasUpper = password.Any(char.IsUpper);
        var hasLower = password.Any(char.IsLower);
        var hasDigit = password.Any(char.IsDigit);
        var hasSpecial = password.Any(c => "!@#$%^&*()_+-=[]{}|;':\",./<>?".Contains(c));
        
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }
    
    public static bool IsValidGuid(this Guid guid)
    {
        return guid != Guid.Empty;
    }
    
    public static bool IsValidLength(this string value, int minLength, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
            return minLength == 0;
            
        return value.Length >= minLength && value.Length <= maxLength;
    }
    
    public static bool IsInRange(this int value, int min, int max)
    {
        return value >= min && value <= max;
    }
    
    public static bool IsInRange(this DateTime value, DateTime min, DateTime max)
    {
        return value >= min && value <= max;
    }
    
    public static bool IsNotExpired(this DateTime expirationDate)
    {
        return expirationDate > DateTime.UtcNow;
    }
}