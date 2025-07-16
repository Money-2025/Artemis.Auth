using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Authentication;

/// <summary>
/// User registration request DTO with comprehensive validation
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// Username (unique identifier)
    /// </summary>
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_.-]+$", ErrorMessage = "Username can only contain letters, numbers, dots, hyphens, and underscores")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Email address
    /// </summary>
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Password with strong validation
    /// </summary>
    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 128 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$", 
        ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")]
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Password confirmation
    /// </summary>
    [Required(ErrorMessage = "Password confirmation is required")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    /// <summary>
    /// First name
    /// </summary>
    [Required(ErrorMessage = "First name is required")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "First name can only contain letters, spaces, hyphens, and apostrophes")]
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Last name
    /// </summary>
    [Required(ErrorMessage = "Last name is required")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "Last name can only contain letters, spaces, hyphens, and apostrophes")]
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Phone number (optional)
    /// </summary>
    [Phone(ErrorMessage = "Invalid phone number format")]
    [StringLength(20, ErrorMessage = "Phone number must not exceed 20 characters")]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Date of birth (optional)
    /// </summary>
    [DataType(DataType.Date)]
    public DateTime? DateOfBirth { get; set; }

    /// <summary>
    /// Terms of service acceptance
    /// </summary>
    [Required(ErrorMessage = "You must accept the terms of service")]
    [Range(typeof(bool), "true", "true", ErrorMessage = "You must accept the terms of service")]
    public bool AcceptTerms { get; set; } = false;

    /// <summary>
    /// Privacy policy acceptance
    /// </summary>
    [Required(ErrorMessage = "You must accept the privacy policy")]
    [Range(typeof(bool), "true", "true", ErrorMessage = "You must accept the privacy policy")]
    public bool AcceptPrivacyPolicy { get; set; } = false;

    /// <summary>
    /// Marketing emails opt-in
    /// </summary>
    public bool AcceptMarketing { get; set; } = false;

    /// <summary>
    /// Device information for tracking
    /// </summary>
    public string? DeviceInfo { get; set; }

    /// <summary>
    /// Client IP address (set by middleware)
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// User agent (set by middleware)
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// Registration source (web, mobile, api)
    /// </summary>
    public string Source { get; set; } = "web";

    /// <summary>
    /// Referral code (optional)
    /// </summary>
    [StringLength(50, ErrorMessage = "Referral code must not exceed 50 characters")]
    public string? ReferralCode { get; set; }
}