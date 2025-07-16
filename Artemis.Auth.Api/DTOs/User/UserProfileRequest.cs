using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.User;

/// <summary>
/// User profile update request DTO
/// </summary>
public class UserProfileRequest
{
    /// <summary>
    /// First name
    /// </summary>
    [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "First name can only contain letters, spaces, hyphens, and apostrophes")]
    public string? FirstName { get; set; }

    /// <summary>
    /// Last name
    /// </summary>
    [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "Last name can only contain letters, spaces, hyphens, and apostrophes")]
    public string? LastName { get; set; }

    /// <summary>
    /// Email address
    /// </summary>
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(256, ErrorMessage = "Email must not exceed 256 characters")]
    public string? Email { get; set; }

    /// <summary>
    /// Phone number
    /// </summary>
    [Phone(ErrorMessage = "Invalid phone number format")]
    [StringLength(20, ErrorMessage = "Phone number must not exceed 20 characters")]
    public string? PhoneNumber { get; set; }

    /// <summary>
    /// Date of birth
    /// </summary>
    [DataType(DataType.Date)]
    public DateTime? DateOfBirth { get; set; }

    /// <summary>
    /// Profile picture URL
    /// </summary>
    [Url(ErrorMessage = "Invalid URL format")]
    [StringLength(500, ErrorMessage = "Profile picture URL must not exceed 500 characters")]
    public string? ProfilePictureUrl { get; set; }

    /// <summary>
    /// Bio or description
    /// </summary>
    [StringLength(1000, ErrorMessage = "Bio must not exceed 1000 characters")]
    public string? Bio { get; set; }

    /// <summary>
    /// Location
    /// </summary>
    [StringLength(100, ErrorMessage = "Location must not exceed 100 characters")]
    public string? Location { get; set; }

    /// <summary>
    /// Website URL
    /// </summary>
    [Url(ErrorMessage = "Invalid URL format")]
    [StringLength(500, ErrorMessage = "Website URL must not exceed 500 characters")]
    public string? WebsiteUrl { get; set; }

    /// <summary>
    /// Timezone
    /// </summary>
    [StringLength(50, ErrorMessage = "Timezone must not exceed 50 characters")]
    public string? Timezone { get; set; }

    /// <summary>
    /// Language preference
    /// </summary>
    [StringLength(10, ErrorMessage = "Language must not exceed 10 characters")]
    public string? Language { get; set; }

    /// <summary>
    /// Marketing emails preference
    /// </summary>
    public bool? AcceptMarketing { get; set; }

    /// <summary>
    /// Email notifications preference
    /// </summary>
    public bool? EmailNotifications { get; set; }

    /// <summary>
    /// Push notifications preference
    /// </summary>
    public bool? PushNotifications { get; set; }
}