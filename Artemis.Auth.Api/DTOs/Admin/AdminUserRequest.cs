using System.ComponentModel.DataAnnotations;

namespace Artemis.Auth.Api.DTOs.Admin;

/// <summary>
/// Admin user update request DTO
/// </summary>
public class AdminUserRequest
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
    /// Whether email is confirmed
    /// </summary>
    public bool? EmailConfirmed { get; set; }

    /// <summary>
    /// Whether phone is confirmed
    /// </summary>
    public bool? PhoneConfirmed { get; set; }

    /// <summary>
    /// Whether account is locked
    /// </summary>
    public bool? IsLocked { get; set; }

    /// <summary>
    /// Account lockout end time
    /// </summary>
    public DateTime? LockoutEnd { get; set; }

    /// <summary>
    /// Reset failed login attempts
    /// </summary>
    public bool? ResetFailedAttempts { get; set; }

    /// <summary>
    /// Force password change on next login
    /// </summary>
    public bool? ForcePasswordChange { get; set; }

    /// <summary>
    /// Administrative notes
    /// </summary>
    [StringLength(1000, ErrorMessage = "Notes must not exceed 1000 characters")]
    public string? Notes { get; set; }
}

/// <summary>
/// Admin user role assignment request DTO
/// </summary>
public class AdminUserRoleRequest
{
    /// <summary>
    /// Role IDs to assign
    /// </summary>
    [Required(ErrorMessage = "At least one role must be specified")]
    public List<Guid> RoleIds { get; set; } = new();

    /// <summary>
    /// Whether to replace existing roles or add to them
    /// </summary>
    public bool ReplaceExisting { get; set; } = false;

    /// <summary>
    /// Administrative notes for the role assignment
    /// </summary>
    [StringLength(500, ErrorMessage = "Notes must not exceed 500 characters")]
    public string? Notes { get; set; }
}

/// <summary>
/// Admin user role assignment response DTO
/// </summary>
public class AdminUserRoleResponse
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
    /// User ID
    /// </summary>
    public Guid UserId { get; set; }

    /// <summary>
    /// Assigned roles
    /// </summary>
    public List<string> AssignedRoles { get; set; } = new();

    /// <summary>
    /// Removed roles
    /// </summary>
    public List<string> RemovedRoles { get; set; } = new();

    /// <summary>
    /// Current user roles
    /// </summary>
    public List<string> CurrentRoles { get; set; } = new();

    /// <summary>
    /// Assignment timestamp
    /// </summary>
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Admin user search request DTO
/// </summary>
public class AdminUserSearchRequest
{
    /// <summary>
    /// Search query (username, email, name)
    /// </summary>
    [StringLength(100, ErrorMessage = "Search query must not exceed 100 characters")]
    public string? Query { get; set; }

    /// <summary>
    /// Filter by role
    /// </summary>
    public Guid? RoleId { get; set; }

    /// <summary>
    /// Filter by email confirmation status
    /// </summary>
    public bool? EmailConfirmed { get; set; }

    /// <summary>
    /// Filter by lock status
    /// </summary>
    public bool? IsLocked { get; set; }

    /// <summary>
    /// Filter by MFA status
    /// </summary>
    public bool? TwoFactorEnabled { get; set; }

    /// <summary>
    /// Filter by creation date from
    /// </summary>
    public DateTime? CreatedFrom { get; set; }

    /// <summary>
    /// Filter by creation date to
    /// </summary>
    public DateTime? CreatedTo { get; set; }

    /// <summary>
    /// Filter by last login date from
    /// </summary>
    public DateTime? LastLoginFrom { get; set; }

    /// <summary>
    /// Filter by last login date to
    /// </summary>
    public DateTime? LastLoginTo { get; set; }

    /// <summary>
    /// Page number (1-based)
    /// </summary>
    [Range(1, int.MaxValue, ErrorMessage = "Page number must be greater than 0")]
    public int Page { get; set; } = 1;

    /// <summary>
    /// Page size
    /// </summary>
    [Range(1, 100, ErrorMessage = "Page size must be between 1 and 100")]
    public int PageSize { get; set; } = 20;

    /// <summary>
    /// Sort by field
    /// </summary>
    public string SortBy { get; set; } = "CreatedAt";

    /// <summary>
    /// Sort direction
    /// </summary>
    public string SortDirection { get; set; } = "desc";

    /// <summary>
    /// Include deleted users
    /// </summary>
    public bool IncludeDeleted { get; set; } = false;
}