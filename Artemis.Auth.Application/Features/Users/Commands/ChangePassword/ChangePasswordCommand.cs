using MediatR;
using Artemis.Auth.Application.Common.Models;

namespace Artemis.Auth.Application.Features.Users.Commands.ChangePassword;

/// <summary>
/// Command to change user password
/// </summary>
public class ChangePasswordCommand : IRequest<Result<ChangePasswordDto>>
{
    public Guid UserId { get; set; }
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Change password response data transfer object
/// </summary>
public class ChangePasswordDto
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public DateTime ChangedAt { get; set; }
    public bool RequiresReauth { get; set; }
}