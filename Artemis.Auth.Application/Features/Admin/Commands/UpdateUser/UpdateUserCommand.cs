using MediatR;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;

namespace Artemis.Auth.Application.Features.Admin.Commands.UpdateUser;

public class UpdateUserCommand : IRequest<Result<UserProfileDto>>
{
    public Guid UserId { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public bool? IsEmailVerified { get; set; }
    public bool? IsPhoneVerified { get; set; }
    public bool? IsLocked { get; set; }
    public DateTime? LockoutEnd { get; set; }
    public bool? ResetFailedAttempts { get; set; }
    public bool? TwoFactorEnabled { get; set; }
    public Guid UpdatedBy { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}