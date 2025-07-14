using MediatR;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Users.Commands.UpdateUserProfile;

public class UpdateUserProfileCommand : IRequest<Result<UserProfileDto>>
{
    public Guid UserId { get; set; }
    public string? Email { get; set; }
    public string? PhoneNumber { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool? TwoFactorEnabled { get; set; }
    public string? CurrentPassword { get; set; }
    public string? NewPassword { get; set; }
    public string? ConfirmPassword { get; set; }
}