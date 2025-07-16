using MediatR;
using Artemis.Auth.Application.Common.Models;
using Artemis.Auth.Application.Features.Users.Commands.UpdateUserProfile;

namespace Artemis.Auth.Application.Features.Users.Queries.GetUserProfile;

public class GetUserProfileQuery : IRequest<Result<UserProfileDto>>
{
    public Guid UserId { get; set; }
    public bool IncludeRoles { get; set; } = true;
    public bool IncludePermissions { get; set; } = true;
    public bool IncludeSessions { get; set; } = false;
}