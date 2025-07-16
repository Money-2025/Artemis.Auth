using MediatR;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;

namespace Artemis.Auth.Application.Features.Admin.Commands.AssignUserRoles;

public class AssignUserRolesCommand : IRequest<Result<UserRolesDto>>
{
    public Guid UserId { get; set; }
    public List<Guid> RoleIds { get; set; } = new();
    public Guid AssignedBy { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}