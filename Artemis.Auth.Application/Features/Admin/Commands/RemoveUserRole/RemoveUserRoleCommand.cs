using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Admin.Commands.RemoveUserRole;

public class RemoveUserRoleCommand : IRequest<Result>
{
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    public Guid RemovedBy { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}