using MediatR;
using Artemis.Auth.Application.Common.Wrappers;

namespace Artemis.Auth.Application.Features.Admin.Commands.DeleteUser;

public class DeleteUserCommand : IRequest<Result>
{
    public Guid UserId { get; set; }
    public Guid DeletedBy { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}