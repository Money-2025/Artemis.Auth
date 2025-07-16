using MediatR;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;

namespace Artemis.Auth.Application.Features.Admin.Queries.GetUserById;

public class GetUserByIdQuery : IRequest<Result<UserProfileDto>>
{
    public Guid UserId { get; set; }
    public Guid RequestedBy { get; set; }
}