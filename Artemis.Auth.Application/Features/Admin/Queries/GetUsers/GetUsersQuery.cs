using MediatR;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;

namespace Artemis.Auth.Application.Features.Admin.Queries.GetUsers;

/// <summary>
/// Query for getting users (admin)
/// </summary>
public class GetUsersQuery : IRequest<PagedResult<AdminUsersDto>>
{
    public Guid RequestedBy { get; set; }
    public string? SearchTerm { get; set; }
    public string? Status { get; set; }
    public string? Role { get; set; }
    public bool? IsLocked { get; set; }
    public bool? IsEmailVerified { get; set; }
    public string? SortBy { get; set; }
    public string? SortOrder { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
}

