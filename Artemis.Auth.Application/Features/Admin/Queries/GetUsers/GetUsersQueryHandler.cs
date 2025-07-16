using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Queries.GetUsers;

public class GetUsersQueryHandler : IRequestHandler<GetUsersQuery, PagedResult<AdminUsersDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<GetUsersQueryHandler> _logger;

    public GetUsersQueryHandler(
        IUserRepository userRepository,
        IMapper mapper,
        ILogger<GetUsersQueryHandler> logger)
    {
        _userRepository = userRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<PagedResult<AdminUsersDto>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
    {
        try
        {
            var users = await _userRepository.SearchUsersAsync(
                searchTerm: request.SearchTerm ?? string.Empty,
                page: request.Page,
                pageSize: request.PageSize,
                cancellationToken: cancellationToken);

            var totalCount = await _userRepository.GetUserCountAsync(cancellationToken);

            var userDtos = new List<AdminUserDto>();
            foreach (var user in users)
            {
                var roles = await _userRepository.GetUserRolesAsync(user.Id, cancellationToken);
                userDtos.Add(new AdminUserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email,
                    FirstName = user.Username, // Using username as display name since no FirstName/LastName
                    LastName = string.Empty,
                    PhoneNumber = user.PhoneNumber,
                    Roles = roles.Select(r => new RoleDto { Name = r }).ToList(),
                    EmailConfirmed = user.EmailConfirmed,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    IsActive = !user.IsLockedOut(),
                    IsLocked = user.IsLockedOut(),
                    LockoutEnd = user.LockoutEnd,
                    AccessFailedCount = user.FailedLoginCount,
                    CreatedAt = user.CreatedAt,
                    UpdatedAt = user.ModifiedAt ?? user.CreatedAt,
                    LastLogin = user.LastLoginAt,
                    IsDeleted = user.IsDeleted,
                    DeletedAt = user.DeletedAt,
                    Status = user.IsLockedOut() ? "Locked" : user.IsDeleted ? "Deleted" : "Active"
                });
            }

            var result = new AdminUsersDto
            {
                Users = userDtos,
                CurrentPage = request.Page,
                PageSize = request.PageSize,
                TotalUsers = totalCount,
                TotalPages = (int)Math.Ceiling(totalCount / (double)request.PageSize)
            };

            return PagedResult<AdminUsersDto>.Success(result, request.Page, request.PageSize, totalCount, "Users retrieved successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving users by admin {RequestedBy}", request.RequestedBy);
            return PagedResult<AdminUsersDto>.Failure(request.Page, request.PageSize, "Failed to retrieve users");
        }
    }
}