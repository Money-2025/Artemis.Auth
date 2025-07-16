using MediatR;
using AutoMapper;
using Microsoft.Extensions.Logging;
using Artemis.Auth.Application.Common.Wrappers;
using Artemis.Auth.Application.DTOs;
using Artemis.Auth.Application.Contracts.Persistence;

namespace Artemis.Auth.Application.Features.Admin.Commands.AssignUserRoles;

public class AssignUserRolesCommandHandler : IRequestHandler<AssignUserRolesCommand, Result<UserRolesDto>>
{
    private readonly IUserRepository _userRepository;
    private readonly IRoleRepository _roleRepository;
    private readonly IMapper _mapper;
    private readonly ILogger<AssignUserRolesCommandHandler> _logger;

    public AssignUserRolesCommandHandler(
        IUserRepository userRepository,
        IRoleRepository roleRepository,
        IMapper mapper,
        ILogger<AssignUserRolesCommandHandler> logger)
    {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _mapper = mapper;
        _logger = logger;
    }

    public async Task<Result<UserRolesDto>> Handle(AssignUserRolesCommand request, CancellationToken cancellationToken)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            
            if (user == null)
            {
                return Result<UserRolesDto>.Failure("User not found");
            }

            // Validate that all roles exist
            var allRoles = await _roleRepository.GetAllAsync();
            var existingRoleIds = allRoles.Select(r => r.Id).ToList();
            var invalidRoleIds = request.RoleIds.Except(existingRoleIds).ToList();
            
            if (invalidRoleIds.Any())
            {
                return Result<UserRolesDto>.Failure("One or more roles not found");
            }

            // Assign roles to user using existing repository methods
            foreach (var roleId in request.RoleIds)
            {
                await _roleRepository.AssignRoleToUserAsync(request.UserId, roleId, request.AssignedBy);
            }

            var userRoles = await _roleRepository.GetByUserIdAsync(request.UserId);
            var userRolesDto = new UserRolesDto
            {
                UserId = request.UserId,
                Roles = userRoles.Select(r => new RoleDto 
                { 
                    Id = r.Id, 
                    Name = r.Name, 
                    Description = r.Description,
                    CreatedAt = r.CreatedAt,
                    ModifiedAt = r.ModifiedAt,
                    IsSystemRole = false,
                    UserCount = 0,
                    Permissions = new List<string>()
                }).ToList(),
                LastUpdated = DateTime.UtcNow
            };

            return Result<UserRolesDto>.Success(userRolesDto, "Roles assigned successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning roles to user {UserId} by admin {AssignedBy}", request.UserId, request.AssignedBy);
            return Result<UserRolesDto>.Failure("Failed to assign roles");
        }
    }
}