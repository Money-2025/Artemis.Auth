using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using AutoMapper;
using MediatR;
using Artemis.Auth.Api.DTOs.Admin;
using Artemis.Auth.Api.DTOs.Common;
using Artemis.Auth.Application.Features.Admin.Queries.GetUsers;
using Artemis.Auth.Application.Features.Admin.Queries.GetUserById;
using Artemis.Auth.Application.Features.Admin.Commands.UpdateUser;
using Artemis.Auth.Application.Features.Admin.Commands.DeleteUser;
using Artemis.Auth.Application.Features.Admin.Commands.AssignUserRoles;
using Artemis.Auth.Application.Features.Admin.Commands.RemoveUserRole;

namespace Artemis.Auth.Api.Controllers;

/// <summary>
/// Admin controller providing comprehensive user management endpoints
/// Requires administrator privileges for all operations
/// </summary>
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[Authorize(Policy = "AdminOnly")]
[Produces("application/json")]
[EnableRateLimiting("AdminPolicy")]
public class AdminController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IMapper _mapper;
    private readonly ILogger<AdminController> _logger;

    /// <summary>
    /// Initializes the admin controller
    /// </summary>
    public AdminController(
        IMediator mediator,
        IMapper mapper,
        ILogger<AdminController> logger)
    {
        _mediator = mediator ?? throw new ArgumentNullException(nameof(mediator));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Gets paginated list of users with advanced filtering and search
    /// </summary>
    /// <param name="request">Search and filter parameters</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Paginated list of users</returns>
    /// <response code="200">Users retrieved successfully</response>
    /// <response code="400">Invalid request parameters</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    [HttpGet("users")]
    [ProducesResponseType(typeof(PaginatedApiResponse<AdminUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetUsers(
        [FromQuery] AdminUserSearchRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin user list request by admin: {AdminId}", adminId);

            var query = _mapper.Map<GetUsersQuery>(request);
            query.RequestedBy = adminId;
            
            var result = await _mediator.Send(query, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin user list failed for admin: {AdminId}. Reason: {Reason}", 
                    adminId, result.Message);

                return BadRequest(ErrorResponse.CustomError("USER_LIST_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<AdminUsersResponse>(result.Data);
            
            _logger.LogInformation("Admin user list retrieved successfully by admin: {AdminId}", adminId);

            return Ok(PaginatedApiResponse<AdminUserResponse>.SuccessResponse(
                response.Users,
                response.CurrentPage,
                response.TotalPages,
                response.PageSize,
                response.TotalUsers,
                "Users retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving users for admin: {AdminId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("User list retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Gets detailed information about a specific user
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Detailed user information</returns>
    /// <response code="200">User retrieved successfully</response>
    /// <response code="400">Invalid user ID</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User not found</response>
    [HttpGet("users/{userId:guid}")]
    [ProducesResponseType(typeof(ApiResponse<AdminUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetUserById(
        [FromRoute] Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin user details request by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            var query = new GetUserByIdQuery
            {
                UserId = userId,
                RequestedBy = adminId
            };
            
            var result = await _mediator.Send(query, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin user details failed for admin: {AdminId}, user: {UserId}. Reason: {Reason}", 
                    adminId, userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("USER_DETAILS_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<AdminUserResponse>(result.Data);
            
            _logger.LogInformation("Admin user details retrieved successfully by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            return Ok(ApiResponse<AdminUserResponse>.SuccessResponse(response, "User details retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user details for admin: {AdminId}, user: {UserId}", 
                GetCurrentUserId(), userId);
            return StatusCode(500, ErrorResponse.InternalServerError("User details retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Updates a user's information
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="request">User update request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated user information</returns>
    /// <response code="200">User updated successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User not found</response>
    [HttpPut("users/{userId:guid}")]
    [EnableRateLimiting("AdminUserUpdatePolicy")]
    [ProducesResponseType(typeof(ApiResponse<AdminUserResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UpdateUser(
        [FromRoute] Guid userId,
        [FromBody] AdminUserRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin user update request by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            var command = _mapper.Map<UpdateUserCommand>(request);
            command.UserId = userId;
            command.UpdatedBy = adminId;
            command.IpAddress = GetClientIpAddress();
            command.UserAgent = GetUserAgent();
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin user update failed for admin: {AdminId}, user: {UserId}. Reason: {Reason}", 
                    adminId, userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("USER_UPDATE_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<AdminUserResponse>(result.Data);
            
            _logger.LogInformation("Admin user update successful for admin: {AdminId}, user: {UserId}", 
                adminId, userId);

            return Ok(ApiResponse<AdminUserResponse>.SuccessResponse(response, "User updated successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating user for admin: {AdminId}, user: {UserId}", 
                GetCurrentUserId(), userId);
            return StatusCode(500, ErrorResponse.InternalServerError("User update failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Soft deletes a user account
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Deletion response</returns>
    /// <response code="200">User deleted successfully</response>
    /// <response code="400">Invalid user ID</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User not found</response>
    [HttpDelete("users/{userId:guid}")]
    [EnableRateLimiting("AdminUserDeletePolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteUser(
        [FromRoute] Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin user deletion request by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            var command = new DeleteUserCommand
            {
                UserId = userId,
                DeletedBy = adminId,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin user deletion failed for admin: {AdminId}, user: {UserId}. Reason: {Reason}", 
                    adminId, userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("USER_DELETE_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            _logger.LogInformation("Admin user deletion successful for admin: {AdminId}, user: {UserId}", 
                adminId, userId);

            return Ok(ApiResponse.SuccessResponse("User deleted successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting user for admin: {AdminId}, user: {UserId}", 
                GetCurrentUserId(), userId);
            return StatusCode(500, ErrorResponse.InternalServerError("User deletion failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Assigns roles to a user
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="request">Role assignment request</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role assignment response</returns>
    /// <response code="200">Roles assigned successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User not found</response>
    [HttpPost("users/{userId:guid}/roles")]
    [EnableRateLimiting("AdminRoleAssignmentPolicy")]
    [ProducesResponseType(typeof(ApiResponse<AdminUserRoleResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> AssignUserRoles(
        [FromRoute] Guid userId,
        [FromBody] AdminUserRoleRequest request,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin role assignment request by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            var command = _mapper.Map<AssignUserRolesCommand>(request);
            command.UserId = userId;
            command.AssignedBy = adminId;
            command.IpAddress = GetClientIpAddress();
            command.UserAgent = GetUserAgent();
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin role assignment failed for admin: {AdminId}, user: {UserId}. Reason: {Reason}", 
                    adminId, userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("ROLE_ASSIGNMENT_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            var response = _mapper.Map<AdminUserRoleResponse>(result.Data);
            
            _logger.LogInformation("Admin role assignment successful for admin: {AdminId}, user: {UserId}", 
                adminId, userId);

            return Ok(ApiResponse<AdminUserRoleResponse>.SuccessResponse(response, "Roles assigned successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error assigning roles for admin: {AdminId}, user: {UserId}", 
                GetCurrentUserId(), userId);
            return StatusCode(500, ErrorResponse.InternalServerError("Role assignment failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Removes a specific role from a user
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="roleId">Role ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Role removal response</returns>
    /// <response code="200">Role removed successfully</response>
    /// <response code="400">Invalid request data</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User or role not found</response>
    [HttpDelete("users/{userId:guid}/roles/{roleId:guid}")]
    [EnableRateLimiting("AdminRoleAssignmentPolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RemoveUserRole(
        [FromRoute] Guid userId,
        [FromRoute] Guid roleId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin role removal request by admin: {AdminId} for user: {UserId}, role: {RoleId}", 
                adminId, userId, roleId);

            var command = new RemoveUserRoleCommand
            {
                UserId = userId,
                RoleId = roleId,
                RemovedBy = adminId,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin role removal failed for admin: {AdminId}, user: {UserId}, role: {RoleId}. Reason: {Reason}", 
                    adminId, userId, roleId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("ROLE_REMOVAL_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            _logger.LogInformation("Admin role removal successful for admin: {AdminId}, user: {UserId}, role: {RoleId}", 
                adminId, userId, roleId);

            return Ok(ApiResponse.SuccessResponse("Role removed successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing role for admin: {AdminId}, user: {UserId}, role: {RoleId}", 
                GetCurrentUserId(), userId, roleId);
            return StatusCode(500, ErrorResponse.InternalServerError("Role removal failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Unlocks a user account
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Unlock response</returns>
    /// <response code="200">User unlocked successfully</response>
    /// <response code="400">Invalid user ID</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    /// <response code="404">User not found</response>
    [HttpPost("users/{userId:guid}/unlock")]
    [EnableRateLimiting("AdminUserUpdatePolicy")]
    [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> UnlockUser(
        [FromRoute] Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin user unlock request by admin: {AdminId} for user: {UserId}", 
                adminId, userId);

            var command = new UpdateUserCommand
            {
                UserId = userId,
                IsLocked = false,
                LockoutEnd = null,
                ResetFailedAttempts = true,
                UpdatedBy = adminId,
                IpAddress = GetClientIpAddress(),
                UserAgent = GetUserAgent()
            };
            
            var result = await _mediator.Send(command, cancellationToken);

            if (!result.IsSuccess)
            {
                _logger.LogWarning("Admin user unlock failed for admin: {AdminId}, user: {UserId}. Reason: {Reason}", 
                    adminId, userId, result.Message);

                return result.Message.Contains("not found") 
                    ? NotFound(ErrorResponse.NotFoundError(result.Message, HttpContext.TraceIdentifier))
                    : BadRequest(ErrorResponse.CustomError("USER_UNLOCK_ERROR", result.Message, 400, HttpContext.TraceIdentifier));
            }

            _logger.LogInformation("Admin user unlock successful for admin: {AdminId}, user: {UserId}", 
                adminId, userId);

            return Ok(ApiResponse.SuccessResponse("User unlocked successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error unlocking user for admin: {AdminId}, user: {UserId}", 
                GetCurrentUserId(), userId);
            return StatusCode(500, ErrorResponse.InternalServerError("User unlock failed", HttpContext.TraceIdentifier));
        }
    }

    /// <summary>
    /// Gets system statistics and analytics
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>System statistics</returns>
    /// <response code="200">Statistics retrieved successfully</response>
    /// <response code="401">Unauthorized</response>
    /// <response code="403">Insufficient permissions</response>
    [HttpGet("statistics")]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> GetStatistics(CancellationToken cancellationToken = default)
    {
        try
        {
            var adminId = GetCurrentUserId();
            
            _logger.LogInformation("Admin statistics request by admin: {AdminId}", adminId);

            // This would typically call a specific query for system statistics
            // For now, returning a placeholder response
            var response = new
            {
                Users = new
                {
                    Total = 1250,
                    Active = 1180,
                    Locked = 25,
                    Deleted = 45,
                    NewToday = 12,
                    NewThisWeek = 85,
                    NewThisMonth = 340
                },
                Authentication = new
                {
                    TotalLogins = 15600,
                    SuccessfulLogins = 14950,
                    FailedLogins = 650,
                    LoginsToday = 450,
                    LoginsThisWeek = 3200,
                    LoginsThisMonth = 12800
                },
                Security = new
                {
                    MfaEnabled = 780,
                    MfaPercentage = 62.4,
                    SuspiciousAttempts = 15,
                    BlockedIps = 8,
                    SecurityEventsToday = 3
                },
                Sessions = new
                {
                    ActiveSessions = 342,
                    AverageSessionDuration = "45m",
                    MaxConcurrentSessions = 425,
                    SessionsToday = 890
                }
            };

            _logger.LogInformation("Admin statistics retrieved successfully by admin: {AdminId}", adminId);

            return Ok(ApiResponse<object>.SuccessResponse(response, "Statistics retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving statistics for admin: {AdminId}", GetCurrentUserId());
            return StatusCode(500, ErrorResponse.InternalServerError("Statistics retrieval failed", HttpContext.TraceIdentifier));
        }
    }

    #region Private Helper Methods

    /// <summary>
    /// Gets the client IP address
    /// </summary>
    private string GetClientIpAddress()
    {
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the user agent
    /// </summary>
    private string GetUserAgent()
    {
        return HttpContext.Request.Headers["User-Agent"].ToString() ?? "Unknown";
    }

    /// <summary>
    /// Gets the current user ID from JWT claims
    /// </summary>
    private Guid GetCurrentUserId()
    {
        var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(userIdClaim, out var userId) ? userId : Guid.Empty;
    }

    /// <summary>
    /// Gets the current username from JWT claims
    /// </summary>
    private string GetCurrentUsername()
    {
        return HttpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? "Unknown";
    }

    #endregion
}