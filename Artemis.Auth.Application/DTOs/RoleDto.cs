namespace Artemis.Auth.Application.DTOs;

public class RoleDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<string> Permissions { get; set; } = new();
    public int UserCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public bool IsSystemRole { get; set; }
}

public class RoleSummaryDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public int UserCount { get; set; }
    public int PermissionCount { get; set; }
    public bool IsSystemRole { get; set; }
}

public class RoleCreateDto
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public List<string> Permissions { get; set; } = new();
}

public class RoleUpdateDto
{
    public string? Name { get; set; }
    public string? Description { get; set; }
    public List<string>? Permissions { get; set; }
}

public class PermissionDto
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Category { get; set; } = string.Empty;
    public bool IsSystemPermission { get; set; }
}

public class RoleAssignmentDto
{
    public Guid UserId { get; set; }
    public List<Guid> RoleIds { get; set; } = new();
    public string? Reason { get; set; }
}