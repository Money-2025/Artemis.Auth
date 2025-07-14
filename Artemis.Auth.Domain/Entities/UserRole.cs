namespace Artemis.Auth.Domain.Entities;

public class UserRole : AuditableEntity
{
    // Many-to-one relationships (Foreign Keys)
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    
    public DateTime AssignedAt { get; set; }
    public Guid? AssignedBy { get; set; }
    
    // Navigation properties
    public virtual User User { get; set; } = null!;
    public virtual Role Role { get; set; } = null!;
}