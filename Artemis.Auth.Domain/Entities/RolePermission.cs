namespace Artemis.Auth.Domain.Entities;

public class RolePermission : AuditableEntity
{
    public string Permission { get; set; } = string.Empty;
    
    // Many-to-one relationship
    public Guid RoleId { get; set; }
    public virtual Role Role { get; set; }
}