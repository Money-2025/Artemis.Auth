namespace Artemis.Auth.Infrastructure.Common;

public class DatabaseConfiguration
{
    public DatabaseProvider Provider { get; set; } = DatabaseProvider.PostgreSQL;
    public string ConnectionString { get; set; } = string.Empty;
    public bool EnableSensitiveDataLogging { get; set; } = false;
    public int CommandTimeout { get; set; } = 30;
    public bool EnableRetryOnFailure { get; set; } = true;
    public int MaxRetryCount { get; set; } = 3;
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromSeconds(30);
}