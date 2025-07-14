namespace Artemis.Auth.Infrastructure.Common;

public enum DatabaseProvider
{
    PostgreSQL,
    SqlServer,
    MySQL,
    SQLite
}

public static class DatabaseProviderExtensions
{
    public static string GetCurrentTimestampSql(this DatabaseProvider provider)
    {
        return provider switch
        {
            DatabaseProvider.PostgreSQL => "NOW() AT TIME ZONE 'UTC'",
            DatabaseProvider.SqlServer => "GETUTCDATE()",
            DatabaseProvider.MySQL => "UTC_TIMESTAMP()",
            DatabaseProvider.SQLite => "DATETIME('now')",
            _ => throw new NotSupportedException($"Database provider {provider} is not supported")
        };
    }
    
    public static string GetBooleanFilterSql(this DatabaseProvider provider, string columnName, bool value)
    {
        return provider switch
        {
            DatabaseProvider.PostgreSQL => $"\"{columnName}\" = {value.ToString().ToLower()}",
            DatabaseProvider.SqlServer => $"[{columnName}] = {(value ? 1 : 0)}",
            DatabaseProvider.MySQL => $"`{columnName}` = {(value ? 1 : 0)}",
            DatabaseProvider.SQLite => $"[{columnName}] = {(value ? 1 : 0)}",
            _ => throw new NotSupportedException($"Database provider {provider} is not supported")
        };
    }
    
    public static string GetColumnQuote(this DatabaseProvider provider, string columnName)
    {
        return provider switch
        {
            DatabaseProvider.PostgreSQL => $"\"{columnName}\"",
            DatabaseProvider.SqlServer => $"[{columnName}]",
            DatabaseProvider.MySQL => $"`{columnName}`",
            DatabaseProvider.SQLite => $"[{columnName}]",
            _ => throw new NotSupportedException($"Database provider {provider} is not supported")
        };
    }
}