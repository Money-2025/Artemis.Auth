using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using System.Data.Common;

namespace Artemis.Auth.Infrastructure.Performance;

public class QueryOptimizationInterceptor : DbCommandInterceptor
{
    private readonly ILogger<QueryOptimizationInterceptor> _logger;
    
    public QueryOptimizationInterceptor(ILogger<QueryOptimizationInterceptor> logger)
    {
        _logger = logger;
    }
    
    public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command,
        CommandEventData eventData,
        InterceptionResult<DbDataReader> result,
        CancellationToken cancellationToken = default)
    {
        // Log slow queries
        var startTime = DateTime.UtcNow;
        
        var executeResult = await base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        
        var executionTime = DateTime.UtcNow - startTime;
        
        if (executionTime.TotalMilliseconds > 1000) // Log queries slower than 1 second
        {
            _logger.LogWarning("Slow query detected: {ExecutionTime}ms - {Query}", 
                executionTime.TotalMilliseconds, 
                command.CommandText);
        }
        
        return executeResult;
    }
    
    public override InterceptionResult<DbCommand> CommandCreating(
        CommandCorrelatedEventData eventData,
        InterceptionResult<DbCommand> result)
    {
        // Add query hints for PostgreSQL
        if (eventData.Context?.Database.ProviderName?.Contains("Npgsql") == true)
        {
            // Add connection-level optimizations
            var command = result.Result;
            if (command != null)
            {
                // Set statement timeout for long-running queries
                command.CommandTimeout = 30;
            }
        }
        
        return base.CommandCreating(eventData, result);
    }
}