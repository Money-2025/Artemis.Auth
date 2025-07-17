using System;
using System.Data.Common;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Artemis.Auth.Infrastructure.Performance
{
    public class QueryOptimizationInterceptor : DbCommandInterceptor
    {
        private readonly ILogger<QueryOptimizationInterceptor> _logger;

        public QueryOptimizationInterceptor(ILogger<QueryOptimizationInterceptor> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Fires after EF Core has constructed the DbCommand. Here you can tweak timeouts, hints, etc.
        /// </summary>
        public override DbCommand CommandCreated(
            CommandEndEventData eventData,
            DbCommand command)
        {
            if (eventData.Context?.Database.ProviderName?.Contains("Npgsql") == true)
            {
                // Set a 30‑second statement timeout on all PostgreSQL commands
                command.CommandTimeout = 30;
            }

            return base.CommandCreated(eventData, command);
        }

        /// <summary>
        /// Logs any query that takes longer than 1 second to execute.
        /// </summary>
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            var startTime = DateTime.UtcNow;

            // Proceed with execution
            var executeResult = await base.ReaderExecutingAsync(command, eventData, result, cancellationToken);

            var executionTime = DateTime.UtcNow - startTime;
            if (executionTime.TotalMilliseconds > 1000)
            {
                _logger.LogWarning(
                    "Slow query detected ({ExecutionTime}ms): {CommandText}",
                    executionTime.TotalMilliseconds,
                    command.CommandText);
            }

            return executeResult;
        }
    }
}
