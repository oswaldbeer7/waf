"use client";

import { useEffect, useState } from "react";
import { RequestLog } from "@/types";

export function RecentActivity() {
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchLogs = async () => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/logs?limit=5`
      );
      if (response.ok) {
        const data = await response.json();
        setLogs(data);
      }
    } catch (error) {
      console.error("Failed to fetch logs:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getDecisionColor = (decision: string) => {
    return decision === "block" ? "text-red-600" : "text-green-600";
  };

  if (loading) {
    return (
      <div className="space-y-8">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex items-center">
            <div className="ml-4 space-y-1">
              <div className="h-4 bg-muted animate-pulse rounded" />
              <div className="h-3 bg-muted animate-pulse rounded w-3/4" />
            </div>
            <div className="ml-auto font-medium">
              <div className="h-4 bg-muted animate-pulse rounded" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (logs.length === 0) {
    return (
      <div className="flex h-[350px] items-center justify-center text-muted-foreground">
        No recent activity
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {logs.map((log) => (
        <div key={log.id} className="flex items-center">
          <div className="ml-4 space-y-1">
            <p className="text-sm font-medium leading-none">{log.path}</p>
            <p className="text-sm text-muted-foreground">
              {log.ip} • {log.country}
            </p>
          </div>
          <div className="ml-auto font-medium">
            <span className={getDecisionColor(log.decision)}>
              {log.decision.toUpperCase()}
            </span>
            <p className="text-xs text-muted-foreground">
              {formatTimestamp(log.timestamp)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
