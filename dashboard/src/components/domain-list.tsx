"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Domain } from "@/types";
import { Trash2, RefreshCw, ExternalLink } from "lucide-react";

interface DomainListProps {
  domains: Domain[];
  onDelete: (id: number) => Promise<void>;
  onRefresh: () => Promise<void>;
}

export function DomainList({ domains, onDelete, onRefresh }: DomainListProps) {
  const [deleting, setDeleting] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const handleDelete = async (id: number) => {
    setDeleting(id);
    try {
      await onDelete(id);
    } catch (error) {
      console.error("Error deleting domain:", error);
    } finally {
      setDeleting(null);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await onRefresh();
    } catch (error) {
      console.error("Error refreshing domains:", error);
    } finally {
      setRefreshing(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (domains.length === 0) {
    return (
      <div className="text-center py-8">
        <p className="text-muted-foreground mb-4">No domains configured yet.</p>
        <p className="text-sm text-muted-foreground">
          Add your first domain to start using the reverse proxy.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">
          {domains.length} domain{domains.length !== 1 ? "s" : ""} configured
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRefresh}
          disabled={refreshing}
        >
          <RefreshCw
            className={`mr-2 h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      <div className="space-y-3">
        {domains.map((domain) => (
          <div
            key={domain.id}
            className="flex items-center justify-between p-4 border rounded-lg"
          >
            <div className="space-y-1 flex-1">
              <div className="flex items-center gap-2">
                <h3 className="font-medium">{domain.name}</h3>
                <Badge variant="secondary">Active</Badge>
              </div>
              <p className="text-sm text-muted-foreground">
                Origin: {domain.origin_url}
              </p>
              <p className="text-xs text-muted-foreground">
                Created: {formatDate(domain.created_at)}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => window.open(`http://${domain.name}`, "_blank")}
              >
                <ExternalLink className="mr-2 h-4 w-4" />
                Visit
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={deleting === domain.id}
                onClick={() => handleDelete(domain.id)}
              >
                <Trash2
                  className={`mr-2 h-4 w-4 ${
                    deleting === domain.id ? "animate-pulse" : ""
                  }`}
                />
                {deleting === domain.id ? "Deleting..." : "Delete"}
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
