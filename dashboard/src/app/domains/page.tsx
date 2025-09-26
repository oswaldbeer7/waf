"use client";

import { useEffect, useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Domain, CreateDomainRequest } from "@/types/index";
import { DomainForm } from "@/components/domain-form";
import { DomainList } from "@/components/domain-list";
import { Plus } from "lucide-react";

export default function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    fetchDomains();
  }, []);

  const fetchDomains = async () => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/domains`
      );
      if (response.ok) {
        const data = await response.json();
        setDomains(data);
      }
    } catch (error) {
      console.error("Failed to fetch domains:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateDomain = async (domainData: CreateDomainRequest) => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/domains`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(domainData),
        }
      );

      if (response.ok) {
        await fetchDomains();
        setShowForm(false);
      } else {
        throw new Error("Failed to create domain");
      }
    } catch (error) {
      console.error("Failed to create domain:", error);
      throw error;
    }
  };

  const handleDeleteDomain = async (id: number) => {
    try {
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/domains/${id}`,
        {
          method: "DELETE",
        }
      );

      if (response.ok) {
        await fetchDomains();
      } else {
        throw new Error("Failed to delete domain");
      }
    } catch (error) {
      console.error("Failed to delete domain:", error);
      throw error;
    }
  };

  if (loading) {
    return (
      <div className="flex-1 space-y-4 p-8 pt-6">
        <div className="flex items-center justify-between">
          <h2 className="text-3xl font-bold tracking-tight">Domains</h2>
          <div className="h-10 bg-muted animate-pulse rounded w-32" />
        </div>
        <div className="space-y-4">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardHeader>
                <div className="h-4 bg-muted animate-pulse rounded" />
                <div className="h-3 bg-muted animate-pulse rounded w-3/4" />
              </CardHeader>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Domains</h2>
        <Button onClick={() => setShowForm(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Domain
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="col-span-full">
          <CardHeader>
            <CardTitle>Domain Management</CardTitle>
            <CardDescription>
              Manage your domains and their origin servers. Each domain will be
              proxied through this WAF.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DomainList
              domains={domains}
              onDelete={handleDeleteDomain}
              onRefresh={fetchDomains}
            />
          </CardContent>
        </Card>
      </div>

      {showForm && (
        <DomainForm
          onSubmit={handleCreateDomain}
          onCancel={() => setShowForm(false)}
        />
      )}
    </div>
  );
}
