"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, Shield, Globe, TrendingUp } from "lucide-react";
import { Statistics } from "@/types/index";

interface StatsCardsProps {
  stats: Statistics | null;
}

export function StatsCards({ stats }: StatsCardsProps) {
  const cards = [
    {
      title: "Total Requests",
      value: stats?.total_requests || 0,
      description: "All time requests",
      icon: Activity,
      color: "text-blue-600",
    },
    {
      title: "Allowed Requests",
      value: stats?.allowed_requests || 0,
      description: "Requests allowed through",
      icon: TrendingUp,
      color: "text-green-600",
    },
    {
      title: "Blocked Requests",
      value: stats?.blocked_requests || 0,
      description: "Requests blocked by rules",
      icon: Shield,
      color: "text-red-600",
    },
    {
      title: "Countries",
      value: Object.keys(stats?.requests_by_country || {}).length,
      description: "Unique countries",
      icon: Globe,
      color: "text-purple-600",
    },
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {cards.map((card, index) => (
        <Card key={index}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{card.title}</CardTitle>
            <card.icon className={`h-4 w-4 ${card.color}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {card.value.toLocaleString()}
            </div>
            <p className="text-xs text-muted-foreground">{card.description}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
