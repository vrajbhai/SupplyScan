"use client";

import { useEffect, useMemo, useState } from "react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Download, History } from "lucide-react";
import { fetchHistory, ScanResult } from "@/lib/api";
import { ScanDetailModal, SeverityBadge } from "@/components/scan-detail-modal";
import { toast } from "sonner";

type Filter = "ALL" | "CLEAN" | "THREATS";

export default function HistoryPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<Filter>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selected, setSelected] = useState<ScanResult | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setHistory(await fetchHistory());
      } catch (err) {
        console.error("Failed to load scan history:", err);
        toast.error("Failed to load history", {
          description: err instanceof Error ? err.message : "The API server is unreachable.",
        });
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const filteredHistory = useMemo(() => {
    let data = history;
    if (filter === "CLEAN") data = history.filter((item) => item.severity === "CLEAN");
    if (filter === "THREATS") data = history.filter((item) => item.severity !== "CLEAN");

    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      data = data.filter((item) =>
        item.package.toLowerCase().includes(query) ||
        item.version.toLowerCase().includes(query) ||
        item.ecosystem.toLowerCase().includes(query)
      );
    }
    return data;
  }, [filter, history, searchQuery]);

  const exportCsv = () => {
    const header = ["timestamp", "package", "version", "ecosystem", "severity", "status", "duration_ms"];
    const rows = filteredHistory.map((item) => [
      item.timestamp,
      item.package,
      item.version,
      item.ecosystem,
      item.severity,
      item.status,
      String(item.duration_ms),
    ]);
    const csv = [header, ...rows]
      .map((row) => row.map((value) => `"${value.replaceAll('"', '""')}"`).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "supplyscan-history.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
        <div className="space-y-3">
          <div className="page-kicker w-fit">
            <History className="h-3.5 w-3.5" />
            Scan records
          </div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">Review package verification logs, clean approvals, and threat blocks.</p>
        </div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:space-x-3">
          {/* Live Search Input */}
          <input
            type="text"
            placeholder="Search package..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-10 w-full sm:w-48 rounded-2xl border border-border bg-card px-4 py-2 text-sm text-foreground placeholder-muted-foreground shadow-xs focus:outline-none focus:ring-1 focus:ring-primary transition-all"
          />
          <div className="flex rounded-2xl border border-border bg-muted/40 p-1">
            {(["ALL", "CLEAN", "THREATS"] as Filter[]).map((value) => (
              <button
                key={value}
                onClick={() => setFilter(value)}
                className={`rounded-xl px-4 py-2 text-sm font-semibold transition-colors cursor-pointer ${
                  filter === value
                    ? "bg-card text-emerald-700 dark:text-emerald-300 shadow-xs"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {value === "THREATS" ? "Threats" : value[0] + value.slice(1).toLowerCase()}
              </button>
            ))}
          </div>
          <Button
            variant="outline"
            className="rounded-2xl border border-border bg-card hover:bg-muted text-foreground font-semibold shadow-xs transition-colors cursor-pointer"
            onClick={exportCsv}
            disabled={loading || filteredHistory.length === 0}
          >
            <Download className="mr-2 h-4 w-4" />
            Export CSV
          </Button>
        </div>
      </div>

      <div className="soft-table">
        <Table>
          <TableHeader className="bg-emerald-50/80 dark:bg-emerald-900/20">
            <TableRow className="border-emerald-100 dark:border-emerald-900">
              <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Timestamp</TableHead>
              <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Package</TableHead>
              <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Ecosystem</TableHead>
              <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Severity</TableHead>
              <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Duration</TableHead>
              <TableHead className="text-right font-bold text-emerald-900 dark:text-emerald-400">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: 4 }).map((_, index) => (
                <TableRow key={index}>
                  <TableCell colSpan={6}><Skeleton className="h-8 w-full rounded-full" /></TableCell>
                </TableRow>
              ))
            ) : filteredHistory.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-emerald-900/60 dark:text-emerald-400/60">No results found for this filter.</TableCell>
              </TableRow>
            ) : (
              filteredHistory.map((item, index) => (
                <TableRow key={`${item.package}-${index}`} className="group border-emerald-100 dark:border-emerald-900 transition-colors hover:bg-emerald-50/70 dark:hover:bg-emerald-900/30">
                  <TableCell className="whitespace-nowrap text-emerald-900/60 dark:text-emerald-400/60">{item.timestamp}</TableCell>
                  <TableCell className="font-bold text-emerald-950 dark:text-emerald-100">
                    {item.package} <span className="ml-1 font-medium text-emerald-700/70 dark:text-emerald-400/70">{item.version}</span>
                  </TableCell>
                  <TableCell className="text-emerald-900/75 dark:text-emerald-300">{item.ecosystem}</TableCell>
                  <TableCell><SeverityBadge severity={item.severity} /></TableCell>
                  <TableCell className="text-emerald-900/75 dark:text-emerald-300">{item.duration_ms}ms</TableCell>
                  <TableCell className="text-right">
                    <button className="text-sm font-bold text-emerald-700 dark:text-emerald-400 opacity-0 transition-opacity group-hover:opacity-100 cursor-pointer" onClick={() => setSelected(item)}>
                      View Details -&gt;
                    </button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <ScanDetailModal result={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
