"use client";

import { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck, ShieldX, CheckCircle2, Clock, Sparkles } from "lucide-react";
import { fetchStats, fetchRecentActivity, MetricStats, ScanResult } from "@/lib/api";
import { ScanDetailModal, SeverityBadge } from "@/components/scan-detail-modal";
import { toast } from "sonner";

export default function Home() {
  const [stats, setStats] = useState<MetricStats | null>(null);
  const [activity, setActivity] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<ScanResult | null>(null);
  const [animated, setAnimated] = useState({ total_scans: 0, threats_blocked: 0, clean_today: 0 });

  useEffect(() => {
    async function loadData() {
      try {
        const [nextStats, nextActivity] = await Promise.all([fetchStats(), fetchRecentActivity()]);
        setStats(nextStats);
        setActivity(nextActivity);
      } catch (err) {
        console.error("Failed to load dashboard metrics:", err);
        toast.error("Failed to sync connection", {
          description: "Could not load stats or recent activity from the backend.",
        });
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!stats) return;
    const started = performance.now();
    const duration = 700;
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min((now - started) / duration, 1);
      setAnimated({
        total_scans: Math.round(stats.total_scans * progress),
        threats_blocked: Math.round(stats.threats_blocked * progress),
        clean_today: Math.round(stats.clean_today * progress),
      });
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [stats]);

  return (
    <div className="space-y-10 animate-in fade-in duration-500">
      <div className="flex flex-col gap-4">
        <div className="page-kicker w-fit">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
          </span>
          Protected - Live
        </div>
        <div className="flex flex-col gap-3">
          <h1 className="page-title">Your supply chain is protected</h1>
          {loading ? (
            <Skeleton className="h-7 w-80 rounded-full" />
          ) : (
            <p className="page-subtitle">
              {stats?.total_scans} packages scanned, {stats?.threats_blocked} risky installs stopped, and {stats?.clean_today} packages cleared for use.
            </p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total Scans" value={animated.total_scans} loading={loading} icon={<ShieldCheck className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />} iconClass="bg-emerald-500/10 dark:bg-emerald-500/20" />
        <MetricCard label="Threats Blocked" value={animated.threats_blocked} loading={loading} icon={<ShieldX className="h-6 w-6 text-rose-600 dark:text-rose-400" />} iconClass="bg-rose-500/10 dark:bg-rose-500/20" pulse={animated.threats_blocked > 0} />
        <MetricCard label="Clean Packages" value={animated.clean_today} loading={loading} icon={<CheckCircle2 className="h-6 w-6 text-teal-600 dark:text-teal-450" />} iconClass="bg-teal-500/10 dark:bg-teal-500/20" />
        <MetricCard label="Avg Scan Time" value={stats?.avg_scan_time || "-"} loading={loading} icon={<Clock className="h-6 w-6 text-sky-600 dark:text-sky-400" />} iconClass="bg-sky-500/10 dark:bg-sky-500/20" />
      </div>

      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          <h2 className="text-2xl font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50 font-display">Recent Activity</h2>
        </div>
        <div className="soft-table">
          <Table>
            <TableHeader className="bg-emerald-50/80 dark:bg-emerald-900/20">
              <TableRow className="border-emerald-100 dark:border-emerald-900">
                <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Package</TableHead>
                <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Ecosystem</TableHead>
                <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Severity</TableHead>
                <TableHead className="font-bold text-emerald-900 dark:text-emerald-400">Status</TableHead>
                <TableHead className="text-right font-bold text-emerald-900 dark:text-emerald-400">Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 4 }).map((_, index) => (
                  <TableRow key={index}><TableCell colSpan={5}><Skeleton className="h-8 w-full rounded-full" /></TableCell></TableRow>
                ))
              ) : activity.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center text-emerald-900/60 dark:text-emerald-400/60">
                    No scans yet. Run a package check to populate this table.
                  </TableCell>
                </TableRow>
              ) : (
                activity.map((item, index) => (
                  <TableRow key={`${item.package}-${index}`} onClick={() => setSelected(item)} className="cursor-pointer border-emerald-100 dark:border-emerald-900 transition-colors hover:bg-emerald-50/70 dark:hover:bg-emerald-900/30">
                    <TableCell className="font-bold text-emerald-950 dark:text-emerald-100">{item.package} <span className="ml-1 font-medium text-emerald-700/70 dark:text-emerald-400/70">{item.version}</span></TableCell>
                    <TableCell className="text-emerald-900/75 dark:text-emerald-300">{item.ecosystem}</TableCell>
                    <TableCell><SeverityBadge severity={item.severity} /></TableCell>
                    <TableCell className={item.status === "Blocked" ? "font-semibold text-rose-700 dark:text-rose-400" : "font-semibold text-emerald-700 dark:text-emerald-400"}>{item.status}</TableCell>
                    <TableCell className="text-right text-emerald-900/60 dark:text-emerald-400/60">{item.timestamp}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      <ScanDetailModal result={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function MetricCard({
  label,
  value,
  loading,
  icon,
  iconClass,
  pulse = false,
}: {
  label: string;
  value: string | number;
  loading: boolean;
  icon: React.ReactNode;
  iconClass: string;
  pulse?: boolean;
}) {
  return (
    <Card className="surface-card transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_20px_50px_rgba(4,47,38,0.06)] dark:hover:shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
      <CardContent className="flex items-center gap-5 p-7">
        <div className={`flex h-14 w-14 items-center justify-center rounded-2xl ${iconClass}`}>{icon}</div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{label}</p>
          {loading ? <Skeleton className="mt-2 h-8 w-20 rounded-full" /> : (
            <h3 className="flex items-center text-3xl font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50 font-display mt-1">
              {value}
              {pulse && (
                <span className="relative ml-3 flex h-2.5 w-2.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75" />
                  <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-rose-500" />
                </span>
              )}
            </h3>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
