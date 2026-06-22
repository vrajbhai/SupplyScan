"use client";

import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScanResult } from "@/lib/api";

interface ScanDetailModalProps {
  result: ScanResult | null;
  onClose: () => void;
}

export function ScanDetailModal({ result, onClose }: ScanDetailModalProps) {
  if (!result) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-emerald-950/30 dark:bg-black/60 p-4 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-3xl border border-emerald-100 dark:border-emerald-900 bg-white dark:bg-card shadow-2xl shadow-emerald-950/10 flex flex-col max-h-[85vh]">
        <div className="flex items-start justify-between border-b border-emerald-100 dark:border-emerald-900 p-6 flex-shrink-0">
          <div>
            <h2 className="text-2xl font-black text-emerald-950 dark:text-emerald-50">
              {result.package} <span className="font-semibold text-emerald-700/70 dark:text-emerald-400/70">{result.version}</span>
            </h2>
            <div className="mt-2 flex items-center gap-2">
              <SeverityBadge severity={result.severity} />
              <span className="text-sm font-semibold text-emerald-900/65 dark:text-emerald-300">{result.status}</span>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close details" className="dark:text-emerald-400 dark:hover:bg-emerald-900/40">
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="space-y-5 p-6 overflow-y-auto flex-1">
          <div>
            <h3 className="mb-3 font-black text-emerald-950 dark:text-emerald-50">Signals</h3>
            {result.signals.length ? (
              <ul className="space-y-2">
                {result.signals.map((signal, index) => (
                  <li key={index} className="rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/50 dark:bg-emerald-900/20 p-4 text-sm text-emerald-950/80 dark:text-emerald-200">
                    <div className="mb-1.5 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={signal.severity} />
                        {signal.detector && <span className="text-xs font-bold uppercase tracking-wide text-emerald-700/70 dark:text-emerald-400/70">{signal.detector}</span>}
                      </div>
                      {signal.url && (
                        <a
                          href={signal.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-bold text-emerald-600 dark:text-emerald-400 hover:underline cursor-pointer"
                        >
                          Advisory Link ↗
                        </a>
                      )}
                    </div>
                    {signal.message}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="rounded-2xl bg-emerald-50 dark:bg-emerald-900/30 p-4 text-sm font-semibold text-emerald-700 dark:text-emerald-400">No malicious signals were detected.</p>
            )}
          </div>
          {result.explanation && (
            <div className="rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-emerald-50/70 dark:bg-emerald-900/30 p-5">
              <h3 className="mb-2 font-black text-emerald-950 dark:text-emerald-50">AI Explanation</h3>
              <p className="whitespace-pre-wrap break-words text-sm leading-6 text-emerald-950/75 dark:text-emerald-300">{result.explanation}</p>
              {result.action && <p className="mt-3 whitespace-pre-wrap break-words text-sm font-bold text-emerald-900 dark:text-emerald-400">Recommended action: {result.action}</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  if (severity === "CLEAN") {
    return <Badge className="rounded-full border-emerald-200 dark:border-emerald-900/60 bg-emerald-100 dark:bg-emerald-900/50 text-emerald-800 dark:text-emerald-300 shadow-none">CLEAN</Badge>;
  }
  if (severity === "CRITICAL") {
    return (
      <Badge className="relative rounded-full border-rose-200 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/40 pr-5 text-rose-700 dark:text-rose-400 shadow-none">
        CRITICAL
        <span className="absolute right-1.5 top-1.5 flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-rose-400 opacity-75" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-rose-500" />
        </span>
      </Badge>
    );
  }
  if (severity === "HIGH") {
    return <Badge className="rounded-full border-orange-200 dark:border-orange-950/40 bg-orange-50 dark:bg-orange-950/20 text-orange-700 dark:text-orange-400 shadow-none">HIGH</Badge>;
  }
  if (severity === "MEDIUM") {
    return <Badge className="rounded-full border-amber-200 dark:border-amber-950/40 bg-amber-50 dark:bg-amber-950/20 text-amber-700 dark:text-amber-400 shadow-none">MEDIUM</Badge>;
  }
  return <Badge variant="outline" className="rounded-full dark:border-emerald-900 dark:text-emerald-300">{severity}</Badge>;
}
