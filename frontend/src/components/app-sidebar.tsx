"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, Home, Search, History, Settings, Sun, Moon, Cpu, Menu, X } from "lucide-react";
import { useTheme } from "next-themes";
import { getStats } from "@/lib/api";

const NAV_ITEMS = [
  { href: "/", label: "Home", icon: Home },
  { href: "/scan", label: "Scan", icon: Search },
  { href: "/sandbox", label: "Threat Sandbox", icon: Cpu },
  { href: "/history", label: "History", icon: History },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppSidebar() {
  const pathname = usePathname();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [connected, setConnected] = useState(false);
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    async function checkConnection() {
      try {
        await getStats();
        setConnected(true);
      } catch (err) {
        setConnected(false);
      }
    }
    checkConnection();
    const interval = setInterval(checkConnection, 8000);
    return () => clearInterval(interval);
  }, []);

  // Close mobile sidebar on navigation
  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);

  return (
    <>
      {/* Mobile Top Header */}
      <div className="flex h-16 items-center justify-between border-b border-emerald-100 dark:border-emerald-900 bg-white/90 dark:bg-emerald-950/80 px-6 backdrop-blur-md md:hidden w-full shrink-0">
        <div className="flex items-center">
          <div className="mr-3 flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-100 dark:bg-emerald-900/50 text-emerald-700 dark:text-emerald-400">
            <Shield className="h-5 w-5" />
          </div>
          <span className="font-display text-lg font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50">SupplyScan</span>
        </div>
        <div className="flex items-center gap-3">
          {mounted && (
            <button
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-100 dark:border-emerald-900 bg-white dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-400 shadow-sm"
              aria-label="Toggle theme"
            >
              {resolvedTheme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          )}
          <button
            onClick={() => setIsOpen(true)}
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-100 dark:border-emerald-900 bg-white dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-400 shadow-sm hover:bg-emerald-50 dark:hover:bg-emerald-900/50"
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Mobile Slide-out Menu Backdrop */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-40 bg-emerald-950/30 backdrop-blur-xs md:hidden"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Mobile Slide-out Menu Panel */}
      <div 
        className={`fixed inset-y-0 left-0 z-50 flex w-72 flex-col border-r border-emerald-100 dark:border-emerald-900 bg-white/95 dark:bg-emerald-950/95 shadow-2xl backdrop-blur transition-transform duration-300 md:hidden ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-emerald-100 dark:border-emerald-900 px-6">
          <div className="flex items-center">
            <div className="mr-3 flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-100 dark:bg-emerald-900/50 text-emerald-700 dark:text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <span className="font-display text-lg font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50">SupplyScan</span>
          </div>
          <button
            onClick={() => setIsOpen(false)}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-100 dark:border-emerald-900 text-emerald-800 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/50"
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav className="flex-1 space-y-2 px-4 py-6">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                onClick={() => setIsOpen(false)}
                className={`flex items-center rounded-2xl px-4 py-3 text-sm font-semibold transition-all ${
                  active
                    ? "bg-emerald-500/10 dark:bg-emerald-400/10 text-emerald-700 dark:text-emerald-300"
                    : "text-emerald-950/60 dark:text-emerald-400/75 hover:bg-emerald-500/5 dark:hover:bg-emerald-400/5"
                }`}
              >
                <Icon className="mr-3 h-4 w-4" />
                {label}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center justify-between border-t border-emerald-100 dark:border-emerald-900 p-5">
          <div className="rounded-2xl bg-emerald-50 dark:bg-emerald-900/40 px-4 py-3 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
            v0.1.0-alpha
          </div>
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${connected ? "bg-emerald-400" : "bg-rose-400"} opacity-75`} />
              <span className={`relative inline-flex h-2 w-2 rounded-full ${connected ? "bg-emerald-500" : "bg-rose-500"}`} />
            </span>
            <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-emerald-600 dark:text-emerald-400">
              {connected ? "Connected" : "Offline"}
            </span>
          </div>
        </div>
      </div>

      {/* Desktop Sidebar */}
      <aside className="hidden w-72 flex-col border-r border-emerald-100 dark:border-emerald-900 bg-white/90 dark:bg-emerald-950/80 shadow-[12px_0_35px_rgba(6,78,59,0.05)] backdrop-blur md:flex">
        <div className="flex h-20 items-center border-b border-emerald-100 dark:border-emerald-900 px-7">
          <div className="mr-3 flex h-11 w-11 items-center justify-center rounded-2xl bg-emerald-100 dark:bg-emerald-900/50 text-emerald-700 dark:text-emerald-400">
            <Shield className="h-6 w-6" />
          </div>
          <div>
            <span className="block font-display text-xl font-extrabold tracking-tight text-emerald-950 dark:text-emerald-50">SupplyScan</span>
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-2 w-2">
                <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${connected ? "bg-emerald-400" : "bg-rose-400"} opacity-75`} />
                <span className={`relative inline-flex h-2 w-2 rounded-full ${connected ? "bg-emerald-500" : "bg-rose-500"}`} />
              </span>
              <span className="text-[10px] font-bold uppercase tracking-[0.14em] text-emerald-600 dark:text-emerald-400">
                {connected ? "Connected" : "Offline Mode"}
              </span>
            </div>
          </div>
        </div>
        <nav className="flex-1 space-y-2 px-5 py-7">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center rounded-2xl px-4 py-3 text-sm font-semibold transition-all ${
                  active
                    ? "bg-emerald-500/10 dark:bg-emerald-400/10 text-emerald-700 dark:text-emerald-300 shadow-xs"
                    : "text-emerald-950/60 dark:text-emerald-400/75 hover:bg-emerald-500/5 dark:hover:bg-emerald-400/5 hover:text-emerald-800 dark:hover:text-emerald-200"
                }`}
              >
                <Icon className="mr-3 h-4 w-4" />
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="flex items-center justify-between border-t border-emerald-100 dark:border-emerald-900 p-5">
          <div className="rounded-2xl bg-emerald-50 dark:bg-emerald-900/40 px-4 py-3 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
            v0.1.0-alpha
          </div>
          {mounted && (
            <button
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              className="flex h-10 w-10 items-center justify-center rounded-2xl border border-emerald-100 dark:border-emerald-900 bg-white dark:bg-emerald-900/40 text-emerald-800 dark:text-emerald-400 shadow-sm hover:bg-emerald-50 dark:hover:bg-emerald-900/50"
              aria-label="Toggle theme"
            >
              {resolvedTheme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          )}
        </div>
      </aside>
    </>
  );
}
