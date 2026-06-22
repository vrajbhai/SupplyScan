import type { Metadata } from "next";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeProvider } from "@/components/theme-provider";

export const metadata: Metadata = {
  title: "SupplyScan Dashboard",
  description: "Autonomous supply chain attack detector.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex flex-col md:flex-row h-screen overflow-hidden bg-background font-sans text-emerald-950 dark:text-emerald-50 antialiased">
        <ThemeProvider attribute="class" defaultTheme="light" enableSystem={false}>
          <TooltipProvider>
            <AppSidebar />
            <main className="flex-1 overflow-y-auto flex flex-col justify-between">
              <div className="app-shell animate-in fade-in duration-300 flex-1">{children}</div>
              <footer className="py-6 text-center border-t border-emerald-100 dark:border-emerald-900 bg-emerald-50/10 dark:bg-emerald-950/10 text-xs font-semibold text-emerald-800/60 dark:text-emerald-400/60">
                SupplyScan Project &copy; {new Date().getFullYear()} &bull;{" "}
                <a
                  href="https://github.com/vrajbhai/SupplyScan"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-emerald-600 dark:hover:text-emerald-400 underline transition-colors"
                >
                  GitHub Repository
                </a>
              </footer>
            </main>
            <Toaster position="top-right" richColors />
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
