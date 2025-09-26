import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "WAF Dashboard",
  description: "Multi-Domain Reverse Proxy & Analytics Dashboard",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <div className="min-h-screen bg-background font-sans antialiased">
          <div className="relative flex min-h-screen flex-col">
            <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
              <div className="container flex h-14 max-w-screen-2xl items-center">
                <div className="mr-4 hidden md:flex">
                  <a className="mr-6 flex items-center space-x-2" href="/">
                    <span className="hidden font-bold sm:inline-block">
                      WAF Dashboard
                    </span>
                  </a>
                </div>
                <div className="flex flex-1 items-center justify-between space-x-2 md:justify-end">
                  <div className="w-full flex-1 md:w-auto md:flex-none">
                    {/* Search or other header content can go here */}
                  </div>
                  <nav className="flex items-center">
                    {/* Navigation items can go here */}
                  </nav>
                </div>
              </div>
            </header>
            <div className="container flex-1 items-start md:grid md:grid-cols-[220px_minmax(0,1fr)] md:gap-6 lg:grid-cols-[240px_minmax(0,1fr)] lg:gap-10">
              <aside className="fixed top-14 z-30 -ml-2 hidden h-[calc(100vh-3.5rem)] w-full shrink-0 overflow-y-auto border-r md:sticky md:block">
                <div className="h-full py-6 pl-8 pr-6 lg:py-8">
                  <div className="space-y-1">
                    <h2 className="mb-2 px-4 text-lg font-semibold tracking-tight">
                      Dashboard
                    </h2>
                    <nav className="grid items-start px-2 text-sm font-medium lg:px-4">
                      <a
                        href="/"
                        className="flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary"
                      >
                        Overview
                      </a>
                      <a
                        href="/domains"
                        className="flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary"
                      >
                        Domains
                      </a>
                      <a
                        href="/analytics"
                        className="flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary"
                      >
                        Analytics
                      </a>
                      <a
                        href="/logs"
                        className="flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary"
                      >
                        Request Logs
                      </a>
                      <a
                        href="/bots"
                        className="flex items-center gap-3 rounded-lg px-3 py-2 text-muted-foreground transition-all hover:text-primary"
                      >
                        Anti-Bot Rules
                      </a>
                    </nav>
                  </div>
                </div>
              </aside>
              <main className="flex w-full flex-col overflow-hidden">
                {children}
              </main>
            </div>
          </div>
        </div>
      </body>
    </html>
  );
}
