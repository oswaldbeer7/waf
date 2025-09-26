/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  experimental: {
    serverComponentsExternalPackages: [],
  },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080",
  },
  webpack: (config, { isServer }) => {
    // Add path aliases for TypeScript
    config.resolve.alias = {
      ...config.resolve.alias,
      "@": require("path").resolve(__dirname, "src"),
      "@/components": require("path").resolve(__dirname, "src/components"),
      "@/lib": require("path").resolve(__dirname, "src/lib"),
      "@/types": require("path").resolve(__dirname, "src/types"),
    };

    return config;
  },
};

module.exports = nextConfig;
