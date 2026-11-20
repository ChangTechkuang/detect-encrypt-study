import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The Playground used to live at /implement: keep old links working
  async redirects() {
    return [
      { source: "/implement", destination: "/playground", permanent: true },
      { source: "/implement/:id", destination: "/playground/:id", permanent: true },
    ];
  },
};

export default nextConfig;
