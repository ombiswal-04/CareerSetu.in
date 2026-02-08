/** @type {import('next').NextConfig} */
const nextConfig = {
  // Externalize mongoose to help with DNS module
  serverExternalPackages: ['mongoose'],
  experimental: {
    serverActions: {
      bodySizeLimit: '10mb',
    },
  },
};

export default nextConfig;
