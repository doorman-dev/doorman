
const gatewayTarget = process.env.GATEWAY_INTERNAL_URL || 'http://localhost:3001'

const securityHeaders = [
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'Referrer-Policy',
    value: 'no-referrer',
  },
  {
    key: 'Permissions-Policy',
    value: 'geolocation=(), microphone=(), camera=()',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin',
  },
  {
    key: 'Cross-Origin-Resource-Policy',
    value: 'same-origin',
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block',
  },
]

function buildRemotePatterns() {
  const env = process.env.NEXT_IMAGE_DOMAINS || ''
  const hosts = env.split(',').map(s => s.trim()).filter(Boolean)
  return hosts.map(hostname => ({ protocol: 'https', hostname }))
}

const nextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // Gateway paths are proxied verbatim: some platform routes are registered
  // with a trailing slash (e.g. /platform/tiers/) and the gateway redirects
  // the unslashed form, so stripping the slash here would loop forever.
  skipTrailingSlashRedirect: true,
  // Harden Next/Image to mitigate known issues around the optimization route
  images: {
    // Allow remote image hosts via env: NEXT_IMAGE_DOMAINS=cdn.example.com,images.example.org
    remotePatterns: buildRemotePatterns(),
    // Prevent script execution / content injection on the image optimization response
    contentSecurityPolicy: "script-src 'none'; frame-ancestors 'none'; sandbox;",
    dangerouslyAllowSVG: false,
    // Allow opt-out to disable optimizer entirely when desired
    unoptimized: (process.env.NEXT_IMAGE_UNOPTIMIZED || '').toLowerCase() === 'true',
  },
  async redirects() {
    return [
      {
        source: '/favicon.ico',
        destination: '/favicon-32x32.png',
        permanent: true,
      },
    ]
  },
  async rewrites() {
    return [
      // Keep a trailing slash: the gateway distinguishes /platform/tiers/.
      { source: '/platform/:path*/', destination: `${gatewayTarget}/platform/:path*/` },
      { source: '/platform/:path*', destination: `${gatewayTarget}/platform/:path*` },
      { source: '/api/:path*/', destination: `${gatewayTarget}/api/:path*/` },
      { source: '/api/:path*', destination: `${gatewayTarget}/api/:path*` },
    ]
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ]
  },
}

export default nextConfig
