/** @type {import('next').NextConfig} */

// STATIC_EXPORT=1 builds a plain static site in web/out that the Python API serves from the same
// origin (see the Dockerfile). Security headers then come from the API, because headers() is not
// supported in static exports.
const staticExport = process.env.STATIC_EXPORT === "1";

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  ...(staticExport
    ? { output: "export", images: { unoptimized: true } }
    : {
        async headers() {
          return [
            {
              source: "/:path*",
              headers: [
                { key: "X-Content-Type-Options", value: "nosniff" },
                { key: "Referrer-Policy", value: "no-referrer" },
                { key: "X-Frame-Options", value: "DENY" },
              ],
            },
          ];
        },
      }),
};

export default nextConfig;
