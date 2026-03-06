import type { NextConfig } from "next";
import createMDX from "@next/mdx";
import path from "node:path";

const isDev = process.env.NODE_ENV === "development";

const nextConfig: NextConfig = {
  pageExtensions: ["ts", "tsx", "md", "mdx"],
  ...(isDev ? {} : { output: "export" }),
  basePath: process.env.DOCS_BASE_PATH !== undefined ? process.env.DOCS_BASE_PATH : (isDev ? "" : "/privacy-proxy"),
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  turbopack: {
    root: __dirname,
  },
};

const withMDX = createMDX({
  options: {
    remarkPlugins: ["remark-gfm", path.join(__dirname, "remark-mermaid.mjs")],
    rehypePlugins: ["rehype-slug"],
  },
});

export default withMDX(nextConfig);
