export interface DocsVersion {
  version: string;
  label: string;
  basePath: string | null;
  isLatest: boolean;
  gitRef: string;
}

export const versions: DocsVersion[] = [
  {
    version: "0.1.0",
    label: "v0.1 (latest)",
    basePath: null,
    isLatest: true,
    gitRef: "main",
  },
];

export const currentVersion = versions.find((v) => v.isLatest)!;
export const hasMultipleVersions = versions.length > 1;
