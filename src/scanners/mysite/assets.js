export const RASTER_IMAGE_EXTENSIONS = new Set([".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tiff", ".webp"]);
const FONT_ASSET_EXTENSIONS = new Set([".eot", ".otf", ".ttf", ".woff", ".woff2"]);
export const MEDIA_ASSET_EXTENSIONS = new Set([".mov", ".mp3", ".mp4", ".ogg", ".wav", ".webm"]);
export const ASSET_BUDGET_BYTES = Object.freeze({
  imageReview: 1024 * 1024,
  imageElevated: 2 * 1024 * 1024,
  animatedGifReview: 512 * 1024,
  fontReview: 300 * 1024,
  mediaReview: 5 * 1024 * 1024,
  mediaElevated: 20 * 1024 * 1024,
  wasmReview: 2 * 1024 * 1024,
});

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 10 * 1024 * 1024 ? 1 : 2)} MiB`;
  return `${Math.ceil(bytes / 1024)} KiB`;
}

export function auditAsset(asset, add) {
  const common = {
    file: asset.relative,
    line: 1,
    suggestedFiles: [asset.relative],
    confidence: "medium",
    manual: true,
  };
  const extension = asset.extension.toLowerCase();
  const size = asset.size;

  if (RASTER_IMAGE_EXTENSIONS.has(extension) && size > ASSET_BUDGET_BYTES.imageReview) {
    add({
      ...common,
      id: "performance-large-image-asset",
      title: "Large raster image may exceed the route's image budget",
      category: "Performance & image delivery",
      severity: size > ASSET_BUDGET_BYTES.imageElevated ? "medium" : "low",
      description: "Large source images can dominate transfer time and delay LCP when they are shipped without responsive variants or strong compression.",
      evidence: `${asset.relative} is ${formatBytes(size)}.`,
      recommendation: "Confirm this asset is delivered, then resize it to rendered dimensions, encode modern responsive variants, and use `srcset`/`sizes` or the framework image pipeline.",
      tags: ["images", "page-speed", "lcp", "performance-budget"],
    });
  }

  if ([".bmp", ".tiff"].includes(extension)) {
    add({
      ...common,
      id: "performance-legacy-image-format",
      title: "Legacy raster format needs a web-delivery review",
      category: "Performance & image delivery",
      severity: "low",
      description: "BMP and TIFF are poor default delivery formats for responsive websites and commonly produce unnecessarily large transfers.",
      evidence: `${asset.relative} uses ${extension.slice(1).toUpperCase()} (${formatBytes(size)}).`,
      recommendation: "Convert photographic content to AVIF/WebP with a suitable fallback, or PNG when lossless raster output is required.",
      tags: ["images", "compression", "cross-browser", "page-speed"],
    });
  }

  if (extension === ".gif" && size > ASSET_BUDGET_BYTES.animatedGifReview) {
    add({
      ...common,
      id: "performance-large-gif-asset",
      title: "Large GIF may be an inefficient animation payload",
      category: "Performance & image delivery",
      severity: "low",
      description: "A large GIF often transfers far more data than an equivalent modern image or muted video and offers limited playback control.",
      evidence: `${asset.relative} is ${formatBytes(size)}.`,
      recommendation: "If animated, compare an accessible, reduced-motion-aware WebM/MP4 or animated WebP/AVIF; if static, encode a modern still image.",
      tags: ["images", "animation", "page-speed", "reduced-motion"],
    });
  }

  if (FONT_ASSET_EXTENSIONS.has(extension) && size > ASSET_BUDGET_BYTES.fontReview) {
    add({
      ...common,
      id: "performance-large-font-asset",
      title: "Large web font needs subsetting and loading review",
      category: "Performance & typography",
      severity: "low",
      description: "Large font files delay usable text and can consume substantial bandwidth across weights, styles, and scripts.",
      evidence: `${asset.relative} is ${formatBytes(size)}.`,
      recommendation: "Subset only required glyphs, prefer WOFF2, reduce unnecessary weights/styles, preload only critical faces, and use metric-compatible fallbacks.",
      tags: ["fonts", "typography", "lcp", "performance-budget"],
    });
  }

  if (MEDIA_ASSET_EXTENSIONS.has(extension) && size > ASSET_BUDGET_BYTES.mediaReview) {
    add({
      ...common,
      id: "performance-large-media-asset",
      title: "Large media asset needs a delivery budget",
      category: "Performance & media",
      severity: size > ASSET_BUDGET_BYTES.mediaElevated ? "medium" : "low",
      description: "Large audio/video transfers can overwhelm mobile data budgets and compete with critical page resources.",
      evidence: `${asset.relative} is ${formatBytes(size)}.`,
      recommendation: "Use adaptive or appropriately compressed delivery, avoid eager preload, supply poster/captions where relevant, and measure on constrained mobile networks.",
      tags: ["media", "page-speed", "mobile", "performance-budget"],
    });
  }

  if (extension === ".wasm" && size > ASSET_BUDGET_BYTES.wasmReview) {
    add({
      ...common,
      id: "performance-large-wasm-asset",
      title: "Large WebAssembly module needs a startup-cost review",
      category: "Performance",
      severity: "medium",
      description: "A large WebAssembly binary carries download, compilation, instantiation, and memory costs before its feature becomes interactive.",
      evidence: `${asset.relative} is ${formatBytes(size)}.`,
      recommendation: "Measure the feature on representative devices, lazy-load it behind intent, strip/debug-optimize the binary, and split optional capabilities when supported.",
      tags: ["wasm", "page-speed", "inp", "performance-budget"],
    });
  }
}
