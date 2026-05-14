// HTML sanitizer for TipTap output. TipTap produces clean HTML by default,
// but anything that touches user input from the wire — even the owner's —
// gets sanitized server-side before we persist it. Defense in depth.

import DOMPurify from "isomorphic-dompurify";

// Allowlist tuned for TipTap StarterKit + Link + Image + CodeBlock.
const ALLOWED_TAGS = [
  "p", "br", "strong", "em", "u", "s", "code", "pre",
  "blockquote", "hr",
  "h1", "h2", "h3", "h4", "h5", "h6",
  "ul", "ol", "li",
  "a", "img",
  "span", "div",
];

const ALLOWED_ATTR = [
  "href", "title", "target", "rel",
  "src", "alt", "width", "height",
  "class",
];

export function sanitizeHtml(input: string): string {
  // Forbid javascript: / data: hrefs and any inline event handlers.
  const out = DOMPurify.sanitize(input, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    FORBID_ATTR: ["style", "onerror", "onclick", "onload", "onmouseover"],
    ALLOW_DATA_ATTR: false,
    USE_PROFILES: { html: true },
  });
  return typeof out === "string" ? out : "";
}

// Cheap HTML -> text for previews + search. Doesn't need to be perfect — it
// drives the blog list snippet only.
export function htmlToText(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}
