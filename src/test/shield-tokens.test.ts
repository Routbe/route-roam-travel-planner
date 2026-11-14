/** Veiligheidsschild colours: every level pair reaches WCAG AAA (>= 7:1) in light and dark mode. */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { contrastRatio, toHex } from "@/lib/wcag";

function hslToHex(h: number, s: number, l: number): string {
  s /= 100; l /= 100;
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return toHex([f(0) * 255, f(8) * 255, f(4) * 255]);
}

const css = readFileSync(resolve(__dirname, "../styles.css"), "utf8");
function block(selector: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = new RegExp(`(^|\\n)${selector.replace(".", "\\.")} \\{([^}]*)\\}`, "g");
  for (const m of css.matchAll(re)) {
    for (const d of m[2].matchAll(/--(shield-[a-z-]+):\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%;/g)) out[d[1]] = hslToHex(Number(d[2]), Number(d[3]), Number(d[4]));
  }
  return out;
}

describe("Veiligheidsschild colour tokens", () => {
  for (const [mode, tokens] of [["light", block(":root")], ["dark", block(".dark")]] as const) {
    for (const level of ["basic", "sovereign", "hardware"]) {
      it(`${mode} ${level}: text and icon on the pill reach at least 7:1`, () => {
        const bg = tokens[`shield-${level}`];
        const fg = tokens[`shield-${level}-foreground`];
        expect(bg, `missing --shield-${level} in ${mode}`).toBeTruthy();
        expect(fg, `missing --shield-${level}-foreground in ${mode}`).toBeTruthy();
        expect(contrastRatio(fg!, bg!)).toBeGreaterThanOrEqual(7);
      });
    }
  }
});
