import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { leadingZeroBits, powDigest, searchPow, solvePow, verifyPow } from "./hashcash";

describe("Hashcash (rout.pow.v1)", () => {
  it("counts leading zero bits exactly", () => {
    expect(leadingZeroBits(Uint8Array.of(0, 0, 0x80))).toBe(16);
    expect(leadingZeroBits(Uint8Array.of(0, 0x01))).toBe(15);
    expect(leadingZeroBits(Uint8Array.of(0xff))).toBe(0);
    expect(leadingZeroBits(new Uint8Array(4))).toBe(32);
  });

  it("every solution verifies at its difficulty", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.integer({ min: 1, max: 12 }), (challenge, bits) => {
        const nonce = solvePow(challenge, bits, 1);
        return verifyPow(challenge, nonce, bits) && leadingZeroBits(powDigest(challenge, nonce)) >= bits;
      }),
      { numRuns: 30 },
    );
  });

  it("the digest is bound to the challenge and the nonce", () => {
    const challenge = new Uint8Array(32).fill(5);
    const nonce = solvePow(challenge, 10, 1);
    const other = challenge.slice();
    other[0] = 4;
    expect(Buffer.from(powDigest(other, nonce)).equals(Buffer.from(powDigest(challenge, nonce)))).toBe(false);
  });

  it("rejects malformed inputs and the server floor", () => {
    expect(verifyPow(new Uint8Array(31), new Uint8Array(8), 1)).toBe(false);
    expect(verifyPow(new Uint8Array(32), new Uint8Array(7), 1)).toBe(false);
    expect(() => solvePow(new Uint8Array(32), 8)).toThrow();
    expect(searchPow(new Uint8Array(32), 26, 0, 4)).toBeNull();
  });
});
