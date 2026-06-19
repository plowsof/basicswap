// Unit tests for the client-side payout-address validator embedded in
// basicswap/static/js/pages/offer-page.js.
//
//   node tests/basicswap/test_address_validation.js
//
// Verifies the Keccak-256 implementation against known vectors and the Monero
// Base58 + checksum address validation against real addresses.

const assert = require("assert");
const A = require("../../basicswap/static/js/pages/offer-page.js");

const hex = (b) => Buffer.from(b).toString("hex");
let passed = 0;

function check(name, fn) {
  fn();
  passed += 1;
  console.log("ok   - " + name);
}

// Keccak-256 (pre-NIST, as used by CryptoNote) known vectors.
check("keccak256 empty string", () => {
  assert.strictEqual(
    hex(A.keccak256(new Uint8Array([]))),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
  );
});
check("keccak256 'abc'", () => {
  assert.strictEqual(
    hex(A.keccak256(new TextEncoder().encode("abc"))),
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
  );
});

// Monero mainnet address (the project donation address) is valid.
const XMR = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
check("valid monero address", () => {
  assert.strictEqual(A.isValidMoneroAddress(XMR), true);
});
check("monero address with one char changed fails checksum", () => {
  const tampered = XMR.slice(0, -1) + (XMR.slice(-1) === "A" ? "B" : "A");
  assert.strictEqual(A.isValidMoneroAddress(tampered), false);
});
check("truncated monero address fails", () => {
  assert.strictEqual(A.isValidMoneroAddress(XMR.slice(0, 40)), false);
});
check("monero address with invalid base58 char fails", () => {
  assert.strictEqual(A.isValidMoneroAddress(XMR.slice(0, -1) + "0"), false);
});

// isValidAddressForCoin dispatch + optional-empty handling.
check("empty address returns null (optional field)", () => {
  assert.strictEqual(A.isValidAddressForCoin("Monero", ""), null);
});
check("monero coin dispatches to checksum validator", () => {
  assert.strictEqual(A.isValidAddressForCoin("Monero", XMR), true);
  assert.strictEqual(A.isValidAddressForCoin("Monero", "notanaddress"), false);
});
check("btc-like coin: plausible -> true, implausible -> null (advisory, never blocks)", () => {
  assert.strictEqual(
    A.isValidAddressForCoin("Bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    true
  );
  // Non-authoritative: must NOT report false (would block a valid bid).
  assert.strictEqual(A.isValidAddressForCoin("Bitcoin", "bad addr!!"), null);
});
check("BCH cashaddr is not falsely rejected (advisory null, not false)", () => {
  // Regression: the heuristic can't parse cashaddr; it must not block the bid.
  assert.strictEqual(
    A.isValidAddressForCoin(
      "Bitcoin Cash",
      "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    ),
    null
  );
});
check("monero invalid is still authoritative false (blocks)", () => {
  assert.strictEqual(A.isValidAddressForCoin("Monero", "notanaddress"), false);
});

console.log("\n" + passed + " passed");
