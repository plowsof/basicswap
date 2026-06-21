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

// Address specs as the server builds them from chainparams.py (per network).
const BTC = { type: "base58", b58: [0, 5], hrp: "bc" }; // mainnet
const PART = { type: "base58", b58: [56, 60, 20], hrp: "pw" }; // mainnet
const PART_RT = { type: "base58", b58: [118, 122, 21], hrp: "rtpw" }; // regtest
const BCH = { type: "cashaddr", prefix: "bitcoincash", b58: [0, 5] };
const XMR_SPEC = { type: "monero" };

check("sha256 known vectors", () => {
  assert.strictEqual(
    hex(A.sha256(new Uint8Array([]))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
  assert.strictEqual(
    hex(A.sha256(new TextEncoder().encode("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});

// The regression: a checksum-valid address of the WRONG coin must be rejected.
// Before per-coin prefixes, this returned true (a BTC address "validated" as
// Particl). The version byte / hrp check now catches it.
check("REGRESSION: a Bitcoin address is rejected in a Particl field", () => {
  const btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
  assert.strictEqual(A.isValidAddressForSpec(BTC, btc), true);
  assert.strictEqual(A.isValidAddressForSpec(PART, btc), false);
  // bech32 too: a bc1 address must not pass for a pw-prefixed coin.
  const btcSeg = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
  assert.strictEqual(A.isValidAddressForSpec(BTC, btcSeg), true);
  assert.strictEqual(A.isValidAddressForSpec(PART, btcSeg), false);
});
check("a Particl address is rejected in a Bitcoin field", () => {
  const part = "pX9N6S76ZtA5BfsiJmqBbjaEgLMHpt58it"; // regtest, version 0x76
  assert.strictEqual(A.isValidAddressForSpec(PART_RT, part), true);
  assert.strictEqual(A.isValidAddressForSpec(BTC, part), false);
});
check("BTC base58check + bech32m valid; tampered/junk false", () => {
  assert.strictEqual(A.isValidAddressForSpec(BTC, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), true);
  assert.strictEqual(A.isValidAddressForSpec(BTC, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"), false);
  assert.strictEqual(A.isValidAddressForSpec(BTC, "bad addr!!"), false);
  assert.strictEqual(
    A.isValidAddressForSpec(BTC, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"),
    true
  );
});
check("BCH cashaddr (prefixed and bare) valid; cross-coin/tampered false", () => {
  assert.strictEqual(
    A.isValidAddressForSpec(BCH, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    true
  );
  assert.strictEqual(
    A.isValidAddressForSpec(BCH, "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"),
    true
  );
  assert.strictEqual(
    A.isValidAddressForSpec(BCH, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b"),
    false
  );
});
check("Monero spec: valid true, invalid false; empty/no-spec advisory null", () => {
  assert.strictEqual(A.isValidAddressForSpec(XMR_SPEC, XMR), true);
  assert.strictEqual(A.isValidAddressForSpec(XMR_SPEC, "notanaddress"), false);
  assert.strictEqual(A.isValidAddressForSpec(XMR_SPEC, ""), null); // empty optional
  assert.strictEqual(A.isValidAddressForSpec({}, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), null); // no validator -> advisory
});

console.log("\n" + passed + " passed");
