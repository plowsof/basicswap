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
check("sha256 known vectors", () => {
  const hx = (b) => Buffer.from(b).toString("hex");
  assert.strictEqual(
    hx(A.sha256(new Uint8Array([]))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  );
  assert.strictEqual(
    hx(A.sha256(new TextEncoder().encode("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  );
});
check("BTC base58check: valid true, tampered/junk false (authoritative)", () => {
  assert.strictEqual(
    A.isValidAddressForCoin("Bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    true
  );
  assert.strictEqual(
    A.isValidAddressForCoin("Bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
    false
  );
  assert.strictEqual(A.isValidAddressForCoin("Bitcoin", "bad addr!!"), false);
});
check("BTC bech32/bech32m: valid true, tampered false", () => {
  assert.strictEqual(
    A.isValidAddressForCoin("Bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    true
  );
  assert.strictEqual(
    A.isValidAddressForCoin(
      "Bitcoin",
      "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    ),
    true
  );
  assert.strictEqual(
    A.isValidAddressForCoin("Bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
    false
  );
});
check("BCH cashaddr: valid (prefixed and bare) true, tampered false", () => {
  assert.strictEqual(
    A.isValidAddressForCoin(
      "Bitcoin Cash",
      "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    ),
    true
  );
  assert.strictEqual(
    A.isValidAddressForCoin(
      "Bitcoin Cash",
      "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"
    ),
    true
  );
  assert.strictEqual(
    A.isValidAddressForCoin(
      "Bitcoin Cash",
      "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b"
    ),
    false
  );
});
check("monero invalid is authoritative false; Decred is advisory null", () => {
  assert.strictEqual(A.isValidAddressForCoin("Monero", "notanaddress"), false);
  assert.strictEqual(A.isValidAddressForCoin("Decred", "Dsunvalidatedoffline"), null);
});

console.log("\n" + passed + " passed");
