(function() {
  'use strict';

  // --- Payout address validation (advisory UX only; postBid validates
  // authoritatively server-side via CoinInterface.isValidAddress). Monero /
  // Wownero get a full Base58 + Keccak-256 checksum check, other coins a
  // lightweight format check to catch typos. ---
  const AddressValidation = (function() {
    const RC = [
      0x00000001, 0x00000000, 0x00008082, 0x00000000, 0x0000808a, 0x80000000,
      0x80008000, 0x80000000, 0x0000808b, 0x00000000, 0x80000001, 0x00000000,
      0x80008081, 0x80000000, 0x00008009, 0x80000000, 0x0000008a, 0x00000000,
      0x00000088, 0x00000000, 0x80008009, 0x00000000, 0x8000000a, 0x00000000,
      0x8000808b, 0x00000000, 0x0000008b, 0x80000000, 0x00008089, 0x80000000,
      0x00008003, 0x80000000, 0x00008002, 0x80000000, 0x00000080, 0x80000000,
      0x0000800a, 0x00000000, 0x8000000a, 0x80000000, 0x80008081, 0x80000000,
      0x00008080, 0x80000000, 0x80000001, 0x00000000, 0x80008008, 0x80000000,
    ];
    const RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
    const PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

    function keccakF(s) {
      const bc = new Int32Array(10);
      for (let round = 0; round < 24; round++) {
        for (let i = 0; i < 5; i++) {
          bc[i * 2] = s[i * 2] ^ s[i * 2 + 10] ^ s[i * 2 + 20] ^ s[i * 2 + 30] ^ s[i * 2 + 40];
          bc[i * 2 + 1] = s[i * 2 + 1] ^ s[i * 2 + 11] ^ s[i * 2 + 21] ^ s[i * 2 + 31] ^ s[i * 2 + 41];
        }
        for (let i = 0; i < 5; i++) {
          const i1 = ((i + 1) % 5) * 2;
          const i4 = ((i + 4) % 5) * 2;
          const t_lo = bc[i4] ^ ((bc[i1] << 1) | (bc[i1 + 1] >>> 31));
          const t_hi = bc[i4 + 1] ^ ((bc[i1 + 1] << 1) | (bc[i1] >>> 31));
          for (let j = 0; j < 25; j += 5) {
            s[(j + i) * 2] ^= t_lo;
            s[(j + i) * 2 + 1] ^= t_hi;
          }
        }
        let t_lo = s[2], t_hi = s[3];
        for (let i = 0; i < 24; i++) {
          const j = PI[i];
          const b_lo = s[j * 2], b_hi = s[j * 2 + 1];
          const r = RHO[i];
          if (r < 32) {
            s[j * 2] = (t_lo << r) | (t_hi >>> (32 - r));
            s[j * 2 + 1] = (t_hi << r) | (t_lo >>> (32 - r));
          } else {
            const rr = r - 32;
            s[j * 2] = (t_hi << rr) | (t_lo >>> (32 - rr));
            s[j * 2 + 1] = (t_lo << rr) | (t_hi >>> (32 - rr));
          }
          t_lo = b_lo; t_hi = b_hi;
        }
        for (let j = 0; j < 25; j += 5) {
          for (let i = 0; i < 5; i++) {
            bc[i * 2] = s[(j + i) * 2];
            bc[i * 2 + 1] = s[(j + i) * 2 + 1];
          }
          for (let i = 0; i < 5; i++) {
            s[(j + i) * 2] ^= ~bc[((i + 1) % 5) * 2] & bc[((i + 2) % 5) * 2];
            s[(j + i) * 2 + 1] ^= ~bc[((i + 1) % 5) * 2 + 1] & bc[((i + 2) % 5) * 2 + 1];
          }
        }
        s[0] ^= RC[round * 2];
        s[1] ^= RC[round * 2 + 1];
      }
    }

    function keccak256(bytes) {
      const s = new Int32Array(50);
      const blockBytes = 136;
      const padded = new Uint8Array(Math.ceil((bytes.length + 1) / blockBytes) * blockBytes);
      padded.set(bytes);
      padded[bytes.length] ^= 0x01;
      padded[padded.length - 1] ^= 0x80;
      for (let off = 0; off < padded.length; off += blockBytes) {
        for (let i = 0; i < blockBytes / 4; i++) {
          s[i] ^= padded[off + i * 4] | (padded[off + i * 4 + 1] << 8) | (padded[off + i * 4 + 2] << 16) | (padded[off + i * 4 + 3] << 24);
        }
        keccakF(s);
      }
      const out = new Uint8Array(32);
      for (let i = 0; i < 4; i++) {
        const lo = s[i * 2], hi = s[i * 2 + 1];
        out[i * 8] = lo & 0xff; out[i * 8 + 1] = (lo >>> 8) & 0xff; out[i * 8 + 2] = (lo >>> 16) & 0xff; out[i * 8 + 3] = (lo >>> 24) & 0xff;
        out[i * 8 + 4] = hi & 0xff; out[i * 8 + 5] = (hi >>> 8) & 0xff; out[i * 8 + 6] = (hi >>> 16) & 0xff; out[i * 8 + 7] = (hi >>> 24) & 0xff;
      }
      return out;
    }

    const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const FULL_BLOCK_SIZE = 8, FULL_ENCODED_BLOCK_SIZE = 11;
    const ENC_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];

    function decodeBlock(str, buf, index) {
      const size = ENC_LEN.indexOf(str.length);
      if (size <= 0) return false;
      let resNum = 0n, order = 1n;
      for (let i = str.length - 1; i >= 0; i--) {
        const digit = B58.indexOf(str[i]);
        if (digit < 0) return false;
        resNum += order * BigInt(digit);
        order *= 58n;
      }
      if (size < FULL_BLOCK_SIZE && resNum >= 1n << BigInt(8 * size)) return false;
      for (let i = size - 1; i >= 0; i--) { buf[index + i] = Number(resNum & 0xffn); resNum >>= 8n; }
      return true;
    }

    function moneroBase58Decode(address) {
      if (address.length === 0) return null;
      const fullBlocks = Math.floor(address.length / FULL_ENCODED_BLOCK_SIZE);
      const lastSize = address.length % FULL_ENCODED_BLOCK_SIZE;
      const lastDecoded = ENC_LEN.indexOf(lastSize);
      if (lastSize !== 0 && lastDecoded <= 0) return null;
      const dataLen = fullBlocks * FULL_BLOCK_SIZE + (lastSize ? lastDecoded : 0);
      const buf = new Uint8Array(dataLen);
      for (let i = 0; i < fullBlocks; i++) {
        if (!decodeBlock(address.substr(i * FULL_ENCODED_BLOCK_SIZE, FULL_ENCODED_BLOCK_SIZE), buf, i * FULL_BLOCK_SIZE)) return null;
      }
      if (lastSize) {
        if (!decodeBlock(address.substr(fullBlocks * FULL_ENCODED_BLOCK_SIZE, lastSize), buf, fullBlocks * FULL_BLOCK_SIZE)) return null;
      }
      return buf;
    }

    function isValidMoneroAddress(address) {
      const data = moneroBase58Decode(address);
      if (!data || (data.length !== 69 && data.length !== 77)) return false;
      const payload = data.slice(0, data.length - 4);
      const checksum = data.slice(data.length - 4);
      const hash = keccak256(payload);
      for (let i = 0; i < 4; i++) { if (hash[i] !== checksum[i]) return false; }
      return true;
    }

    const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;
    const BECH32_RE = /^[a-z0-9]+$/;
    function isPlausibleBtcLikeAddress(address) {
      if (/^(bc1|tb1|bcrt1|ltc1|rltc1|tltc1|pw1|tpw1|rtpw1)[0-9a-z]{6,}$/i.test(address)) {
        return BECH32_RE.test(address.toLowerCase());
      }
      return address.length >= 26 && address.length <= 90 && BASE58_RE.test(address);
    }

    function isValidAddressForCoin(coin, address) {
      if (!address) return null; // empty allowed (optional field)
      const c = String(coin || "").toLowerCase();
      if (c.indexOf("monero") !== -1 || c.indexOf("wownero") !== -1) return isValidMoneroAddress(address);
      return isPlausibleBtcLikeAddress(address);
    }

    return { isValidAddressForCoin, isValidMoneroAddress, keccak256 };
  })();

  // Exported for node-based unit testing (tests/basicswap/test_address_validation.js).
  if (typeof module !== 'undefined' && module.exports) module.exports = AddressValidation;

  const OfferPage = {
    xhr_rates: null,
    xhr_bid_params: null,
    xhr_bid_prefund: null,

    init: function() {
      this.xhr_rates = new XMLHttpRequest();
      this.xhr_bid_params = new XMLHttpRequest();
      this.xhr_bid_prefund = new XMLHttpRequest();

      this.setupXHRHandlers();
      this.setupEventListeners();
      this.handleBidsPageAddress();
      this.setupPayoutValidation();
    },

    payoutAddressValid: function() {
      // Returns true when the optional payout address is empty or valid.
      const input = document.getElementById('payout_address');
      if (!input) return true;
      const value = input.value.trim();
      if (value === '') return true;
      const result = AddressValidation.isValidAddressForCoin(input.dataset.coin, value);
      return result !== false;
    },

    setupPayoutValidation: function() {
      const input = document.getElementById('payout_address');
      const feedback = document.getElementById('payout_address_feedback');
      if (!input) return;
      const render = () => {
        const value = input.value.trim();
        const result = AddressValidation.isValidAddressForCoin(input.dataset.coin, value);
        if (feedback) feedback.classList.add('hidden');
        input.classList.remove('border-red-500', 'border-green-500');
        if (value === '' || result === null) return;
        if (result) {
          input.classList.add('border-green-500');
        } else {
          input.classList.add('border-red-500');
          if (feedback) {
            feedback.textContent = 'This does not look like a valid ' + (input.dataset.coin || 'coin') + ' address.';
            feedback.className = 'mt-1 text-xs text-red-500';
          }
        }
      };
      input.addEventListener('blur', render);
      input.addEventListener('input', render);
    },

    setupXHRHandlers: function() {
      this.xhr_rates.onload = () => {
        if (this.xhr_rates.status == 200) {
          const obj = JSON.parse(this.xhr_rates.response);
          const inner_html = '<h4 class="bold">Rates</h4><pre><code>' + JSON.stringify(obj, null, '  ') + '</code></pre>';
          const ratesDisplay = document.getElementById('rates_display');
          if (ratesDisplay) {
            ratesDisplay.innerHTML = inner_html;
          }
        }
      };

      this.xhr_bid_params.onload = () => {
        if (this.xhr_bid_params.status == 200) {
          const obj = JSON.parse(this.xhr_bid_params.response);
          const bidAmountSendInput = document.getElementById('bid_amount_send');
          if (bidAmountSendInput) {
            bidAmountSendInput.value = obj['amount_to'];
          }
        }
      };

      this.xhr_bid_prefund.onload = () => {
        if (this.xhr_bid_prefund.status == 200) {
          const obj = JSON.parse(this.xhr_bid_prefund.response);
          const bidAmountInput = document.getElementById('bid_amount');
          if (bidAmountInput) {
            bidAmountInput.value = obj['amount_from'];
          }
          const prefundedBidInput = document.getElementById('prefunded_bid_tx');
          if (prefundedBidInput) {
            prefundedBidInput.value = obj['bid_tx'];
          }
        }
      };
    },

    setupEventListeners: function() {
      const sendBidBtn = document.querySelector('button[name="sendbid"][value="Send Bid"]');
      if (sendBidBtn) {
        sendBidBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.showConfirmModal();
        });
      }

      const modalCancelBtn = document.querySelector('#confirmModal [data-hide-modal]');
      if (modalCancelBtn) {
        modalCancelBtn.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          this.hideConfirmModal();
        });
      }

      const confirmModal = document.getElementById('confirmModal');
      if (confirmModal) {
        confirmModal.addEventListener('click', (e) => {
          if (e.target === confirmModal || e.target.classList.contains('bg-opacity-50')) {
            this.hideConfirmModal();
          }
        });
      }

      const mainCancelBtn = document.querySelector('button[name="cancel"]');
      if (mainCancelBtn) {
        mainCancelBtn.onclick = this.handleCancelClick.bind(this);
      }

      const errorOkBtn = document.getElementById('errorOk');
      if (errorOkBtn) {
        errorOkBtn.addEventListener('click', this.hideErrorModal.bind(this));
      }
    },

    lookup_rates: function() {
      const coin_from = document.getElementById('coin_from')?.value;
      const coin_to = document.getElementById('coin_to')?.value;

      if (!coin_from || !coin_to || coin_from === '-1' || coin_to === '-1') {
        alert('Coins from and to must be set first.');
        return;
      }

      const ratesDisplay = document.getElementById('rates_display');
      if (ratesDisplay) {
        ratesDisplay.innerHTML = '<h4>Rates</h4><p>Updating...</p>';
      }

      this.xhr_rates.open('POST', '/json/rates');
      this.xhr_rates.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
      this.xhr_rates.send(`coin_from=${coin_from}&coin_to=${coin_to}`);
    },

    resetForm: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');
      const bidRateInput = document.getElementById('bid_rate');
      const validMinsInput = document.querySelector('input[name="validmins"]');
      const amtVar = document.getElementById('amt_var')?.value === 'True';

      if (bidAmountSendInput) {
        bidAmountSendInput.value = amtVar ? '' : bidAmountSendInput.getAttribute('max');
      }
      if (bidAmountInput) {
        bidAmountInput.value = amtVar ? '' : bidAmountInput.getAttribute('max');
      }
      if (bidRateInput && !bidRateInput.disabled) {
        const defaultRate = document.getElementById('offer_rate')?.value || '';
        bidRateInput.value = defaultRate;
      }
      if (validMinsInput) {
        validMinsInput.value = "60";
      }
      if (!amtVar) {
        this.updateBidParams('rate');
      }

      const errorMessages = document.querySelectorAll('.error-message');
      errorMessages.forEach(msg => msg.remove());

      const inputs = document.querySelectorAll('input');
      inputs.forEach(input => {
        input.classList.remove('border-red-500', 'focus:border-red-500');
      });
    },

    roundUpToDecimals: function(value, decimals) {
      const factor = Math.pow(10, decimals);
      return Math.ceil(value * factor) / factor;
    },

    updateBidParams: function(value_changed) {
      const coin_from = document.getElementById('coin_from')?.value;
      const coin_to = document.getElementById('coin_to')?.value;
      const coin_from_exp = parseInt(document.getElementById('coin_from_exp')?.value || '8');
      const coin_to_exp = parseInt(document.getElementById('coin_to_exp')?.value || '8');
      const amt_var = document.getElementById('amt_var')?.value;
      const rate_var = document.getElementById('rate_var')?.value;
      const bidAmountInput = document.getElementById('bid_amount');
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidRateInput = document.getElementById('bid_rate');
      const offerRateInput = document.getElementById('offer_rate');
      const bidSubfee = document.getElementById('subfee_bid');

      if (!coin_from || !coin_to || !amt_var || !rate_var) return;

      const rate = rate_var === 'True' && bidRateInput ?
        parseFloat(bidRateInput.value) || 0 :
        parseFloat(offerRateInput?.value || '0');

      if (!rate) return;

      if (value_changed === 'rate') {
        if (bidAmountSendInput && bidAmountInput) {
          const sendAmount = parseFloat(bidAmountSendInput.value) || 0;
          const receiveAmount = (sendAmount / rate).toFixed(coin_from_exp);
          bidAmountInput.value = receiveAmount;
        }
      } else if (value_changed === 'sending' || value_changed === 'subfee') {
        if (bidAmountSendInput && bidAmountInput) {
          const sendAmount = parseFloat(bidAmountSendInput.value) || 0;
          const receiveAmount = (sendAmount / rate).toFixed(coin_from_exp);
          bidAmountInput.value = receiveAmount;
        }
      } else if (value_changed === 'receiving') {
        if (bidAmountInput && bidAmountSendInput) {
          const receiveAmount = parseFloat(bidAmountInput.value) || 0;
          const sendAmount = this.roundUpToDecimals(receiveAmount * rate, coin_to_exp).toFixed(coin_to_exp);
          bidAmountSendInput.value = sendAmount;
        }
      }

      this.validateAmountsAfterChange();

      if (bidSubfee && bidSubfee.checked) {
        bidAmountInput.readOnly = true;

        const offer_id = document.getElementById('offer_id')?.value || '';
        if (!offer_id) {
          console.log("offer_id not found!");
          return;
        }
        this.xhr_bid_prefund.open('POST', '/json/getsubfeebidtx');
        this.xhr_bid_prefund.setRequestHeader('Content-type', 'application/json;charset=UTF-8');
        const data = { offer_id: offer_id, amount_to: bidAmountSendInput.value , bid_rate: rate};
        this.xhr_bid_prefund.overrideMimeType("application/json");
        this.xhr_bid_prefund.send(JSON.stringify(data));
        return;
      }
      bidAmountInput.readOnly = false;
      const prefundedBidInput = document.getElementById('prefunded_bid_tx');
      if (prefundedBidInput) {
        prefundedBidInput.value = "";
      }

      this.xhr_bid_params.open('POST', '/json/rate');
      this.xhr_bid_params.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
      this.xhr_bid_params.overrideMimeType("application/json");
      this.xhr_bid_params.send(`coin_from=${coin_from}&coin_to=${coin_to}&rate=${rate}&amt_from=${bidAmountInput?.value || '0'}`);
    },

    validateAmountsAfterChange: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');

      if (bidAmountSendInput) {
        const maxSend = parseFloat(bidAmountSendInput.getAttribute('max'));
        this.validateMaxAmount(bidAmountSendInput, maxSend);
      }
      if (bidAmountInput) {
        const maxReceive = parseFloat(bidAmountInput.getAttribute('max'));
        this.validateMaxAmount(bidAmountInput, maxReceive);
      }
    },

    validateMaxAmount: function(input, maxAmount) {
      if (!input) return;
      const value = parseFloat(input.value) || 0;
      if (value > maxAmount) {
        input.value = maxAmount;
      }
    },

    showErrorModal: function(title, message) {
      document.getElementById('errorTitle').textContent = title || 'Error';
      document.getElementById('errorMessage').textContent = message || 'An error occurred';
      const modal = document.getElementById('errorModal');
      if (modal) {
        modal.classList.remove('hidden');
      }
    },

    hideErrorModal: function() {
      const modal = document.getElementById('errorModal');
      if (modal) {
        modal.classList.add('hidden');
      }
    },

    showConfirmModal: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');
      const validMinsInput = document.querySelector('input[name="validmins"]');
      const addrFromSelect = document.querySelector('select[name="addr_from"]');

      let sendAmount = 0;
      let receiveAmount = 0;

      if (bidAmountSendInput && bidAmountSendInput.value) {
        sendAmount = parseFloat(bidAmountSendInput.value) || 0;
      }

      if (bidAmountInput && bidAmountInput.value) {
        receiveAmount = parseFloat(bidAmountInput.value) || 0;
      }

      if (sendAmount <= 0 || receiveAmount <= 0) {
        this.showErrorModal('Validation Error', 'Please enter valid amounts for both sending and receiving.');
        return false;
      }
      if (!this.payoutAddressValid()) {
        this.showErrorModal('Validation Error', 'The payout address is not a valid address for this coin.');
        return false;
      }
      let subfee = false;
      const checkbox = document.getElementById('subfee_bid');
      if (checkbox) {
        subfee = checkbox.checked;
      }

      const coinFrom = document.getElementById('coin_from_name')?.value || '';
      const coinTo = document.getElementById('coin_to_name')?.value || '';
      const tlaFrom = document.getElementById('tla_from')?.value || '';
      const tlaTo = document.getElementById('tla_to')?.value || '';

      const validMins = validMinsInput ? validMinsInput.value : '60';

      const addrFrom = addrFromSelect ? addrFromSelect.value : '';

      const modalAmtReceive = document.getElementById('modal-amt-receive');
      const modalReceiveCurrency = document.getElementById('modal-receive-currency');
      const modalAmtSend = document.getElementById('modal-amt-send');
      const modalSendCurrency = document.getElementById('modal-send-currency');
      const modalAddrFrom = document.getElementById('modal-addr-from');
      const modalValidMins = document.getElementById('modal-valid-mins');

      if (modalAmtReceive) modalAmtReceive.textContent = receiveAmount.toFixed(8);
      if (modalReceiveCurrency) modalReceiveCurrency.textContent = ` ${tlaFrom}`;
      if (modalAmtSend) modalAmtSend.textContent = sendAmount.toFixed(8);
      if (modalSendCurrency) {
        modalSendCurrency.textContent = ` ${tlaTo}`;
        if (subfee) {
          modalSendCurrency.textContent += ` (incl fee)`;
        }
      }
      if (modalAddrFrom) modalAddrFrom.textContent = addrFrom || 'Default';
      if (modalValidMins) modalValidMins.textContent = validMins;

      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.remove('hidden');
      }
      return false;
    },

    hideConfirmModal: function() {
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.add('hidden');
      }
      return false;
    },

    handleBidsPageAddress: function() {
      const selectElement = document.querySelector('select[name="addr_from"]');
      const STORAGE_KEY = 'lastUsedAddressBids';

      if (!selectElement) return;

      const loadInitialAddress = () => {
        const savedAddressJSON = localStorage.getItem(STORAGE_KEY);
        if (savedAddressJSON) {
          try {
            const savedAddress = JSON.parse(savedAddressJSON);
            selectElement.value = savedAddress.value;
          } catch (e) {
            selectFirstAddress();
          }
        } else {
          selectFirstAddress();
        }
      };

      const selectFirstAddress = () => {
        if (selectElement.options.length > 1) {
          const firstOption = selectElement.options[1];
          if (firstOption) {
            selectElement.value = firstOption.value;
            this.saveAddress(firstOption.value, firstOption.text);
          }
        }
      };

      selectElement.addEventListener('change', (event) => {
        this.saveAddress(event.target.value, event.target.selectedOptions[0].text);
      });

      loadInitialAddress();
    },

    saveAddress: function(value, text) {
      const addressData = {
        value: value,
        text: text
      };
      localStorage.setItem('lastUsedAddressBids', JSON.stringify(addressData));
    },

    confirmPopup: function() {
      return confirm("Are you sure?");
    },

    handleCancelClick: function(event) {
      if (event) event.preventDefault();
      const pathParts = window.location.pathname.split('/');
      const offerId = pathParts[pathParts.indexOf('offer') + 1];
      window.location.href = `/offer/${offerId}`;
    },

    cleanup: function() {
    }
  };

  // Skip DOM wiring when loaded outside a browser (node-based unit tests).
  if (typeof document === 'undefined' || typeof window === 'undefined') return;

  document.addEventListener('DOMContentLoaded', function() {
    OfferPage.init();

    if (window.CleanupManager) {
      CleanupManager.registerResource('offerPage', OfferPage, (page) => {
        if (page.cleanup) page.cleanup();
      });
    }
  });

  window.OfferPage = OfferPage;
  window.lookup_rates = OfferPage.lookup_rates.bind(OfferPage);
  window.resetForm = OfferPage.resetForm.bind(OfferPage);
  window.updateBidParams = OfferPage.updateBidParams.bind(OfferPage);
  window.validateMaxAmount = OfferPage.validateMaxAmount.bind(OfferPage);
  window.showConfirmModal = OfferPage.showConfirmModal.bind(OfferPage);
  window.hideConfirmModal = OfferPage.hideConfirmModal.bind(OfferPage);
  window.showErrorModal = OfferPage.showErrorModal.bind(OfferPage);
  window.hideErrorModal = OfferPage.hideErrorModal.bind(OfferPage);
  window.confirmPopup = OfferPage.confirmPopup.bind(OfferPage);
  window.handleBidsPageAddress = OfferPage.handleBidsPageAddress.bind(OfferPage);

})();
