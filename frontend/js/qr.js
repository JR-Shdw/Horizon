// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/**
 * Minimal QR Code encoder, byte mode, ECC level M, versions 1-10.
 * Pixelarray-style canvas renderer (white on dark).
 *
 * Usage:
 *   drawQR('canvas-id', 'otpauth://totp/...', { scale: 4 });
 */
'use strict';

/* GF(256) for Reed-Solomon */

const _EXP = new Uint8Array(512);
const _LOG = new Uint8Array(256);
(function () {
  let v = 1;
  for (let i = 0; i < 255; i++) {
    _EXP[i] = v; _LOG[v] = i;
    v = (v << 1) ^ (v & 128 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) _EXP[i] = _EXP[i - 255];
})();

function _rsEncode(data, ecLen) {
  // Build generator polynomial
  const gen = new Uint8Array(ecLen + 1);
  gen[0] = 1;
  for (let i = 0; i < ecLen; i++) {
    for (let j = i + 1; j >= 1; j--) {
      gen[j] = gen[j] ^ (gen[j - 1] && _EXP[_LOG[gen[j - 1]] + i] || 0);
    }
  }
  // Polynomial division
  const rem = new Uint8Array(ecLen);
  for (let i = 0; i < data.length; i++) {
    const f = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecLen - 1] = 0;
    if (f) {
      for (let j = 0; j < ecLen; j++) {
        rem[j] ^= _EXP[_LOG[gen[j + 1]] + _LOG[f]];
      }
    }
  }
  return rem;
}

/* Version table, ECC level M */
// [size, totalDataCodewords, ecCodewordsPerBlock, numBlocks, alignPos]

const _VER = [
  null,
  [21,  16, 10, 1, 0],   // V1
  [25,  28, 16, 1, 18],  // V2
  [29,  44, 26, 1, 22],  // V3
  [33,  64, 18, 2, 26],  // V4
  [37,  86, 24, 2, 30],  // V5
  [41, 108, 16, 4, 34],  // V6
  [45, 124, 18, 4, 22],  // V7 (multiple alignment)
  [49, 154, 22, 4, 24],  // V8
  [53, 182, 22, 4, 26],  // V9
  [57, 216, 26, 4, 28],  // V10
];

// Alignment pattern positions per version (centers)
const _ALIGN = [
  null, [], [6,18], [6,22], [6,26], [6,30], [6,34],
  [6,22,38], [6,24,42], [6,26,46], [6,28,52],
];

function _pickVersion(byteLen) {
  for (let v = 1; v <= 10; v++) {
    const cntBits = v <= 9 ? 8 : 16;
    const needed = Math.ceil((4 + cntBits + byteLen * 8) / 8);
    if (needed <= _VER[v][1]) return v;
  }
  return 10;
}

/* Encode data → interleaved codewords */

function _encodeData(text) {
  const raw = new TextEncoder().encode(text);
  const ver = _pickVersion(raw.length);
  const [size, totalDC, ecPB, nBlocks] = _VER[ver];

  // Bit stream: mode(4) + count(8|16) + data + terminator + padding
  const bits = [];
  const put = (v, n) => { for (let i = n - 1; i >= 0; i--) bits.push((v >> i) & 1); };

  put(0b0100, 4);                         // byte mode
  put(raw.length, ver <= 9 ? 8 : 16);    // char count
  for (const b of raw) put(b, 8);        // data

  // Terminator (up to 4 zero bits)
  const cap = totalDC * 8;
  put(0, Math.min(4, cap - bits.length));
  while (bits.length & 7) bits.push(0);  // byte-align
  while (bits.length < cap) { put(0xEC, 8); if (bits.length < cap) put(0x11, 8); }

  // Bits → bytes
  const cw = new Uint8Array(totalDC);
  for (let i = 0; i < totalDC; i++) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i * 8 + j];
    cw[i] = b;
  }

  // Split blocks, RS encode each
  const dcPerShort = Math.floor(totalDC / nBlocks);
  const longBlocks = totalDC % nBlocks;
  const dBlocks = [], eBlocks = [];
  let off = 0;
  for (let b = 0; b < nBlocks; b++) {
    const len = dcPerShort + (b >= nBlocks - longBlocks ? 1 : 0);
    const block = cw.slice(off, off + len);
    dBlocks.push(block);
    eBlocks.push(_rsEncode(block, ecPB));
    off += len;
  }

  // Interleave data codewords
  const out = [];
  const maxDLen = dcPerShort + (longBlocks ? 1 : 0);
  for (let i = 0; i < maxDLen; i++)
    for (const b of dBlocks) if (i < b.length) out.push(b[i]);
  // Interleave EC codewords
  for (let i = 0; i < ecPB; i++)
    for (const b of eBlocks) out.push(b[i]);

  return { ver, size, codewords: out };
}

/* Build QR matrix */

function _buildMatrix(ver, size, codewords) {
  // 1 = black, 0 = white
  const mod = Array.from({ length: size }, () => new Uint8Array(size));
  const used = Array.from({ length: size }, () => new Uint8Array(size));

  function set(r, c, black) {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      mod[r][c] = black ? 1 : 0;
      used[r][c] = 1;
    }
  }

  // Finder patterns (7x7 + 1px separator)
  function finder(row, col) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = row + dr, c = col + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const outer = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const ring = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        set(r, c, outer && (ring || core));
      }
    }
  }
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);

  // Alignment patterns
  const ap = _ALIGN[ver] || [];
  for (const ar of ap) {
    for (const ac of ap) {
      // Skip if overlapping finder
      if (ar <= 8 && ac <= 8) continue;
      if (ar <= 8 && ac >= size - 8) continue;
      if (ar >= size - 8 && ac <= 8) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const edge = Math.abs(dr) === 2 || Math.abs(dc) === 2;
          const center = dr === 0 && dc === 0;
          set(ar + dr, ac + dc, edge || center);
        }
      }
    }
  }

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    if (!used[6][i]) set(6, i, i % 2 === 0);
    if (!used[i][6]) set(i, 6, i % 2 === 0);
  }

  // Dark module
  set(size - 8, 8, true);

  // Reserve format info areas
  for (let i = 0; i < 9; i++) {
    if (!used[8][i]) { used[8][i] = 1; }
    if (!used[i][8]) { used[i][8] = 1; }
  }
  for (let i = 0; i < 8; i++) {
    if (!used[8][size - 1 - i]) { used[8][size - 1 - i] = 1; }
    if (!used[size - 1 - i][8]) { used[size - 1 - i][8] = 1; }
  }

  // Place data bits (zigzag right-to-left, alternating up/down)
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let upward = true;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;   // skip timing column
    for (let i = 0; i < size; i++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        const r = upward ? (size - 1 - i) : i;
        if (used[r][c]) continue;
        if (bitIdx < totalBits) {
          mod[r][c] = (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
          bitIdx++;
        }
        used[r][c] = 1;
      }
    }
    upward = !upward;
  }

  // Apply mask 0: (row + col) % 2 === 0
  // Only on data/EC modules (used but not function patterns)
  // We need to track which are function patterns vs data
  // Rebuild function-pattern mask
  const func = Array.from({ length: size }, () => new Uint8Array(size));
  // Mark finders
  function markFunc(row, col, w, h) {
    for (let r = row; r < row + h && r < size; r++)
      for (let c = col; c < col + w && c < size; c++)
        if (r >= 0 && c >= 0) func[r][c] = 1;
  }
  markFunc(0, 0, 9, 9);                    // top-left finder + separator
  markFunc(0, size - 8, 8, 9);             // top-right
  markFunc(size - 8, 0, 9, 8);             // bottom-left
  // Timing
  for (let i = 0; i < size; i++) { func[6][i] = 1; func[i][6] = 1; }
  // Alignment
  for (const ar of ap) {
    for (const ac of ap) {
      if (ar <= 8 && ac <= 8) continue;
      if (ar <= 8 && ac >= size - 8) continue;
      if (ar >= size - 8 && ac <= 8) continue;
      markFunc(ar - 2, ac - 2, 5, 5);
    }
  }
  // Dark module
  func[size - 8][8] = 1;
  // Format info
  for (let i = 0; i < 9; i++) { func[8][i] = 1; func[i][8] = 1; }
  for (let i = 0; i < 8; i++) { func[8][size - 1 - i] = 1; func[size - 1 - i][8] = 1; }

  // Apply mask on data modules only
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!func[r][c] && (r + c) % 2 === 0) {
        mod[r][c] ^= 1;
      }
    }
  }

  // Write format info, ECC M (00), mask 0 (000)
  // Data: 00 000 → BCH: 0000000000 → XOR 101010000010010 = 101010000010010
  const fmt = [1,0,1,0,1,0,0,0,0,0,1,0,0,1,0];

  // Horizontal + vertical around top-left
  const fmtH = [
    [8,0],[8,1],[8,2],[8,3],[8,4],[8,5],  // 0-5: row 8, cols 0-5
    [8,7],[8,8],                           // 6-7: row 8, cols 7-8
    [7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8] // 8-14: col 8, rows 7,5,4,3,2,1,0
  ];
  // Bottom-left (vertical) + top-right (horizontal)
  const fmtV = [
    [size-1,8],[size-2,8],[size-3,8],[size-4,8],
    [size-5,8],[size-6,8],[size-7,8],     // 0-6: col 8, bottom rows
    [8,size-8],[8,size-7],[8,size-6],[8,size-5],
    [8,size-4],[8,size-3],[8,size-2],[8,size-1] // 7-14: row 8, right cols
  ];

  for (let i = 0; i < 15; i++) {
    const v = fmt[i];
    mod[fmtH[i][0]][fmtH[i][1]] = v;
    mod[fmtV[i][0]][fmtV[i][1]] = v;
  }

  return mod;
}

/* Canvas renderer */

function drawQR(canvasId, text, opts) {
  const { ver, size, codewords } = _encodeData(text);
  const matrix = _buildMatrix(ver, size, codewords);

  const scale = (opts && opts.scale) || 3;
  const quiet = 4;  // ISO requires 4 modules quiet zone
  const total = (size + quiet * 2) * scale;

  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  canvas.width = total;
  canvas.height = total;
  canvas.style.width = total + 'px';
  canvas.style.height = total + 'px';

  const ctx = canvas.getContext('2d');
  // White background (quiet zone)
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, total, total);

  // Black modules
  ctx.fillStyle = '#000';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
      }
    }
  }
}
