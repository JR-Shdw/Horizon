// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/**
 * pixelarray, micro pixel drawing library
 * Zero dependencies. Pure canvas 2D. fillRect(x, y, size, size).
 *
 * @author shdw
 * @license MIT
 * @version 2.0.0
 */

'use strict';

class PixelArray {
  /**
   * @param {HTMLCanvasElement|string} canvas, element or CSS selector
   * @param {object} [opts]
   * @param {number} [opts.pixelSize=1], size of each pixel square
   * @param {boolean} [opts.autoClear=false], clear canvas each frame
   */
  constructor(canvas, opts = {}) {
    this.el = typeof canvas === 'string'
      ? document.querySelector(canvas)
      : canvas;
    if (!this.el) throw new Error('pixelarray: canvas not found');
    this.ctx = this.el.getContext('2d');
    this.w = this.el.width;
    this.h = this.el.height;
    this.ps = opts.pixelSize || 1;
    this.autoClear = opts.autoClear || false;
    this._raf = null;
    this._running = false;
  }

  /** Draw a single pixel at (x, y) */
  dot(x, y, r, g, b, a = 1) {
    this.ctx.fillStyle = a < 1
      ? `rgba(${r},${g},${b},${a})`
      : `rgb(${r},${g},${b})`;
    this.ctx.fillRect(x, y, this.ps, this.ps);
  }

  /** Draw with CSS color string */
  dotc(x, y, color) {
    this.ctx.fillStyle = color;
    this.ctx.fillRect(x, y, this.ps, this.ps);
  }

  /** Draw rectangle */
  rect(x, y, w, h, r, g, b, a = 1) {
    this.ctx.fillStyle = a < 1
      ? `rgba(${r},${g},${b},${a})`
      : `rgb(${r},${g},${b})`;
    this.ctx.fillRect(x, y, w, h);
  }

  /** Clear entire canvas */
  clear() {
    this.ctx.clearRect(0, 0, this.w, this.h);
  }

  /** Fill entire canvas with color */
  fill(r, g, b, a = 1) {
    this.ctx.fillStyle = a < 1
      ? `rgba(${r},${g},${b},${a})`
      : `rgb(${r},${g},${b})`;
    this.ctx.fillRect(0, 0, this.w, this.h);
  }

  /** Fade canvas (overlay with translucent color) */
  fade(r = 0, g = 0, b = 0, a = 0.05) {
    this.ctx.fillStyle = `rgba(${r},${g},${b},${a})`;
    this.ctx.fillRect(0, 0, this.w, this.h);
  }

  /** Start animation loop */
  run(fn) {
    if (fn) this._lastFn = fn;
    const render = this._lastFn;
    this._running = true;
    const loop = () => {
      if (!this._running) return;
      if (this.autoClear) this.clear();
      render(this);
      this._raf = requestAnimationFrame(loop);
    };
    this._raf = requestAnimationFrame(loop);
  }

  /** Stop animation loop */
  stop() {
    this._running = false;
    if (this._raf) cancelAnimationFrame(this._raf);
  }

  /** Resize canvas to parent or specific size */
  resize(w, h) {
    this.el.width = w || this.el.parentElement.clientWidth;
    this.el.height = h || this.el.parentElement.clientHeight;
    this.w = this.el.width;
    this.h = this.el.height;
  }
}

// Global, loaded via <script src>
if (typeof window !== 'undefined') {
  window.PixelArray = PixelArray;
}
