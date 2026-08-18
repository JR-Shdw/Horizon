// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
/**
 * Black hole animation, spiral aspiration effect.
 * Fine 1px particles with long trails spiraling into the center.
 * 100% pixelarray v2 API, dot() + rect() + fade() + fill() only.
 *
 * Key icon animation for collapsed sidebar mode.
 * Green key = unsealed, Red key = sealed, orbiting white pixel.
 */
'use strict';

/* ===== BLACK HOLE (expanded sidebar) ===== */

const BH = {
  px: null,
  particles: [],
  jets: [],
  sealed: true,
};

function bhInit(canvasId) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  el.width = 160;
  el.height = 160;
  BH.px = new PixelArray(el, { pixelSize: 1 });
  BH.particles = [];

  for (let i = 0; i < 500; i++) {
    BH.particles.push(_bhNewParticle());
  }

  BH.jets = [];
  for (let i = 0; i < 40; i++) {
    BH.jets.push(_bhNewJet(80, 80, 12));
  }

  BH.px.run(() => { _bhFrame(); });
}

function _bhNewParticle() {
  const dist = 18 + Math.random() * 60;
  return {
    angle: Math.random() * Math.PI * 2,
    dist,
    baseDist: dist,
    speed: (0.004 + Math.random() * 0.015) / (dist * 0.03),
    brightness: 0.15 + Math.random() * 0.85,
    hue: Math.random() > 0.45 ? 'v' : 'c',
    trail: [],
    trailMax: 4 + Math.floor(Math.random() * 8 + dist * 0.15),
  };
}

function _bhNewJet(cx, cy, radius) {
  const up = Math.random() > 0.5;
  return {
    x: cx + (Math.random() - 0.5) * 2,
    y: up ? cy - radius - 1 - Math.random() * 3 : cy + radius + 1 + Math.random() * 3,
    vy: up ? -(0.6 + Math.random() * 1.2) : (0.6 + Math.random() * 1.2),
    brightness: 0.4 + Math.random() * 0.6,
    life: 0.6 + Math.random() * 0.4,
  };
}

function bhSetState(sealed) { BH.sealed = sealed; }

function _bhFrame() {
  const px = BH.px;
  const { particles, sealed } = BH;
  const cx = 80, cy = 80;
  const radius = 12;

  px.fade(5, 5, 8, 0.06);

  // Event horizon, filled circle with px.dot
  for (let dy = -radius; dy <= radius; dy++) {
    for (let dx = -radius; dx <= radius; dx++) {
      if (dx * dx + dy * dy <= radius * radius) {
        px.dot(cx + dx, cy + dy, 5, 5, 8);
      }
    }
  }

  // Glow when unsealed, concentric rings of purple/cyan
  if (!sealed) {
    for (let ring = 0; ring < 4; ring++) {
      const r = radius + 5 + ring * 10;
      const a = 0.08 - ring * 0.018;
      if (a <= 0) break;
      for (let ang = 0; ang < Math.PI * 2; ang += 0.06) {
        const gx = cx + Math.cos(ang) * r;
        const gy = cy + Math.sin(ang) * r;
        // Blend purple and cyan
        const blend = ring / 3;
        const rv = Math.floor(124 * (1 - blend) + 6 * blend);
        const gv = Math.floor(58 * (1 - blend) + 182 * blend);
        const bv = Math.floor(237 * (1 - blend) + 212 * blend);
        px.dot(gx | 0, gy | 0, rv, gv, bv, a);
      }
    }
  }

  // Particles
  for (let i = 0; i < particles.length; i++) {
    const p = particles[i];
    p.angle += p.speed;

    const pull = sealed ? 0.002 : 0.015 + (0.1 / p.dist);
    p.dist -= pull;

    if (p.dist < radius + 1) {
      particles[i] = _bhNewParticle();
      continue;
    }

    const x = cx + Math.cos(p.angle) * p.dist;
    const y = cy + Math.sin(p.angle) * p.dist * 0.3;

    const dx = x - cx, dy = y - cy;
    if (dx * dx + dy * dy < radius * radius) continue;

    p.trail.push({ x, y });
    if (p.trail.length > p.trailMax) p.trail.shift();

    let alpha = p.brightness;
    if (sealed) alpha *= 0.1;

    const rv = p.hue === 'v' ? 124 : 6;
    const gv = p.hue === 'v' ? 58 : 182;
    const bv = p.hue === 'v' ? 237 : 212;

    // Trail
    for (let t = 0; t < p.trail.length; t++) {
      const ta = alpha * (t / p.trail.length) * 0.35;
      px.dot(p.trail[t].x | 0, p.trail[t].y | 0, rv, gv, bv, ta);
    }

    // Particle
    px.dot(x | 0, y | 0, rv, gv, bv, alpha);
  }

  // Photon ring when unsealed, dots in a circle
  if (!sealed) {
    for (let ang = 0; ang < Math.PI * 2; ang += 0.1) {
      const rx = cx + Math.cos(ang) * (radius + 1);
      const ry = cy + Math.sin(ang) * (radius + 1);
      px.dot(rx | 0, ry | 0, 124, 58, 237, 0.3);
    }
  }

  // Relativistic jets when unsealed, tight collimated beams from poles
  if (!sealed) {
    // Static beam core, continuous bright line
    for (let dy = -70; dy < -radius - 1; dy++) {
      const dist = Math.abs(dy);
      const fade = Math.max(0, 1 - dist / 75);
      const spread = fade * 0.8;
      // Core line (bright)
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.15);
      // Slight glow around core
      px.dot(cx - 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
      px.dot(cx + 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
    }
    for (let dy = radius + 2; dy < 150; dy++) {
      const dist = dy;
      const fade = Math.max(0, 1 - dist / 75);
      const spread = fade * 0.8;
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.15);
      px.dot(cx - 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
      px.dot(cx + 1, cy + dy, 124, 58, 237, fade * 0.06 * spread);
    }

    // Moving particles along the beam
    for (let i = 0; i < BH.jets.length; i++) {
      const j = BH.jets[i];
      j.y += j.vy;
      j.life -= 0.015;

      if (j.life <= 0 || j.y < 2 || j.y > 158) {
        BH.jets[i] = _bhNewJet(cx, cy, radius);
        continue;
      }

      const a = j.life * j.brightness;
      const dist = Math.abs(j.y - cy);
      const blend = Math.min(1, dist / 60);
      // White-blue core → cyan at distance
      const rv = Math.floor(200 * (1 - blend) + 6 * blend);
      const gv = Math.floor(200 * (1 - blend) + 182 * blend);
      const bv = Math.floor(255 * (1 - blend) + 212 * blend);
      px.dot(j.x | 0, j.y | 0, rv, gv, bv, a * 0.8);
    }
  }
}

/* ===== MINI BLACK HOLE (collapsed sidebar) ===== */

const MINI = {
  px: null,
  particles: [],
  jets: [],
};

function miniBhInit(canvasId) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  el.width = 36;
  el.height = 36;
  MINI.px = new PixelArray(el, { pixelSize: 1 });
  MINI.particles = [];

  for (let i = 0; i < 120; i++) {
    const dist = 3 + Math.random() * 18;
    MINI.particles.push({
      angle: Math.random() * Math.PI * 2,
      dist,
      baseDist: dist,
      speed: (0.01 + Math.random() * 0.03) / (dist * 0.08),
      brightness: 0.4 + Math.random() * 0.6,
      hue: Math.random() > 0.45 ? 'v' : 'c',
    });
  }

  MINI.jets = [];
  for (let i = 0; i < 16; i++) {
    MINI.jets.push(_bhNewJet(18, 18, 3));
  }

  MINI.px.run(() => { _miniFrame(); });
}

function _miniFrame() {
  const px = MINI.px;
  const sealed = BH.sealed;
  const cx = 18, cy = 18, r = 3;

  px.fade(5, 5, 8, 0.08);

  // Event horizon, solid black core
  for (let dy = -r; dy <= r; dy++) {
    for (let dx = -r; dx <= r; dx++) {
      if (dx * dx + dy * dy <= r * r) {
        px.dot(cx + dx, cy + dy, 2, 2, 4);
      }
    }
  }

  // Photon ring, bright edge around the eye
  for (let ang = 0; ang < Math.PI * 2; ang += 0.12) {
    px.dot(
      (cx + Math.cos(ang) * (r + 1)) | 0,
      (cy + Math.sin(ang) * (r + 1)) | 0,
      124, 58, 237, sealed ? 0.15 : 0.35);
  }

  // Glow rings when unsealed
  if (!sealed) {
    for (let ring = 0; ring < 2; ring++) {
      const gr = r + 3 + ring * 4;
      const a = 0.08 - ring * 0.03;
      for (let ang = 0; ang < Math.PI * 2; ang += 0.15) {
        px.dot(
          (cx + Math.cos(ang) * gr) | 0,
          (cy + Math.sin(ang) * gr) | 0,
          124, 58, 237, a);
      }
    }
  }

  // Particles, draw BEFORE event horizon so core stays on top
  for (let i = 0; i < MINI.particles.length; i++) {
    const p = MINI.particles[i];
    p.angle += p.speed * 0.8;
    const pull = sealed ? 0.002 : 0.012 + (0.03 / p.dist);
    p.dist -= pull;

    if (p.dist < r + 2) {
      p.dist = p.baseDist;
      p.angle = Math.random() * Math.PI * 2;
      continue;
    }

    const x = cx + Math.cos(p.angle) * p.dist;
    const yCompress = 0.35 + 0.1 * (1 - p.dist / 18);
    const y = cy + Math.sin(p.angle) * p.dist * yCompress;

    // Skip if inside visual core area
    const dx2 = x - cx, dy2 = y - cy;
    if (dx2 * dx2 + dy2 * dy2 < (r + 1) * (r + 1)) continue;

    let alpha = p.brightness;
    if (sealed) alpha *= 0.12;
    // Fade eccentric particles smoothly
    if (p.dist > 14) alpha *= Math.max(0, 1 - (p.dist - 14) / 6);

    const rv = p.hue === 'v' ? 124 : 6;
    const gv = p.hue === 'v' ? 58 : 182;
    const bv = p.hue === 'v' ? 237 : 212;

    px.dot(x | 0, y | 0, rv, gv, bv, alpha);
  }

  // Redraw event horizon ON TOP of particles
  for (let dy2 = -r; dy2 <= r; dy2++) {
    for (let dx2 = -r; dx2 <= r; dx2++) {
      if (dx2 * dx2 + dy2 * dy2 <= r * r) {
        px.dot(cx + dx2, cy + dy2, 2, 2, 4);
      }
    }
  }

  // Photon ring on top
  for (let ang = 0; ang < Math.PI * 2; ang += 0.1) {
    px.dot(
      (cx + Math.cos(ang) * (r + 1)) | 0,
      (cy + Math.sin(ang) * (r + 1)) | 0,
      124, 58, 237, sealed ? 0.2 : 0.4);
  }

  // Relativistic jets when unsealed
  if (!sealed) {
    // Static beam core, shorter jets
    for (let dy = -12; dy < -r - 1; dy++) {
      const fade = Math.max(0, 1 - Math.abs(dy) / 14);
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.10);
    }
    for (let dy = r + 2; dy < 30; dy++) {
      const fade = Math.max(0, 1 - dy / 14);
      px.dot(cx, cy + dy, 180, 180, 255, fade * 0.10);
    }

    // Moving particles along the beam, single pixel wide
    for (let i = 0; i < MINI.jets.length; i++) {
      const j = MINI.jets[i];
      j.y += j.vy * 0.5;
      j.life -= 0.025;

      if (j.life <= 0 || j.y < 0 || j.y > 36) {
        MINI.jets[i] = _bhNewJet(cx, cy, r);
        continue;
      }

      const a = j.life * j.brightness;
      const dist = Math.abs(j.y - cy);
      const blend = Math.min(1, dist / 16);
      const rv = Math.floor(200 * (1 - blend) + 6 * blend);
      const gv = Math.floor(200 * (1 - blend) + 182 * blend);
      const bv = Math.floor(255 * (1 - blend) + 212 * blend);
      px.dot(cx, j.y | 0, rv, gv, bv, a * 0.5);
    }
  }
}

/* ===== KEY ICON (collapsed sidebar) ===== */

const KEY = {
  px: null,
  orbitAngle: 0,
};

function keyInit(canvasId) {
  const el = document.getElementById(canvasId);
  if (!el) return;
  // 2x internal resolution for smoother rendering on small canvas
  el.width = 72;
  el.height = 72;
  KEY.px = new PixelArray(el, { pixelSize: 1 });

  KEY.px.run(() => { _keyFrame(); });
}

function _keyFrame() {
  const px = KEY.px;
  const sealed = BH.sealed;
  const cx = 36, cy = 36;

  px.clear();

  const cr = sealed ? 239 : 16;
  const cg = sealed ? 68 : 185;
  const cb = sealed ? 68 : 129;

  // Background circle, soft fill, larger to meet halo
  const bgR = 33;
  for (let dy = -bgR; dy <= bgR; dy++) {
    for (let dx = -bgR; dx <= bgR; dx++) {
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d <= bgR) {
        const edge = Math.max(0, 1 - (bgR - d) / 2);
        px.dot(cx + dx, cy + dy, cr, cg, cb, 0.08 + edge * 0.3);
      }
    }
  }

  // Key, head (circle outline, anti-aliased)
  const kx = cx - 6, ky = cy - 6, kr = 9;
  for (let dy = -kr - 1; dy <= kr + 1; dy++) {
    for (let dx = -kr - 1; dx <= kr + 1; dx++) {
      const d = Math.sqrt(dx * dx + dy * dy);
      const dist = Math.abs(d - kr);
      if (dist < 1.2) {
        px.dot(kx + dx, ky + dy, cr, cg, cb, Math.max(0, 1 - dist / 1.2));
      }
    }
  }

  // Key, shaft (anti-aliased diagonal line)
  for (let t = 0; t <= 14; t += 0.5) {
    const sx = cx + t, sy = cy + t;
    for (let dy = -1; dy <= 1; dy++) {
      for (let dx = -1; dx <= 1; dx++) {
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < 1.2) {
          px.dot((sx + dx) | 0, (sy + dy) | 0, cr, cg, cb, Math.max(0, 1 - d / 1.2) * 0.9);
        }
      }
    }
  }

  // Key, teeth (smooth short lines)
  const teeth = [
    [[8, 10], [8, 14]],
    [[12, 14], [12, 18]],
  ];
  for (const [from, to] of teeth) {
    const steps = 8;
    for (let i = 0; i <= steps; i++) {
      const tx = cx + from[0] + (to[0] - from[0]) * i / steps;
      const ty = cy + from[1] + (to[1] - from[1]) * i / steps;
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 1.0) {
            px.dot((tx + dx) | 0, (ty + dy) | 0, cr, cg, cb, Math.max(0, 1 - d) * 0.85);
          }
        }
      }
    }
  }

  KEY.orbitAngle += 0.05;
  const orbR = 32;

  if (sealed) {
    // Sealed: 2 pixels at 180° with trails
    for (let dot = 0; dot < 2; dot++) {
      const offset = dot * Math.PI;
      for (let i = 0; i < 5; i++) {
        const a = KEY.orbitAngle + offset - i * 0.12;
        const ox = cx + Math.cos(a) * orbR;
        const oy = cy + Math.sin(a) * orbR;
        const alpha = 1 - i * 0.2;
        for (let dy = -1; dy <= 1; dy++) {
          for (let dx = -1; dx <= 1; dx++) {
            const d = Math.sqrt(dx * dx + dy * dy);
            if (d < 1.2) {
              px.dot((ox + dx) | 0, (oy + dy) | 0, 255, 255, 255, alpha * Math.max(0, 1 - d / 1.2));
            }
          }
        }
      }
    }
  } else {
    // Unsealed: thick solid ring + outer glow
    for (let ang = 0; ang < Math.PI * 2; ang += 0.05) {
      const cos = Math.cos(ang), sin = Math.sin(ang);
      // Main ring, 3px thick solid white
      for (let t = -1; t <= 1; t += 0.5) {
        const rx = cx + cos * (orbR + t);
        const ry = cy + sin * (orbR + t);
        px.dot(rx | 0, ry | 0, 255, 255, 255, 0.25);
      }
      // Outer glow, 4px fade out
      for (let g = 1; g <= 4; g++) {
        const rx = cx + cos * (orbR + 1 + g);
        const ry = cy + sin * (orbR + 1 + g);
        px.dot(rx | 0, ry | 0, 255, 255, 255, 0.18 - g * 0.04);
      }
    }
  }
}

// Expose entry points used by the SPA renderer and delegated actions.
window.bhInit = bhInit;
window.bhSetState = bhSetState;
window.miniBhInit = miniBhInit;
window.keyInit = keyInit;
