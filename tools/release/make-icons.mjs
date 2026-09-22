import {mkdirSync, writeFileSync} from 'node:fs';
import path from 'node:path';

/**
 * 产品自有图标：青绿圆角底、白色盾牌、盾内对勾。纯算法绘制，不取任何上游图像。
 *   node tools/release/make-icons.mjs [--out <目录>]   默认写到 apps/desktop-host/src-tauri/icons/
 * 输出逐字节可重现：PNG 用不压缩的 deflate 存储块（不依赖 zlib 版本），ICO 小尺寸用 32 位 BMP、256 用 PNG。
 */
const outIndex = process.argv.indexOf('--out');
const out = outIndex > 0 ? process.argv[outIndex + 1] : 'apps/desktop-host/src-tauri/icons';

const CRC_TABLE = Array.from({length: 256}, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (bytes) => {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

function inRoundedSquare(x, y, size, radius) {
  const cx = Math.min(Math.max(x, radius), size - radius);
  const cy = Math.min(Math.max(y, radius), size - radius);
  return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2;
}

function inShield(x, y) {
  if (y < 44 || y > 214) return false;
  const top = 44 + 12 * ((x - 128) / 70) ** 2;
  if (y < top) return false;
  const half = y <= 128 ? 70 : 70 * Math.sqrt(Math.max(0, 1 - ((y - 128) / 86) ** 2));
  return Math.abs(x - 128) <= half;
}

function nearSegment(x, y, [ax, ay], [bx, by], width) {
  const t = Math.max(0, Math.min(1, ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)));
  return (x - ax - t * (bx - ax)) ** 2 + (y - ay - t * (by - ay)) ** 2 <= (width / 2) ** 2;
}

/** 在 256 画布坐标上取一点的颜色 [r, g, b, a]。 */
function sample(x, y) {
  if (!inRoundedSquare(x, y, 256, 56)) return [0, 0, 0, 0];
  if (inShield(x, y)) {
    if (nearSegment(x, y, [92, 132], [118, 158], 18) || nearSegment(x, y, [118, 158], [166, 104], 18)) return [15, 118, 110, 255];
    return [255, 255, 255, 255];
  }
  const t = y / 256;
  return [Math.round(20 + (15 - 20) * t), Math.round(184 + (118 - 184) * t), Math.round(166 + (110 - 166) * t), 255];
}

/** 每像素 4×4 超采样抗锯齿，返回自上而下的 RGBA。 */
function render(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const scale = 256 / size;
  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      const sum = [0, 0, 0, 0];
      for (let sy = 0; sy < 4; sy += 1) {
        for (let sx = 0; sx < 4; sx += 1) {
          const [r, g, b, a] = sample((px + (sx + 0.5) / 4) * scale, (py + (sy + 0.5) / 4) * scale);
          sum[0] += r * a;
          sum[1] += g * a;
          sum[2] += b * a;
          sum[3] += a;
        }
      }
      const offset = (py * size + px) * 4;
      pixels[offset + 3] = Math.round(sum[3] / 16);
      for (let channel = 0; channel < 3; channel += 1) pixels[offset + channel] = sum[3] ? Math.round(sum[channel] / sum[3]) : 0;
    }
  }
  return pixels;
}

function chunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])), 0);
  return Buffer.concat([head, data, crc]);
}

function storedZlib(raw) {
  const parts = [Buffer.from([0x78, 0x01])];
  for (let offset = 0; offset < raw.length || offset === 0; offset += 65535) {
    const block = raw.subarray(offset, offset + 65535);
    const header = Buffer.alloc(5);
    header[0] = offset + 65535 >= raw.length ? 1 : 0;
    header.writeUInt16LE(block.length, 1);
    header.writeUInt16LE(block.length ^ 0xffff, 3);
    parts.push(header, block);
    if (header[0] === 1) break;
  }
  let a = 1;
  let b = 0;
  for (const byte of raw) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  const adler = Buffer.alloc(4);
  adler.writeUInt32BE(((b << 16) | a) >>> 0, 0);
  parts.push(adler);
  return Buffer.concat(parts);
}

function png(size) {
  const pixels = render(size);
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let row = 0; row < size; row += 1) pixels.copy(raw, row * (size * 4 + 1) + 1, row * size * 4, (row + 1) * size * 4);
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', header), chunk('IDAT', storedZlib(raw)), chunk('IEND', Buffer.alloc(0))]);
}

function bmp(size) {
  const pixels = render(size);
  const info = Buffer.alloc(40);
  info.writeUInt32LE(40, 0);
  info.writeInt32LE(size, 4);
  info.writeInt32LE(size * 2, 8);
  info.writeUInt16LE(1, 12);
  info.writeUInt16LE(32, 14);
  info.writeUInt32LE(size * size * 4, 20);
  const xor = Buffer.alloc(size * size * 4);
  for (let row = 0; row < size; row += 1) {
    for (let column = 0; column < size; column += 1) {
      const from = (row * size + column) * 4;
      const to = ((size - 1 - row) * size + column) * 4;
      xor[to] = pixels[from + 2];
      xor[to + 1] = pixels[from + 1];
      xor[to + 2] = pixels[from];
      xor[to + 3] = pixels[from + 3];
    }
  }
  const stride = Math.ceil(size / 32) * 4;
  return Buffer.concat([info, xor, Buffer.alloc(stride * size)]);
}

function ico(entries) {
  const header = Buffer.alloc(6 + 16 * entries.length);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(entries.length, 4);
  let offset = header.length;
  entries.forEach(({size, data}, index) => {
    const at = 6 + index * 16;
    header[at] = size >= 256 ? 0 : size;
    header[at + 1] = size >= 256 ? 0 : size;
    header.writeUInt16LE(1, at + 4);
    header.writeUInt16LE(32, at + 6);
    header.writeUInt32LE(data.length, at + 8);
    header.writeUInt32LE(offset, at + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...entries.map((entry) => entry.data)]);
}

mkdirSync(out, {recursive: true});
const large = png(256);
writeFileSync(path.join(out, 'icon.png'), large);
writeFileSync(path.join(out, 'icon.ico'), ico([16, 24, 32, 48, 64, 128].map((size) => ({size, data: bmp(size)})).concat({size: 256, data: large})));
console.log(`icons written to ${out}`);
