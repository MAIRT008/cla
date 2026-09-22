import {existsSync} from 'node:fs';
import {readdir, readFile} from 'node:fs/promises';
import path from 'node:path';

/**
 * 本机没有 cargo/rustc，宿主 crate 的编译问题本来要等 T10 才暴露。
 * T9 Round 5 就是因为 Windows 路径里的 `\U` `\P` 被当成非法转义而整个 crate 编译不过。
 * 这里只做本机能可靠判定的三类静态检查，不冒充 cargo check：
 *   1. 普通字符串字面量的转义序列（规则取自 Rust 参考手册）；
 *   2. `pub mod X;` 是否有对应的源文件；
 *   3. 用到的外部 crate 是否在 Cargo.toml 里声明。
 * 类型、借用与宏展开仍然只能在 T10 的编译环境验证。
 */

/** Rust 2018 起可以直接用的 crate，不需要在 Cargo.toml 里声明。 */
const BUILTIN_CRATES = new Set(['std', 'core', 'alloc', 'crate', 'self', 'super']);

const SIMPLE = new Set(['n', 'r', 't', '\\', '0', "'", '"']);

export function scanFile(source, file) {
  const problems = [];
  let index = 0;
  let line = 1;

  const isIdentChar = (ch) => /[A-Za-z0-9_]/.test(ch);

  while (index < source.length) {
    const ch = source[index];
    if (ch === '\n') {
      line += 1;
      index += 1;
      continue;
    }

    // 行注释与块注释
    if (ch === '/' && source[index + 1] === '/') {
      while (index < source.length && source[index] !== '\n') index += 1;
      continue;
    }
    if (ch === '/' && source[index + 1] === '*') {
      index += 2;
      let depth = 1;
      while (index < source.length && depth > 0) {
        if (source[index] === '\n') line += 1;
        if (source[index] === '/' && source[index + 1] === '*') { depth += 1; index += 2; continue; }
        if (source[index] === '*' && source[index + 1] === '/') { depth -= 1; index += 2; continue; }
        index += 1;
      }
      continue;
    }

    // 原始字符串：r"..."、r#"..."#，里面的反斜杠是字面量
    if (ch === 'r' && !isIdentChar(source[index - 1] || ' ')) {
      let probe = index + 1;
      let hashes = 0;
      while (source[probe] === '#') { hashes += 1; probe += 1; }
      if (source[probe] === '"') {
        const terminator = `"${'#'.repeat(hashes)}`;
        const end = source.indexOf(terminator, probe + 1);
        const stop = end < 0 ? source.length : end + terminator.length;
        for (let scan = index; scan < stop; scan += 1) if (source[scan] === '\n') line += 1;
        index = stop;
        continue;
      }
    }

    // 字节串 b"..." 与普通字符串 "..."：两者的转义规则不同，不能共用一套判据。
    //   普通字符串：\x 只到 \x7F（ASCII_ESCAPE），\u{...} 必须是有效 Unicode 标量值；
    //   字节字符串：\x 可到 \xFF（BYTE_ESCAPE），但完全不接受 \u{...}。
    if (ch === '"' || (ch === 'b' && source[index + 1] === '"')) {
      const isByteString = ch === 'b';
      const kind = isByteString ? 'byte string' : 'normal string';
      const start = ch === '"' ? index : index + 1;
      const openedAt = line;
      const literalLine = line;
      let scan = start + 1;
      while (scan < source.length) {
        const current = source[scan];
        if (current === '\n') {
          line += 1;
          scan += 1;
          continue;
        }
        if (current === '\\') {
          const next = source[scan + 1];
          if (next === undefined) break;
          if (next === '\n') { line += 1; scan += 2; continue; }
          if (SIMPLE.has(next)) { scan += 2; continue; }
          if (next === 'x') {
            const digits = source.slice(scan + 2, scan + 4);
            if (!/^[0-9a-fA-F]{2}$/.test(digits)) {
              problems.push({file, line, escape: source.slice(scan, scan + 4), reason: 'incomplete \\x escape'});
            } else if (!isByteString && Number.parseInt(digits, 16) > 0x7f) {
              problems.push({
                file,
                line,
                escape: `\\x${digits}`,
                reason: 'out of range hex escape: a normal string literal only allows \\x00-\\x7F',
              });
            }
            scan += 4;
            continue;
          }
          if (next === 'u') {
            const escape = source.slice(scan, scan + 6);
            if (isByteString) {
              problems.push({file, line, escape, reason: 'a byte string literal does not accept \\u{...}'});
              const close = source.indexOf('}', scan + 3);
              scan = source[scan + 2] === '{' && close >= 0 ? close + 1 : scan + 2;
              continue;
            }
            if (source[scan + 2] !== '{') {
              problems.push({file, line, escape, reason: 'malformed \\u{...} escape'});
              scan += 2;
              continue;
            }
            const close = source.indexOf('}', scan + 3);
            const digits = close < 0 ? '' : source.slice(scan + 3, close);
            if (close < 0 || !/^[0-9a-fA-F_]{1,6}$/.test(digits) || !/[0-9a-fA-F]/.test(digits)) {
              problems.push({file, line, escape, reason: 'malformed \\u{...} escape'});
            } else {
              const value = Number.parseInt(digits.replaceAll('_', ''), 16);
              if (value > 0x10ffff) {
                problems.push({file, line, escape: `\\u{${digits}}`, reason: 'invalid unicode escape: above the maximum scalar value 10FFFF'});
              } else if (value >= 0xd800 && value <= 0xdfff) {
                problems.push({file, line, escape: `\\u{${digits}}`, reason: 'invalid unicode escape: D800-DFFF are surrogates, not scalar values'});
              }
            }
            scan = close < 0 ? scan + 3 : close + 1;
            continue;
          }
          problems.push({file, line, escape: `\\${next}`, reason: `unknown escape in a ${kind} literal`});
          scan += 2;
          continue;
        }
        if (current === '"') { scan += 1; break; }
        scan += 1;
      }
      if (scan >= source.length && openedAt === line) {
        problems.push({file, line, escape: '"', reason: 'unterminated string literal'});
      }
      // `\n` `\t` `\r` 在 Rust 里是合法转义，写进 Windows 路径能编译，但路径本身已经错了。
      // 例：普通字符串里的 "C:\new\temp" 会变成换行与制表符。
      const raw = source.slice(start, scan);
      if (/[A-Za-z]:\\(?!\\)/.test(raw)) {
        problems.push({
          file,
          line: literalLine,
          escape: raw.length > 48 ? `${raw.slice(0, 45)}...` : raw,
          reason: `windows path in a ${kind} literal; use a raw string or PathBuf::join`,
        });
      }
      index = scan;
      continue;
    }

    index += 1;
  }
  return problems;
}

/** `pub mod X;` / `mod X;` 必须能找到 X.rs 或 X/mod.rs。 */
async function checkModules(files) {
  const problems = [];
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    const directory = path.dirname(file);
    for (const match of source.matchAll(/^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;/gm)) {
      const name = match[1];
      const sibling = path.join(directory, `${name}.rs`);
      const folder = path.join(directory, name, 'mod.rs');
      const line = source.slice(0, match.index).split('\n').length;
      if (!existsSync(sibling) && !existsSync(folder)) {
        problems.push({file: path.relative(process.cwd(), file), line, escape: `mod ${name}`, reason: 'declared module has no source file'});
      }
    }
  }
  return problems;
}

/** 外部 crate 必须在 Cargo.toml 的依赖里出现。 */
async function checkCrates(files, manifestPath) {
  const problems = [];
  const manifest = existsSync(manifestPath) ? await readFile(manifestPath, 'utf8') : '';
  const declared = new Set(
    [...manifest.matchAll(/^\s*([A-Za-z0-9_-]+)\s*=/gm)].map((match) => match[1].replaceAll('-', '_')),
  );
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    const localModules = new Set(
      [...source.matchAll(/^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)/gm)].map((match) => match[1]),
    );
    for (const match of source.matchAll(/^\s*(?:pub\s+)?use\s+([a-z_][a-z0-9_]*)\s*::/gm)) {
      const name = match[1];
      if (BUILTIN_CRATES.has(name) || localModules.has(name) || declared.has(name)) continue;
      const line = source.slice(0, match.index).split('\n').length;
      problems.push({file: path.relative(process.cwd(), file), line, escape: `use ${name}::`, reason: 'crate is not declared in Cargo.toml'});
    }
  }
  return problems;
}

async function collect(directory) {
  const found = [];
  for (const entry of await readdir(directory, {withFileTypes: true})) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'target' || entry.name === 'node_modules') continue;
      found.push(...(await collect(full)));
    } else if (entry.name.endsWith('.rs')) {
      found.push(full);
    }
  }
  return found;
}

export async function checkRustSources(root = 'apps/desktop-host/src-tauri/src', manifest = 'apps/desktop-host/src-tauri/Cargo.toml') {
  const files = await collect(path.resolve(root));
  const problems = [];
  for (const file of files) {
    problems.push(...scanFile(await readFile(file, 'utf8'), path.relative(process.cwd(), file)));
  }
  problems.push(...(await checkModules(files)));
  problems.push(...(await checkCrates(files, path.resolve(manifest))));
  return {files: files.length, problems};
}

if (process.argv[1] && import.meta.url.endsWith(path.basename(process.argv[1]))) {
  const {files, problems} = await checkRustSources(process.argv[2]);
  for (const problem of problems) {
    console.error(`${problem.file}:${problem.line}  ${problem.escape}  ${problem.reason}`);
  }
  console.log(`${files} 个 Rust 源文件，${problems.length} 处静态问题`);
  process.exit(problems.length ? 1 : 0);
}
