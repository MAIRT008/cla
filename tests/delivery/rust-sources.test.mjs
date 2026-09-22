import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {checkRustSources, scanFile} from '../../tools/check-rust-sources.mjs';

/**
 * 本机没有 cargo/rustc，这组用例守住三类本机能判定的编译阻断。
 * T9 Round 5 就是 host.rs 的 Windows 路径写成普通字符串里的非法转义，整个 crate 编译不过。
 *
 * 用例里的「Rust 源码」一律用 String.raw 写：普通模板字符串会先被 JS 自己吃掉反斜杠，
 * 那样传进检查器的样本里根本没有反斜杠，测试就变成了自证。
 */

const BACKSLASH = '\\';

test('宿主源码里没有非法字符串转义、悬空模块或未声明的 crate', async () => {
  const {files, problems} = await checkRustSources();
  assert.ok(files >= 8, '宿主 crate 应该有一批源文件');
  assert.deepEqual(problems, [], JSON.stringify(problems, null, 2));
  // RC3 把 Mihomo 控制与 WFP 移进产品网络服务 crate，同一组静态检查也覆盖它。
  const service = await checkRustSources('apps/desktop-host/vendor/service-ipc/src', 'apps/desktop-host/vendor/service-ipc/Cargo.toml');
  assert.ok(service.files >= 20, '产品网络服务 crate 应该有一批源文件');
  assert.deepEqual(service.problems, [], JSON.stringify(service.problems, null, 2));
});

test('检查器认得 Windows 路径这一类非法转义', () => {
  const bad = scanFile(String.raw`fn a() { let p = "C:\Users\name\AppData"; }`, 'bad.rs');
  const unknown = bad.filter((item) => item.reason.includes('unknown escape'));
  assert.deepEqual(
    unknown.map((item) => item.escape).sort(),
    [`${BACKSLASH}A`, `${BACKSLASH}U`],
    JSON.stringify(bad),
  );
  assert.ok(bad.some((item) => item.reason.includes('windows path')), '整条路径也要被点名');

  // `\n` `\t` 在 Rust 里合法：这条路径能编译，但已经变成换行与制表符。
  const silent = scanFile(String.raw`fn a() { let p = "C:\new\temp"; }`, 'silent.rs');
  assert.deepEqual(silent.filter((item) => item.reason.includes('unknown escape')), [], '这里没有非法转义');
  assert.ok(silent.some((item) => item.reason.includes('windows path')), '合法转义拼出的错路径同样要报');

  const incomplete = scanFile(String.raw`fn a() { let s = "\xZZ"; }`, 'hex.rs');
  assert.ok(incomplete.some((item) => item.reason.includes('incomplete')), '半截的十六进制转义也要报');

  const malformed = scanFile(String.raw`fn a() { let s = "\u{zzzz}"; }`, 'unicode.rs');
  assert.ok(malformed.some((item) => item.reason.includes('malformed')), '写坏的 Unicode 转义也要报');
});

test('普通字符串的 \\x 只到 7F，超出范围要报', () => {
  for (const digits of ['80', 'FF', 'ff', 'A0']) {
    const found = scanFile(`fn a() { let s = "${BACKSLASH}x${digits}"; }`, 'hex-range.rs');
    assert.ok(
      found.some((item) => item.reason.includes('out of range hex escape')),
      `普通字符串里的 \\x${digits} 必须被点名：${JSON.stringify(found)}`,
    );
  }
  for (const digits of ['00', '41', '7f', '7F']) {
    const found = scanFile(`fn a() { let s = "${BACKSLASH}x${digits}"; }`, 'hex-ok.rs');
    assert.deepEqual(found, [], `\\x${digits} 在普通字符串里是合法的`);
  }
});

test('字节字符串的 \\x 到 FF 合法，但不接受 \\u{...}', () => {
  for (const digits of ['00', '7F', '80', 'FF']) {
    const found = scanFile(`fn a() { let s = b"${BACKSLASH}x${digits}"; }`, 'byte-hex.rs');
    assert.deepEqual(found, [], `字节字符串里的 \\x${digits} 是合法的`);
  }
  const unicodeInBytes = scanFile(`fn a() { let s = b"${BACKSLASH}u{41}"; }`, 'byte-unicode.rs');
  assert.ok(
    unicodeInBytes.some((item) => item.reason.includes('byte string literal does not accept')),
    JSON.stringify(unicodeInBytes),
  );
  const unknownInBytes = scanFile(`fn a() { let s = b"${BACKSLASH}q"; }`, 'byte-unknown.rs');
  assert.ok(unknownInBytes.some((item) => item.reason.includes('byte string literal')), '字节串的未知转义要点明字面量类型');
});

test('\\u{...} 必须是有效 Unicode 标量值', () => {
  const tooLarge = scanFile(`fn a() { let s = "${BACKSLASH}u{110000}"; }`, 'above-max.rs');
  assert.ok(tooLarge.some((item) => item.reason.includes('above the maximum scalar value')), JSON.stringify(tooLarge));

  for (const digits of ['D800', 'DFFF', 'dc00']) {
    const surrogate = scanFile(`fn a() { let s = "${BACKSLASH}u{${digits}}"; }`, 'surrogate.rs');
    assert.ok(
      surrogate.some((item) => item.reason.includes('surrogates')),
      `\\u{${digits}} 是代理码位，不是标量值：${JSON.stringify(surrogate)}`,
    );
  }

  for (const digits of ['0', '41', '4e2d', '10FFFF', '1_0000']) {
    const found = scanFile(`fn a() { let s = "${BACKSLASH}u{${digits}}"; }`, 'scalar-ok.rs');
    assert.deepEqual(found, [], `\\u{${digits}} 是有效标量值`);
  }

  const empty = scanFile(`fn a() { let s = "${BACKSLASH}u{}"; }`, 'empty.rs');
  assert.ok(empty.some((item) => item.reason.includes('malformed')), '空的 \\u{} 要报');
  const noBrace = scanFile(`fn a() { let s = "${BACKSLASH}u41"; }`, 'no-brace.rs');
  assert.ok(noBrace.some((item) => item.reason.includes('malformed')), '缺花括号的 \\u 要报');
});

test('检查器不把合法写法当问题', () => {
  assert.deepEqual(scanFile(String.raw`fn a() { let p = r"C:\Users\name"; }`, 'raw.rs'), [], '原始字符串里的反斜杠是字面量');
  assert.deepEqual(scanFile(String.raw`fn a() { let p = r#"C:\Users"#; }`, 'hashed.rs'), [], '带井号的原始字符串同样跳过');
  assert.deepEqual(scanFile(String.raw`fn a() { let p = "C:\\Users\\name"; }`, 'escaped.rs'), [], '转义过的反斜杠是合法的');
  assert.deepEqual(scanFile(String.raw`fn a() { let s = "line\n\t\"q\"\x41\u{4e2d}\0"; }`, 'ok.rs'), [], '常规转义都要认');
  assert.deepEqual(scanFile(`// 注释里的 C:${BACKSLASH}Users 不算\nfn a() {}`, 'comment.rs'), [], '行注释不参与检查');
  assert.deepEqual(scanFile(`/* 块注释里的 C:${BACKSLASH}Users 也不算 */\nfn a() {}`, 'block.rs'), [], '块注释不参与检查');
});

test('检查器认得悬空模块与未声明的 crate', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'steward-rust-'));
  const src = path.join(root, 'src');
  await mkdir(src, {recursive: true});
  await writeFile(
    path.join(src, 'lib.rs'),
    'pub mod present;\npub mod missing;\nuse ghost_crate::Thing;\nuse serde_json::Value;\nuse std::fs;\n',
    'utf8',
  );
  await writeFile(path.join(src, 'present.rs'), 'pub fn ok() {}\n', 'utf8');
  await writeFile(path.join(root, 'Cargo.toml'), '[dependencies]\nserde_json = "1"\n', 'utf8');

  const {problems} = await checkRustSources(src, path.join(root, 'Cargo.toml'));
  assert.ok(problems.some((item) => item.escape === 'mod missing'), '声明了却没有源文件的模块要报');
  assert.ok(!problems.some((item) => item.escape === 'mod present'), '有源文件的模块不报');
  assert.ok(problems.some((item) => item.escape === 'use ghost_crate::'), '没在 Cargo.toml 里的 crate 要报');
  assert.ok(!problems.some((item) => item.escape === 'use serde_json::'), '已声明的 crate 不报');
  assert.ok(!problems.some((item) => item.escape === 'use std::'), 'std 不需要声明');
});

test('宿主 crate 声明了确认窗口与数据库这两个必需依赖', async () => {
  const {problems} = await checkRustSources();
  assert.equal(problems.length, 0);
  const manifest = await import('node:fs/promises').then((fs) => fs.readFile(
    path.resolve('apps/desktop-host/src-tauri/Cargo.toml'),
    'utf8',
  ));
  assert.ok(manifest.includes('tauri-plugin-dialog'), 'Tauri v2 的对话框是独立插件');
  assert.ok(manifest.includes('rusqlite'), '第三方数据库能力组需要 SQLite');
});
