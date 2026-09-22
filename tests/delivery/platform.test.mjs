import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {domainToASCII} from 'node:url';
import test from 'node:test';
import {sha256Bytes, sha256Hex as pureSha256Hex} from '../../src/adapters/platform/sha256.mjs';
import {platformKind, randomHex, sha256Hex, timingSafeEqualHex, toAsciiDomain} from '../../src/adapters/platform/index.mjs';

test('平台 sha256 与 node:crypto 逐个字节一致', () => {
  const cases = [
    '',
    'a',
    'abc',
    'The quick brown fox jumps over the lazy dog',
    '受限账号资料与项目配置',
    'x'.repeat(55),
    'x'.repeat(56),
    'x'.repeat(63),
    'x'.repeat(64),
    'x'.repeat(65),
    'x'.repeat(1000),
  ];
  for (const value of cases) {
    assert.equal(pureSha256Hex(value), createHash('sha256').update(value).digest('hex'), `字符串 ${value.length} 字节不一致`);
  }
  for (let round = 0; round < 64; round += 1) {
    const bytes = randomBytes(round * 7 % 300);
    assert.equal(
      pureSha256Hex(new Uint8Array(bytes)),
      createHash('sha256').update(bytes).digest('hex'),
      `随机 ${bytes.length} 字节不一致`,
    );
  }
  assert.equal(sha256Bytes('abc').length, 32);
  assert.equal(pureSha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('平台层在 Node 下沿用内置实现，接口行为一致', () => {
  assert.equal(platformKind, 'node');
  assert.equal(sha256Hex('abc'), createHash('sha256').update('abc').digest('hex'));
  assert.equal(randomHex(16).length, 32);
  assert.notEqual(randomHex(16), randomHex(16));
  assert.equal(timingSafeEqualHex('abcd', 'abcd'), true);
  assert.equal(timingSafeEqualHex('abcd', 'abce'), false);
  assert.equal(timingSafeEqualHex('abcd', 'abc'), false, '长度不同直接判否，不抛错');
  assert.equal(toAsciiDomain('例子.测试'), domainToASCII('例子.测试'));
  assert.equal(toAsciiDomain('direct.example'), 'direct.example');
});
