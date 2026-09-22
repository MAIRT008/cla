import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

function toRelativePath(value) {
  return String(value).replaceAll('\\', '/').replace(/^\.\//, '');
}

export class FixtureAuditStore {
  constructor(root) {
    this.root = path.resolve(root);
  }

  resolve(relativePath) {
    const normalized = toRelativePath(relativePath);
    if (!normalized || path.isAbsolute(normalized) || normalized.split('/').includes('..')) {
      throw new Error(`fixture path out of scope: ${relativePath}`);
    }
    const resolved = path.resolve(this.root, normalized);
    if (resolved !== this.root && !resolved.startsWith(`${this.root}${path.sep}`)) {
      throw new Error(`fixture path out of scope: ${relativePath}`);
    }
    return resolved;
  }

  async exists(relativePath) {
    try {
      await fs.access(this.resolve(relativePath));
      return true;
    } catch {
      return false;
    }
  }

  async readBytes(relativePath) {
    return new Uint8Array(await fs.readFile(this.resolve(relativePath)));
  }

  async readText(relativePath) {
    return fs.readFile(this.resolve(relativePath), 'utf8');
  }

  async writeBytes(relativePath, bytes, {overwrite = false} = {}) {
    const target = this.resolve(relativePath);
    await fs.mkdir(path.dirname(target), {recursive: true});
    await fs.writeFile(target, bytes, overwrite ? undefined : {flag: 'wx'});
  }

  async writeText(relativePath, text, options) {
    await this.writeBytes(relativePath, new TextEncoder().encode(text), options);
  }

  async listFiles(relativeRoot) {
    const root = this.resolve(relativeRoot);
    const found = [];
    const visit = async (directory) => {
      let entries;
      try { entries = await fs.readdir(directory, {withFileTypes: true}); } catch (error) {
        if (error.code === 'ENOENT') return;
        throw error;
      }
      for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) await visit(absolute);
        else if (entry.isFile()) {
          const relative = toRelativePath(path.relative(this.root, absolute));
          found.push({path: relative, bytes: new Uint8Array(await fs.readFile(absolute))});
        }
      }
    };
    await visit(root);
    return found;
  }

  /** 只列路径，不读内容；归档索引与回放按需再读字节。 */
  async listPaths(relativeRoot) {
    const root = this.resolve(relativeRoot);
    const found = [];
    const visit = async (directory) => {
      let entries;
      try { entries = await fs.readdir(directory, {withFileTypes: true}); } catch (error) {
        if (error.code === 'ENOENT') return;
        throw error;
      }
      for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) await visit(absolute);
        else if (entry.isFile()) found.push({path: toRelativePath(path.relative(this.root, absolute))});
      }
    };
    await visit(root);
    return found;
  }

  async sha256(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
  }
}
