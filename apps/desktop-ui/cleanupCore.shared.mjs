export const PROTECTED_ROOT_KEYS = Object.freeze([
  'identity',
  'projectConfig',
  'memory',
  'records',
  'projects',
]);

export const ALLOWED_CLEANUP_PATH_PATTERNS = Object.freeze([
  Object.freeze([
    {type: 'key', key: 'thirdParty'},
    {type: 'key', key: '*'},
    {type: 'key', key: 'apiKey'},
  ]),
  Object.freeze([
    {type: 'key', key: 'thirdParty'},
    {type: 'key', key: '*'},
    {type: 'key', key: 'refreshToken'},
  ]),
  Object.freeze([
    {type: 'key', key: 'thirdParty'},
    {type: 'key', key: 'apiKey'},
  ]),
  Object.freeze([
    {type: 'key', key: 'thirdParty'},
    {type: 'key', key: 'refreshToken'},
  ]),
  Object.freeze([
    {type: 'key', key: 'projects'},
    {type: 'index', index: -1},
    {type: 'key', key: 'thirdParty'},
    {type: 'key', key: 'apiKey'},
  ]),
]);

function tokenMatchesPattern(patternToken, actualToken) {
  if (patternToken.type === 'index') {
    return actualToken.type === 'index' && patternToken.index === actualToken.index;
  }

  return (
    actualToken.type === 'key' &&
    (patternToken.key === '*' || patternToken.key === actualToken.key)
  );
}

function isAllowedCleanupPathTokens(tokens) {
  return ALLOWED_CLEANUP_PATH_PATTERNS.some((pattern) => {
    if (pattern.length !== tokens.length) {
      return false;
    }

    return pattern.every((patternToken, index) =>
      tokenMatchesPattern(patternToken, tokens[index]),
    );
  });
}

export function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
  }

  return Object.keys(value)
    .sort()
    .reduce((acc, key) => {
      acc[key] = canonicalize(value[key]);
      return acc;
    }, {});
}

export function parseFieldPath(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    throw new Error(`path must be a non-empty string: ${String(rawPath)}`);
  }

  const tokens = [];
  const pattern = /([^.[\]\s]+)|(\[(\*|\d*)\])/g;
  for (const match of rawPath.matchAll(pattern)) {
    if (match[1] !== undefined) {
      tokens.push({type: 'key', key: match[1]});
      continue;
    }

    if (match[3] === undefined) {
      throw new Error(`invalid path token in ${rawPath}`);
    }

    const indexToken = match[3];
    if (!indexToken || indexToken === '*') {
      tokens.push({type: 'index', index: -1});
    } else {
      tokens.push({type: 'index', index: Number.parseInt(indexToken, 10)});
    }
  }

  if (tokens.length === 0) {
    throw new Error(`invalid path token in ${rawPath}`);
  }

  return tokens;
}

export function removeByPath(root, tokens, index = 0) {
  if (root === null || root === undefined) {
    return false;
  }

  if (index >= tokens.length) {
    return false;
  }

  const token = tokens[index];
  const isLast = index === tokens.length - 1;

  if (token.type === 'key') {
    if (Array.isArray(root) || typeof root !== 'object') {
      return false;
    }

    if (!(token.key in root)) {
      return false;
    }

    if (isLast) {
      if (Object.prototype.hasOwnProperty.call(root, token.key)) {
        delete root[token.key];
        return true;
      }
      return false;
    }

    return removeByPath(root[token.key], tokens, index + 1);
  }

  if (token.type === 'index') {
    if (!Array.isArray(root)) {
      return false;
    }

    if (token.index === -1) {
      return root.reduce(
        (acc, item) => removeByPath(item, tokens, index + 1) || acc,
        false,
      );
    }

    if (token.index < 0 || token.index >= root.length) {
      return false;
    }

    if (isLast) {
      root.splice(token.index, 1);
      return true;
    }

    return removeByPath(root[token.index], tokens, index + 1);
  }

  return false;
}

function stripProtected(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return value;
  }

  const projected = structuredClone(value);

  for (const allowedPath of ALLOWED_CLEANUP_PATH_PATTERNS) {
    removeByPath(projected, allowedPath);
  }

  return Object.keys(value)
    .filter((key) => PROTECTED_ROOT_KEYS.includes(key))
    .reduce((acc, key) => {
      const projectedValue = projected[key];
      acc[key] = canonicalize(projectedValue);
      return acc;
    }, {});
}

export function isProtectedUnchanged(before, after) {
  return JSON.stringify(stripProtected(before)) === JSON.stringify(stripProtected(after));
}

export function applyCleanupToDocument(document, approvedRemovals, requestedRemovals) {
  if (!Array.isArray(approvedRemovals) || approvedRemovals.length === 0) {
    throw new Error('approvedRemovals must be a non-empty array');
  }

  if (!Array.isArray(requestedRemovals) || requestedRemovals.length === 0) {
    throw new Error('requestedRemovals must be a non-empty array');
  }

  const unknown = requestedRemovals.filter((path) => !approvedRemovals.includes(path));
  if (unknown.length > 0) {
    throw new Error(`requested path not approved: ${unknown.join(', ')}`);
  }

  const parsed = requestedRemovals.map((path) => ({path, tokens: parseFieldPath(path)}));
  const blocked = parsed.filter((entry) => !isAllowedCleanupPathTokens(entry.tokens));
  if (blocked.length > 0) {
    throw new Error(`requested path not supported: ${blocked.map((entry) => entry.path).join(', ')}`);
  }

  const before = structuredClone(document);
  const after = structuredClone(document);
  const removed = [];
  const missingOrNoChange = [];

  for (const entry of parsed) {
    const beforeSnapshot = JSON.stringify(after);
    const changed = removeByPath(after, entry.tokens);
    const afterSnapshot = JSON.stringify(after);

    if (changed) {
      removed.push(entry.path);
      if (beforeSnapshot !== afterSnapshot) {
        continue;
      }
    }
    missingOrNoChange.push(entry.path);
  }

  return {
    before,
    after,
    removed,
    missingOrNoChange,
    changed: removed.length > 0,
  };
}

export function signaturesForFields(fields) {
  return JSON.stringify([...fields].sort());
}

export function deterministicHash(value) {
  const text = JSON.stringify(canonicalize(value));
  let hash = 0;
  for (let i = 0; i < text.length; i += 1) {
    hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
  }
  return hash.toString(16).padStart(16, '0').repeat(4);
}
