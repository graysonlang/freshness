import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// TODO: Add support for checking file timestamp prior to hashing.

export function computeUrlSafeBase64Digest(input, algorithm = 'sha1') {
  const hash = crypto.createHash(algorithm).update(input, 'utf8').digest('base64');
  return hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function computeFileHash(filePath, signal, algorithm = 'sha1') {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error(`Aborted: Skipping hash computation for ${filePath}`));
      return;
    }
    const hash = crypto.createHash(algorithm);
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => {
      if (signal?.aborted) {
        stream.destroy();
        reject(new Error(`Aborted: Skipping hash computation for ${filePath}`));
        return;
      }
      hash.update(chunk);
    });
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (error) => reject(`Error reading file ${filePath}: ${error.message}`));
  });
}

export async function computeFileHashes(filePaths, algorithm = 'sha1') {
  return new Map(await Promise.all(filePaths.map(async p => [p, await computeFileHash(p, algorithm)])));
}

function setsAreSame(s1, s2) { return s1.size === s2.size && [...s1].every((x) => s2.has(x)); }

export default class Freshness {
  #fileHashes = new Map();

  async check(filePathSet) {
    if (!setsAreSame(filePathSet, new Set(this.#fileHashes.keys()))) {
      return false;
    }
    const controller = new AbortController();
    const { signal } = controller;
    let fresh = true;
    const promises = [...filePathSet].map(async (filePath) => {
      if (!fresh) {
        return false;
      }
      try {
        const newHash = await computeFileHash(filePath, signal);
        if (!this.#fileHashes.has(filePath) || this.#fileHashes.get(filePath) !== newHash) {
          this.#fileHashes.set(filePath, newHash);
          fresh = false;
          controller.abort();
        }
      } catch (error) {
        if (signal.aborted) return;
        console.error(`Error computing hash for ${filePath}:`, error);
        controller.abort();
      }
    });
    await Promise.allSettled(promises);
    return fresh;
  }

  async update(filePathSet) {
    for (const key of [...this.#fileHashes.keys()].filter(k => !filePathSet.has(k))) {
      this.#fileHashes.delete(key);
    }
    try {
      const newHashes = await computeFileHashes([...filePathSet]);
      for (const [file, hash] of newHashes) {
        this.#fileHashes.set(file, hash);
      }
    } catch (error) {
      console.error('Error updating file hashes:', error);
    }
  }
}
