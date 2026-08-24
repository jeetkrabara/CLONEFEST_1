require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const multer = require('multer');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
const prisma = new PrismaClient({ adapter });

const app = express();
app.use(cors());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }
});

const DELETION_GRACE_PERIOD_MINUTES = 5;

function computeTimeRemaining(expiresAt) {
  if (!expiresAt) return null;
  const diffMs = new Date(expiresAt).getTime() - Date.now();
  return diffMs > 0 ? Math.floor(diffMs / 1000) : 0;
}

function computeConfigSecurityScore(secret) {
  let score = 0;
  if (secret.policy?.expiresAt) score += 25;
  if (secret.policy?.burnAfterReading) {
    score += 25;
  } else if (secret.policy?.maxViews) {
    const strictness = Math.max(0, 25 - (secret.policy.maxViews - 1) * 3);
    score += Math.min(25, strictness);
  }
  if (secret.viewers && secret.viewers.length > 0) score += 25;
  if (secret.state === 'REVOKED') score += 25;
  return Math.min(100, score);
}

async function generateUniqueSecretId() {
  const MAX_ATTEMPTS = 5;
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    const candidate = crypto.randomBytes(16).toString('base64url');
    const existing = await prisma.secret.findUnique({ where: { secretId: candidate } });
    if (!existing) return candidate;
  }
  throw new Error('Failed to generate a unique secretId after multiple attempts');
}

function validateViewers(viewers) {
  if (!Array.isArray(viewers) || viewers.length === 0) {
    throw { statusCode: 400, message: 'at least one viewer is required - every secret needs a password per viewer' };
  }
  for (const v of viewers) {
    if (!v.viewerLabel || !v.wrappedKey || !v.kdfSalt || !v.wrapIv || !v.kdfParams) {
      throw { statusCode: 400, message: 'each viewer requires viewerLabel, wrappedKey, kdfSalt, wrapIv, and kdfParams' };
    }
  }
}

function computeChecksum({ ciphertext, iv, encryptedBytes, fileIv, metaIv, encryptedMetadata, encryptedAnalysis, analysisIv }) {
  const hash = crypto.createHash('sha256');
  hash.update(ciphertext || '');
  hash.update(iv || '');
  if (encryptedBytes) hash.update(encryptedBytes);
  hash.update(fileIv || '');
  hash.update(metaIv || '');
  hash.update(encryptedMetadata || '');
  hash.update(encryptedAnalysis || '');
  hash.update(analysisIv || '');
  return hash.digest('hex');
}

async function createSecretRecord(fields) {
  const {
    ciphertext, iv, encryptedBytes, fileIv, metaIv, encryptedMetadata,
    encryptedAnalysis, analysisIv, viewers, maxViews, expiresAt
  } = fields;

  validateViewers(viewers);

  const secretId = await generateUniqueSecretId();
  const ownerToken = crypto.randomBytes(24).toString('hex');
  const ownerTokenHash = await bcrypt.hash(ownerToken, 10);

  const contentFields = { ciphertext, iv, encryptedBytes, fileIv, metaIv, encryptedMetadata, encryptedAnalysis, analysisIv };
  const checksum = computeChecksum(contentFields);

  const secret = await prisma.secret.create({
    data: {
      secretId,
      ownerTokenHash,
      ciphertext: ciphertext || null,
      iv: iv || null,
      encryptedBytes: encryptedBytes || null,
      fileIv: fileIv || null,
      metaIv: metaIv || null,
      encryptedMetadata: encryptedMetadata || null,
      encryptedAnalysis: encryptedAnalysis || null,
      analysisIv: analysisIv || null,
      checksum,
      policy: {
        create: {
          expiresAt: expiresAt ? new Date(expiresAt) : null,
          maxViews: maxViews ? parseInt(maxViews, 10) : null,
          burnAfterReading: false
        }
      },
      viewers: {
        create: viewers.map(v => ({
          viewerLabel: v.viewerLabel,
          wrappedKey: v.wrappedKey,
          kdfSalt: v.kdfSalt,
          wrapIv: v.wrapIv,
          kdfParams: v.kdfParams
        }))
      },
      backup: {
        create: {
          ciphertext: ciphertext || null,
          iv: iv || null,
          encryptedBytes: encryptedBytes || null,
          fileIv: fileIv || null,
          metaIv: metaIv || null,
          encryptedMetadata: encryptedMetadata || null,
          encryptedAnalysis: encryptedAnalysis || null,
          analysisIv: analysisIv || null,
          checksum
        }
      }
    }
  });

  return { secretId: secret.secretId, ownerToken };
}

async function verifyAndHeal(secret) {
  const currentChecksum = computeChecksum({
    ciphertext: secret.ciphertext,
    iv: secret.iv,
    encryptedBytes: secret.encryptedBytes,
    fileIv: secret.fileIv,
    metaIv: secret.metaIv,
    encryptedMetadata: secret.encryptedMetadata,
    encryptedAnalysis: secret.encryptedAnalysis,
    analysisIv: secret.analysisIv
  });

  if (currentChecksum === secret.checksum) {
    return { healed: false, content: secret };
  }

  console.warn(`[integrity] Checksum mismatch for secret ${secret.secretId} - attempting heal from backup`);

  const backup = await prisma.secretBackup.findUnique({ where: { secretId: secret.id } });
  if (!backup) {
    throw { statusCode: 500, message: 'Data integrity check failed and no backup is available' };
  }

  const backupChecksum = computeChecksum({
    ciphertext: backup.ciphertext,
    iv: backup.iv,
    encryptedBytes: backup.encryptedBytes,
    fileIv: backup.fileIv,
    metaIv: backup.metaIv,
    encryptedMetadata: backup.encryptedMetadata,
    encryptedAnalysis: backup.encryptedAnalysis,
    analysisIv: backup.analysisIv
  });

  if (backupChecksum !== backup.checksum) {
    throw { statusCode: 500, message: 'Data integrity check failed and backup copy is also corrupted' };
  }

  const healed = await prisma.secret.update({
    where: { id: secret.id },
    data: {
      ciphertext: backup.ciphertext,
      iv: backup.iv,
      encryptedBytes: backup.encryptedBytes,
      fileIv: backup.fileIv,
      metaIv: backup.metaIv,
      encryptedMetadata: backup.encryptedMetadata,
      encryptedAnalysis: backup.encryptedAnalysis,
      analysisIv: backup.analysisIv,
      checksum: backup.checksum,
      healEvents: { increment: 1 }
    }
  });

  console.log(`[integrity] Secret ${secret.secretId} healed successfully from backup`);
  return { healed: true, content: healed };
}

app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ok', message: 'Server and database are connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.post('/api/secrets',
  express.json(),
  upload.single('encryptedBytes'),
  async (req, res) => {
    try {
      const isFileUpload = !!req.file;

      if (isFileUpload) {
        const {
          fileIv, metaIv, encryptedMetadata,
          encryptedAnalysis, analysisIv,
          viewers: viewersRaw, maxViews, expiresAt
        } = req.body;

        // Contract: encryptedAnalysis is TEXT SECRETS ONLY - reject if sent with a file
        if (encryptedAnalysis || analysisIv) {
          return res.status(400).json({
            error: 'encryptedAnalysis/analysisIv are not supported for file secrets - content analysis is text-only per the contract'
          });
        }

        if (!fileIv || !metaIv || !encryptedMetadata) {
          return res.status(400).json({ error: 'fileIv, metaIv, and encryptedMetadata are required for file secrets' });
        }

        let viewers;
        try {
          viewers = typeof viewersRaw === 'string' ? JSON.parse(viewersRaw) : viewersRaw;
        } catch {
          return res.status(400).json({ error: 'viewers must be valid JSON' });
        }

        const result = await createSecretRecord({
          encryptedBytes: req.file.buffer,
          fileIv,
          metaIv,
          encryptedMetadata,
          viewers,
          maxViews,
          expiresAt
        });

        return res.status(201).json(result);
      }

      const { ciphertext, iv, encryptedAnalysis, analysisIv, viewers, maxViews, expiresAt } = req.body;

      if (!ciphertext || !iv) {
        return res.status(400).json({ error: 'ciphertext and iv are required' });
      }

      const result = await createSecretRecord({
        ciphertext, iv, encryptedAnalysis, analysisIv, viewers, maxViews, expiresAt
      });
      res.status(201).json(result);

    } catch (err) {
      if (err.statusCode) return res.status(err.statusCode).json({ error: err.message });
      if (err.code === 'P2002') return res.status(400).json({ error: 'duplicate viewerLabel for this secret' });
      res.status(500).json({ error: err.message });
    }
  }
);

app.get('/api/secrets/:secretId', async (req, res) => {
  try {
    const { secretId } = req.params;
    const { viewer: viewerLabel } = req.query;

    if (!viewerLabel) {
      return res.status(400).json({ error: 'viewer query parameter is required' });
    }

    let secret = await prisma.secret.findUnique({
      where: { secretId },
      include: { policy: true, viewers: true, accessLogs: true }
    });

    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const viewerRecord = secret.viewers.find(v => v.viewerLabel === viewerLabel);
    if (!viewerRecord) {
      return res.status(404).json({ error: 'Viewer not found for this secret' });
    }

    if (['REVOKED', 'BURNED', 'DELETED', 'EXPIRED'].includes(secret.state)) {
      await prisma.accessLog.create({ data: { secretId: secret.id, success: false, viewerLabel } });
      return res.status(410).json({ error: `Secret is ${secret.state.toLowerCase()}` });
    }

    if (secret.policy?.expiresAt && new Date() > secret.policy.expiresAt) {
      await prisma.secret.update({ where: { id: secret.id }, data: { state: 'EXPIRED' } });
      await prisma.accessLog.create({ data: { secretId: secret.id, success: false, viewerLabel } });
      return res.status(410).json({ error: 'Secret has expired' });
    }

    const viewCount = secret.accessLogs.filter(log => log.success).length;
    if (secret.policy?.maxViews && viewCount >= secret.policy.maxViews) {
      await prisma.secret.update({ where: { id: secret.id }, data: { state: 'EXPIRED' } });
      await prisma.accessLog.create({ data: { secretId: secret.id, success: false, viewerLabel } });
      return res.status(410).json({ error: 'View limit exceeded' });
    }

    let healResult;
    try {
      healResult = await verifyAndHeal(secret);
    } catch (err) {
      await prisma.accessLog.create({ data: { secretId: secret.id, success: false, viewerLabel } });
      return res.status(err.statusCode || 500).json({ error: err.message });
    }
    secret = { ...secret, ...healResult.content };

    await prisma.accessLog.create({ data: { secretId: secret.id, success: true, viewerLabel } });
    await prisma.viewer.update({
      where: { id: viewerRecord.id },
      data: { hasViewed: true, viewedAt: new Date() }
    });

    let nextState = secret.state === 'ACTIVE' ? 'VIEWED' : secret.state;
    if (secret.policy?.burnAfterReading) {
      nextState = 'BURNED';
    }
    await prisma.secret.update({ where: { id: secret.id }, data: { state: nextState } });

    const wrapData = {
      wrappedKey: viewerRecord.wrappedKey,
      kdfSalt: viewerRecord.kdfSalt,
      wrapIv: viewerRecord.wrapIv
    };

    const responseBody = secret.encryptedBytes
      ? {
          encryptedBytes: Buffer.from(secret.encryptedBytes).toString('base64'),
          encryptedMetadata: secret.encryptedMetadata,
          fileIv: secret.fileIv,
          metaIv: secret.metaIv,
          wrapData
        }
      : {
          ciphertext: secret.ciphertext,
          iv: secret.iv,
          wrapData
        };

    // Per contract: encryptedAnalysis only ever present for text secrets
    if (secret.encryptedAnalysis && !secret.encryptedBytes) {
      responseBody.encryptedAnalysis = secret.encryptedAnalysis;
      responseBody.analysisIv = secret.analysisIv;
    }

    if (healResult.healed) {
      responseBody._healed = true;
    }

    res.status(200).json(responseBody);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/secrets/:secretId/status', async (req, res) => {
  try {
    const { secretId } = req.params;

    const secret = await prisma.secret.findUnique({
      where: { secretId },
      include: { policy: true, accessLogs: true, viewers: true }
    });

    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const viewCount = secret.accessLogs.filter(log => log.success).length;

    res.json({
      state: secret.state,
      type: secret.encryptedBytes ? 'file' : 'text',
      timeRemainingSeconds: computeTimeRemaining(secret.policy?.expiresAt),
      maxViews: secret.policy?.maxViews || null,
      viewsUsed: viewCount,
      viewerLabels: secret.viewers.map(v => v.viewerLabel),
      configSecurityScore: computeConfigSecurityScore(secret)
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/secrets/:secretId/integrity', async (req, res) => {
  try {
    const { secretId } = req.params;

    const secret = await prisma.secret.findUnique({ where: { secretId } });
    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const currentChecksum = computeChecksum({
      ciphertext: secret.ciphertext,
      iv: secret.iv,
      encryptedBytes: secret.encryptedBytes,
      fileIv: secret.fileIv,
      metaIv: secret.metaIv,
      encryptedMetadata: secret.encryptedMetadata,
      encryptedAnalysis: secret.encryptedAnalysis,
      analysisIv: secret.analysisIv
    });

    res.json({
      intact: currentChecksum === secret.checksum,
      healEvents: secret.healEvents
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/secrets/:secretId/stats', async (req, res) => {
  try {
    const { secretId } = req.params;

    const secret = await prisma.secret.findUnique({
      where: { secretId },
      include: { policy: true, accessLogs: true, viewers: true }
    });

    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const successfulLogs = secret.accessLogs.filter(log => log.success);
    const failedLogs = secret.accessLogs.filter(log => !log.success);

    const perViewer = secret.viewers.map(v => {
      const viewerLogs = successfulLogs.filter(log => log.viewerLabel === v.viewerLabel);
      return {
        viewerLabel: v.viewerLabel,
        hasViewed: v.hasViewed,
        viewCount: viewerLogs.length,
        firstAccessedAt: viewerLogs.length ? viewerLogs[0].accessedAt : null,
        lastAccessedAt: viewerLogs.length ? viewerLogs[viewerLogs.length - 1].accessedAt : null
      };
    });

    const timestamps = successfulLogs.map(log => log.accessedAt).sort((a, b) => a - b);

    res.json({
      secretId: secret.secretId,
      state: secret.state,
      type: secret.encryptedBytes ? 'file' : 'text',
      createdAt: secret.createdAt,
      totalSuccessfulViews: successfulLogs.length,
      totalFailedAttempts: failedLogs.length,
      maxViews: secret.policy?.maxViews || null,
      expiresAt: secret.policy?.expiresAt || null,
      burnAfterReading: secret.policy?.burnAfterReading || false,
      firstAccessedAt: timestamps.length ? timestamps[0] : null,
      lastAccessedAt: timestamps.length ? timestamps[timestamps.length - 1] : null,
      healEvents: secret.healEvents,
      configSecurityScore: computeConfigSecurityScore(secret),
      hasAnalysis: !!secret.encryptedAnalysis,
      perViewer
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/secrets/:secretId/revoke', express.json(), async (req, res) => {
  try {
    const { secretId } = req.params;
    const { ownerToken } = req.body;

    if (!ownerToken) {
      return res.status(400).json({ error: 'ownerToken is required' });
    }

    const secret = await prisma.secret.findUnique({ where: { secretId } });
    if (!secret) {
      return res.status(404).json({ error: 'Secret not found' });
    }

    const isValidOwner = await bcrypt.compare(ownerToken, secret.ownerTokenHash);
    if (!isValidOwner) {
      return res.status(403).json({ error: 'Invalid owner token' });
    }

    if (['REVOKED', 'BURNED', 'DELETED'].includes(secret.state)) {
      return res.status(410).json({ error: `Secret is already ${secret.state.toLowerCase()}` });
    }

    await prisma.secret.update({ where: { id: secret.id }, data: { state: 'REVOKED' } });
    res.json({ status: 'ok', message: 'Secret revoked successfully' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  next(err);
});

async function sweepExpiredSecrets() {
  try {
    const cutoff = new Date(Date.now() - DELETION_GRACE_PERIOD_MINUTES * 60 * 1000);
    const toDelete = await prisma.secret.findMany({
      where: { state: { in: ['EXPIRED', 'REVOKED', 'BURNED'] }, updatedAt: { lt: cutoff } }
    });

    if (toDelete.length === 0) {
      console.log(`[cleanup] No secrets to delete at ${new Date().toISOString()}`);
      return;
    }

    for (const secret of toDelete) {
      await prisma.secret.delete({ where: { id: secret.id } });
    }
    console.log(`[cleanup] Deleted ${toDelete.length} secret(s) at ${new Date().toISOString()}`);
  } catch (err) {
    console.error('[cleanup] Error during sweep:', err.message);
  }
}

cron.schedule('* * * * *', sweepExpiredSecrets);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SecureBin backend running on http://localhost:${PORT}`);
  console.log(`[cleanup] Background deletion job scheduled - grace period: ${DELETION_GRACE_PERIOD_MINUTES} min`);
});
