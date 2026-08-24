-- CreateEnum
CREATE TYPE "SecretState" AS ENUM ('ACTIVE', 'VIEWED', 'EXPIRED', 'REVOKED', 'BURNED', 'DELETED');

-- CreateTable
CREATE TABLE "Secret" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "ownerTokenHash" TEXT NOT NULL,
    "ciphertext" TEXT,
    "iv" TEXT,
    "encryptedBytes" BYTEA,
    "fileIv" TEXT,
    "metaIv" TEXT,
    "encryptedMetadata" TEXT,
    "encryptedAnalysis" TEXT,
    "analysisIv" TEXT,
    "checksum" TEXT NOT NULL,
    "healEvents" INTEGER NOT NULL DEFAULT 0,
    "state" "SecretState" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Secret_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecretBackup" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "ciphertext" TEXT,
    "iv" TEXT,
    "encryptedBytes" BYTEA,
    "fileIv" TEXT,
    "metaIv" TEXT,
    "encryptedMetadata" TEXT,
    "encryptedAnalysis" TEXT,
    "analysisIv" TEXT,
    "checksum" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SecretBackup_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Policy" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "maxViews" INTEGER,
    "burnAfterReading" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Viewer" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "viewerLabel" TEXT NOT NULL,
    "wrappedKey" TEXT NOT NULL,
    "kdfSalt" TEXT NOT NULL,
    "wrapIv" TEXT NOT NULL,
    "kdfParams" JSONB NOT NULL,
    "hasViewed" BOOLEAN NOT NULL DEFAULT false,
    "viewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Viewer_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AccessLog" (
    "id" TEXT NOT NULL,
    "secretId" TEXT NOT NULL,
    "accessedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "success" BOOLEAN NOT NULL,
    "viewerLabel" TEXT,

    CONSTRAINT "AccessLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Secret_secretId_key" ON "Secret"("secretId");

-- CreateIndex
CREATE UNIQUE INDEX "SecretBackup_secretId_key" ON "SecretBackup"("secretId");

-- CreateIndex
CREATE UNIQUE INDEX "Policy_secretId_key" ON "Policy"("secretId");

-- CreateIndex
CREATE UNIQUE INDEX "Viewer_secretId_viewerLabel_key" ON "Viewer"("secretId", "viewerLabel");

-- AddForeignKey
ALTER TABLE "SecretBackup" ADD CONSTRAINT "SecretBackup_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Policy" ADD CONSTRAINT "Policy_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Viewer" ADD CONSTRAINT "Viewer_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AccessLog" ADD CONSTRAINT "AccessLog_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;
