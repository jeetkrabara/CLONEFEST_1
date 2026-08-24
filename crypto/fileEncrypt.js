import { encryptData, decryptData } from './encrypt.js';

export async function encryptFile(file, key, iv, metaIv) {
  const fileBuf = await file.arrayBuffer();
  const encryptedBytes = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, fileBuf
  );

  const metadataJson = JSON.stringify({
    fileName: file.name,
    fileType: file.type,
    fileSize: file.size
  });
  const encryptedMetadata = await encryptData(metadataJson, key, metaIv);

  return { encryptedBytes, encryptedMetadata };
}

export async function decryptFile(encryptedBytes, encryptedMetadata, key, iv, metaIv) {
  const metadataJson = await decryptData(encryptedMetadata, key, metaIv);
  const { fileName, fileType } = JSON.parse(metadataJson);
  const decryptedBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, key, encryptedBytes
  );
  return new File([decryptedBuf], fileName, { type: fileType });
}