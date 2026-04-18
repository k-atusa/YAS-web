import fs from "node:fs/promises";
import path from "node:path";
import { FileModel } from "./models/File";

export async function cleanupOrphanedFiles() {
  const UPLOADS_DIR = path.join(__dirname, "../uploads");
  try {
    const files = await fs.readdir(UPLOADS_DIR);
    const dbFiles = await FileModel.find({}, { _id: 1, filePath: 1 }).lean();
    
    // Maps of valid file paths in DB
    const validPaths = new Set(
      dbFiles
        .filter((f: any) => f.filePath) // 이전 버전의 데이터(filePath가 없는 데이터) 필터링
        .map((f: any) => path.basename(f.filePath))
    );

    for (const file of files) {
      if (file.endsWith(".enc") && !validPaths.has(file)) {
        await fs.unlink(path.join(UPLOADS_DIR, file)).catch(() => {});
        console.log(`[Cleanup] Deleted orphaned file: ${file}`);
      }
    }
  } catch (error) {
    console.error("[Cleanup] Failed to cleanup orphaned files", error);
  }
}
