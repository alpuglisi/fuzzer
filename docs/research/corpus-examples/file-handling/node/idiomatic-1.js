/*
 * Excerpt from Kelvi077/Ecommerce-Website-Template-FullStack, app.js:
 * multer storage/fileFilter config with filename sanitization and a
 * mimetype allowlist. See manifest.yaml for repo/commit/license
 * provenance. Trimmed to the upload-config lines; unrelated routes
 * omitted (`path` and `multer` are required earlier in the source file).
 */

// Set up file storage using multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images"); // Upload images to 'public/images' folder
  },
  filename: (req, file, cb) => {
    // SECURITY: Sanitize filenames to prevent directory traversal attacks
    const sanitizedFilename = path
      .basename(file.originalname)
      .replace(/[^a-zA-Z0-9_.-]/g, "_");
    const ext = path.extname(sanitizedFilename); // Get file extension
    cb(null, Date.now() + ext); // Use current timestamp as filename
  },
});

// SECURITY: Add file validation to multer
const fileFilter = (req, file, cb) => {
  // Accept only image files
  if (file.mimetype.startsWith("image/")) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed!"), false);
  }
};

// Initialize multer with storage configuration and file filter
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size to 5MB
  },
});
