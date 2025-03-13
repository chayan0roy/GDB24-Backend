const multer = require('multer');
const path = require('path');

const imageFileFilter = (req, file, cb) => {
    const fileTypes = /jpeg|jpg|png|gif|webp/;
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = fileTypes.test(file.mimetype);

    if (extname && mimetype) {
        return cb(null, true);
    } else {
        return cb(new Error('Only image files are allowed!'), false);
    }
};

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    },
});

const uploads = multer({ 
    storage: storage,
    fileFilter: imageFileFilter
});

const singleImageUpload = uploads.single('image');

const multipleImageUpload = uploads.array('images', 10);

const imageGalleryUploads = uploads.fields([
    { name: 'galleryImage', maxCount: 50 }
]);

module.exports = { uploads, singleImageUpload, multipleImageUpload, imageGalleryUploads };