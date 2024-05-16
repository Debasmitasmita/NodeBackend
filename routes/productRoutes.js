const express = require('express');
const router = express.Router();
const productController = require('../controller/productController');

router.get("/",productController.getAllProducts)
router.get("/:productId",productController.getProductById)



module.exports = router;