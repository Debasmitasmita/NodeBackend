

const ProductController = {

    getAllProducts: async (req, res) => {
        try {
            // const products = await ProductService.getAllProducts();
            const products=[{"id":1,"product_name":"T Shirt"}]
            res.json(products);
        } catch (error) {
            console.error('Error fetching products:', error);
            res.status(500).json({ error: 'Could not fetch products' });
        }
    },

    getProductById: async (req, res) => {
        try {
            // const product = await ProductService.getProductById(req.params.productId);
            // if (!product) {
            //     return res.status(404).json({ error: 'Product not found' });
            // }
            product = [{ "id": req.params.productId }]
            res.json(product);
        } catch (error) {
            console.error('Error fetching product:', error);
            res.status(500).json({ error: 'Could not fetch product' });
        }
    },

}
module.exports = ProductController;