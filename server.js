const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');// Read Application Cookies
// const cronScheduler = require('./commonServices/cronScheduler');
const path = require('path');
//scheduler lock file should be removed before running the scheduler
const corsOption = {
  origin: ["http://localhost:3000"],
  credentials: true
};
const AuthRoutes = require('./routes/AuthUrl');
const productRoutes = require('./routes/productRoutes')
const port = process.env.PORT || 7000;

// if (cluster.isMaster) {
//   console.log(`Master ${process.pid} is running`);
//   // Fork workers.
//   for (let i = 0; i < numCPUs; i++) {
//     cluster.fork();
//   }

//   cluster.on('exit', (worker, code, signal) => {
//     console.log(`worker ${worker.process.pid} died`);
//   });
// } else {
  const app = express();
  // Use cookie-parser middleware
  app.use(cookieParser());
  app.use(cors(corsOption));
  app.use(express.json());
  app.use('/public', express.static(path.join(__dirname, 'public')));
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views/index.html'));
  });




  app.get("/v1/check", (req, res) => {
    const requestedDomain = req.hostname;
    res.cookie(
      'callback-url',
      requestedDomain.toString(),
      {
        httpOnly: true,
        // secure: true,
        maxAge: 2 * 24 * 60 * 60 * 1000, // Set cookie expiration time (2 days)
        path: '/' // Set a specific path for the refresh token cookie
      }
    );
    res.cookie(
      'projectName',
      "projectOne",
      {
        httpOnly: true,
        // secure: true,
        maxAge: 2 * 24 * 60 * 60 * 1000, // Set cookie expiration time (2 days)
        path: '/' // Set a specific path for the refresh token cookie
      }
    );
    res.status(200).send('Application Is Healthy');
  })
  app.use('/auth', AuthRoutes);
  app.use("/v1/product", productRoutes)
  app.listen(port, () => {
    console.log(`Worker ${process.pid} started server at port ${port}`);
  });
// }

