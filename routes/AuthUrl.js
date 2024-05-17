const express = require('express');
const router = express.Router();
const customMiddleware = require('../middleware/customMidddleware');
const authenticationController = require("../controller/auth/authentication")
const userController = require('../controller/auth/userApi');

const authenticationMiddleware = require('../middleware/authenticate');

router.post('/register', userController.registerUser);
router.get('/forGotPasswordOnUserId', customMiddleware, userController.forgotPasswordOnUserId);
router.post('/login', userController.loginUser);
router.post('/logout', authenticationMiddleware.checkSessionMiddleware, (req, res) => {
  // Assuming the cookie name is 'session'
  res.clearCookie('refresh_token', {
    httpOnly: true,
    sameSite: 'None',
    secure: true
  });

  // Send a response indicating successful logout
  res.status(200).send('Logged out successfully');
});
router.get("/session", authenticationMiddleware.checkSessionMiddleware, authenticationController.grantPermission);
router.post('/refresh', authenticationMiddleware.checkSessionMiddleware, authenticationController.newAccessToken);

router.post('/passWordResetVerification', customMiddleware, userController.passWordResetVerification);
router.post('/emailVerifyUser', customMiddleware, userController.emailVerifyUser);
router.post('/updateUserEmail', customMiddleware, userController.updateUserEmail);
router.post('/updateUserBasicData', customMiddleware, userController.updateUserBasicData);
router.post('/roleAccess/AssignRoleToUser', customMiddleware, userController.AssignRoleToUser);

router.get('/getUsers',authenticationMiddleware.checkAccessTokenMiddleWare,authenticationController.getuser)
module.exports = router;