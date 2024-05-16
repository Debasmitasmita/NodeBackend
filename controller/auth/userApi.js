// const express = require('express');
// const router = express.Router();
const bcrypt = require('bcrypt');
const { DateTime } = require('luxon');
const MongoDBManager = require('../../commonServices/mongoServices');
console.log('MongoDBManager :', MongoDBManager);
const { readJsonFiles, requestDataInjectionCheck, logError, logInfo, sendEmail, generateTokens, getNewAccessToken } = require('../../commonServices/commonOperation');
// const { send_email } = require('./emailService'); // Assuming you have an email service file

const mongoConfig = readJsonFiles('./config/mongoConfig.json');
const apiRequirementsConfig = readJsonFiles('./config/apiRequirements.json');
const otherConfig = readJsonFiles('./config/otherFeaturesConfigs.json');

const mongoDBManagerObj = new MongoDBManager();

function send_otp_email(to_email, otp) {
    const subject = "Your OTP for account verification";
    const body = `
    <html>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Account Verification OTP</title>
    </head>
    <body style="font-family: Arial, sans-serif;">

    <table cellspacing="0" cellpadding="0" width="100%">
        <tr>
            <td style="padding: 20px;">
                <h2 style="text-align: center; color: #333;">Account Verification OTP</h2>
                <p style="text-align: center;">Please use the following OTP to verify your account:</p>
                <div style="text-align: center; font-size: 24px; color: #007bff; padding: 10px; border: 2px solid #007bff; border-radius: 5px; margin-top: 20px;">${otp}</div>
            </td>
        </tr>
    </table>

    </body>
    </html>

    `;
    sendEmail(subject, body, to_email);
}

exports.registerUser = async (req, res) => {
    try {
        // console.log('req.body :', req.body);
        const projectName = req.cookies['projectName']
        if (!req.body || !projectName) {
            const message_error = { error: 'Please provide Project Name', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        // const { projectName } = req.body;
        if (!apiRequirementsConfig[projectName]) {
            const message_error = { error: 'projectName does not exist', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const userFieldsConfig = apiRequirementsConfig[projectName].registerFields;
        const userFields = Object.keys(userFieldsConfig);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }
        // console.log('userData :', userData);
        const existingUser = await mongoDBManagerObj.findDocuments(mongoConfig[projectName].userCol, { email: userData.email, phone: userData.phone }, {});
        if (existingUser.length === 0) {
            const hashed_password = await bcrypt.hash(userData.password, 10);
            userData.password = hashed_password;
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            var emailVefData = {
                otp,
                otpTimeStamp: DateTime.now(),
                numOfEmailVefFailAttempt: 0,
                blockedTillEmailVefTimeStamp: DateTime.now(),
                verified: false,
            };
            userData.emailVefData = emailVefData;
            userData['numOfLoginFailAttempt'] = 0
            userData['blockTillLogInTimeStamp'] = DateTime.now()
            // You need to implement the send_otp_email function
            send_otp_email(userData.email, otp);
            var { emailVefData, ...userDataSendRes } = userData;
            await mongoDBManagerObj.insertDocument(mongoConfig[projectName].userCol, userData);
            const message_info = { message: `User: ${userData.userName} registered successfully`, projectName, 'success': true, data: userDataSendRes };
            logInfo({ ...message_info });
            return res.status(200).json(message_info);
        } else {
            const message_info = { error: `User: ${userData.userName} already exists`, projectName, 'success': false, message: 'User already exists' };
            logInfo({ ...message_info });
            return res.status(409).json(message_info);
        }
    } catch (err) {
        console.error('error in registering user-->', err);
        const message_error = { message: `Error in registering user`, success: false, error: err.message };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }
};

exports.forgotPasswordOnUserId = async (request, res) => {
    try {
        if (!request || !request.body || !request.body.projectName) {
            const message_error = { error: 'Please provide Project Name', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const projectName = request.body.projectName;
        console.log('-----1', projectName);

        if (!apiRequirementsConfig[projectName]) {
            const message_error = { error: 'projectName does not exist', success: false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const userFieldsConfig = apiRequirementsConfig[projectName]['forgotPassword'];
        const userFields = Object.keys(userFieldsConfig);
        console.log('-----3', userFields);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        const dbUserDataArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, {});

        if (dbUserDataArr.length === 0) {
            console.log("User doesn't exists");
            const message_info = { error: `User: ${userData['userName']} does not exist`, 'projectName': projectName, 'success': false, message: 'User does not exist' };
            logInfo({ ...message_info });
            return res.status(404).json(message_info);
        } else {
            const dbUserData = dbUserDataArr[0];
            console.log("User exists");
            const pwdReset = dbUserData['pwdReset'] || {};
            console.log('pwdReset', pwdReset);
            const otp = Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join('');

            if (Object.keys(pwdReset).length === 0) {
                pwdReset['otp'] = otp;
                pwdReset['otpTimeStamp'] = DateTime.now();
                pwdReset['blockedTillMulForgotTimeStamp'] = DateTime.now();
                pwdReset['numOfMulForgotFailAttempt'] = 0;
                pwdReset['passWordResetVefFailAttempt'] = 0;
                dbUserData['pwdReset'] = pwdReset;
            } else {
                if (DateTime.now() < (pwdReset['blockedTillMulForgotTimeStamp'] || DateTime.now())) {
                    const message_info = { error: `User: ${userData['userName']} is blocked for password verification till ${pwdReset['blockedTillMulForgotTimeStamp'] || DateTime.now()}`, 'projectName': projectName, 'success': false, message: 'User is blocked for password verification' };
                    logInfo({ ...message_info });
                    return res.status(200).json(message_info);
                } else {
                    pwdReset['otp'] = otp;
                    pwdReset['otpTimeStamp'] = DateTime.now();
                    pwdReset['numOfMulForgotFailAttempt'] = (pwdReset['numOfMulForgotFailAttempt'] || 0) + 1;

                    if (pwdReset['numOfMulForgotFailAttempt'] >= 3) {
                        pwdReset['blockedTillMulForgotTimeStamp'] = DateTime.now().plus({ minutes: otherConfig[projectName].verifyUser.blockedTillEmailMinutes }).toJSDate() // 30 minutes
                        pwdReset['numOfMulForgotFailAttempt'] = 0;
                        pwdReset['passWordResetVefFailAttempt'] = 0;
                    }
                    dbUserData['pwdReset'] = pwdReset;
                }
            }

            console.log('userData--', dbUserData);
            send_otp_email(dbUserData['email'], otp);
            console.log('------5');
            await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { 'userName': dbUserData['userName'] }, { '$set': dbUserData });

            const message_info = { message: `User: ${userData['userName']} Otp sent to your registered email`, 'projectName': projectName, 'success': true };
            logInfo({ ...message_info });
            return res.status(200).json(message_info);
        }
    } catch (err) {
        console.log('error in resetting user password-->', err);
        const message_error = { message: 'Error in resetting user password: ', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }

}

exports.passWordResetVerification = async (request, res) => {
    try {
        if (!request || !request.body || !request.body.projectName) {
            const message_error = { error: 'Please provide Project Name', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const projectName = request.body.projectName;
        console.log('-----1', projectName);

        if (!apiRequirementsConfig[projectName]) {
            const message_error = { error: 'projectName does not exist', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const userFieldsConfig = apiRequirementsConfig[projectName]['passWordReset'];
        const userFields = Object.keys(userFieldsConfig);
        console.log('-----3', userFields);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }
        console.log('-----5', userData);

        const userDbArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, {});
        const userDb = userDbArr.length > 0 ? userDbArr[0] : {};

        if (Object.keys(userDb).length === 0) {
            console.log("User doesn't exist");
            const message_error = { error: `User: ${userData['userName']} does not exist`, 'projectName': projectName, 'success': false, message: 'User does not exist' };
            logError({ ...message_error });
            return res.status(404).json(message_error);
        } else {
            console.log("User exists");
            const pwdresetData = userDb['pwdReset'] || {};

            if (Object.keys(pwdresetData).length === 0) {
                const message_error = { error: `User: ${userData['userName']} does not have otp`, 'projectName': projectName, 'success': false, message: 'User does not have otp' };
                logError({ ...message_error });
                return res.status(400).json(message_error);
            }

            if (pwdresetData['blockedTillMulForgotTimeStamp'] !== null && DateTime.now() < (pwdresetData['blockedTillMulForgotTimeStamp'] || DateTime.now())) {
                const message_info = { error: `User: ${userData['userName']} blocked due to multiple otp fail attempts till ${pwdresetData['blockedTillMulForgotTimeStamp']}`, 'projectName': projectName, 'success': false, message: 'User is blocked for password verification' };
                logInfo({ ...message_info });
                return res.status(400).json(message_info);
            }

            if ((DateTime.now() - new Date(pwdresetData['otpTimeStamp'])) > otherConfig[projectName]['verifyUser']['blockedTillEmailMinutes'] * 60000) {
                return res.status(400).json({ error: 'Otp expired', 'projectName': projectName, 'success': false, message: 'Otp expired' });
            }

            if ((DateTime.now() - new Date(pwdresetData['otpTimeStamp'])) < 5 * 60000) {
                if (pwdresetData['otp'] !== userData['otp']) {
                    pwdresetData['passWordResetVefFailAttempt'] += 1;
                    if (pwdresetData['passWordResetVefFailAttempt'] >= 3) {
                        pwdresetData['blockedTillMulForgotTimeStamp'] = DateTime.now().plus({ minutes: otherConfig[projectName]['verifyUser']['blockedTillEmailMinutes'] }).toJSDate()
                        pwdresetData['passWordResetVefFailAttempt'] = 0;
                    }
                    userDb['pwdReset'] = pwdresetData;
                    await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, { '$set': userDb });
                    const message_error = { error: `User: ${userData['userName']} Invalid otp`, 'projectName': projectName, 'success': false, message: 'Invalid otp' };
                    logError({ ...message_error });
                    return res.status(400).json(message_error);
                } else {
                    pwdresetData['passWordResetVefFailAttempt'] = 0;
                    userDb['blockTillLogInTimeStamp'] = DateTime.now();
                    pwdresetData['otp'] = Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join('');
                    const hashed_password = await bcrypt.hash(userData['newPassword'], 10);
                    pwdresetData['password'] = hashed_password;
                    userDb['pwdReset'] = pwdresetData;
                    await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, { '$set': userDb });
                    const message_info = { message: `User: ${userData['userName']} Password reset successfully`, 'projectName': projectName, 'success': true };
                    logInfo({ ...message_info });
                    return res.status(200).json(message_info);
                }
            }
        }
    } catch (err) {
        console.log('error in resetting user password-->', err);
        const message_error = { message: 'Error in resetting user password ', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }

}


exports.loginUser = async (req, res) => {
    try {
        const requestData = req.body;
        const projectName = req.cookies['projectName']

        if (!requestData || !requestData || !projectName) {
            return res.status(400).json({ error: 'Please provide Project Name', 'success': false, message: 'Input error' });
        }
        // const projectName = projectName;
        if (!apiRequirementsConfig[projectName]) {
            return res.status(400).json({ error: 'projectName does not exist', 'success': false, message: 'Input error' });
        }
        const userFieldsConfig = apiRequirementsConfig[projectName]['loginFields'];
        const userFields = Object.keys(userFieldsConfig);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        console.log("login dta", userData);
        const query = {
            $or: [
                {
                    email: userData['loginId']
                },
                {
                    phone: userData['loginId']
                }
            ]
        }
        const storedData = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['userCol'], query, {});
        console.log("storedData", storedData);
        if (storedData.length > 0) {

            const storedHashedPassword = storedData[0].password;
            const providedPassword = userData['password'];
            if (storedData[0].blockTillLogInTimeStamp > DateTime.now()) {
                console.log("User is blocked till", storedData[0].blockTillLogInTimeStamp);
                return res.status(200).json({ message: 'User is blocked', 'success': false, message: 'User is blocked' });
            }
            if (bcrypt.compareSync(providedPassword, storedHashedPassword)) {
                console.log("Password is correct");
                const payload = {
                    userName: storedData[0].userName,
                    firstName: storedData[0].firstName,
                    lastName: storedData[0].lastName,
                    image:null,
                    email: storedData[0].email,
                    phone: storedData[0].phone,
                    role: "user"
                };
                const tokens = generateTokens(payload, otherConfig[projectName]['tokenConfig']['secretKey'], otherConfig[projectName]['tokenConfig']['acess_expiration_delta'], otherConfig[projectName]['tokenConfig']['refresh_expiration_delta']);
                const message_info = {
                    "message": 'Login successful',
                    "authProvider":"login-web",
                    'success': true,
                    "login_info": {
                        userFullName: storedData[0].userName,
                        email: storedData[0].email,
                        phone: storedData[0].phone,
                        firstName: storedData[0].firstName,
                        lastName: storedData[0].lastName
                    },
                    "accessToken": tokens.access_token
                };
                logInfo({ ...message_info });
                // Set access token in the response headers
                res.setHeader('Authorization', `Bearer ${tokens.access_token}`);
                // Set refresh token in a secure cookie
                res.cookie(
                    'refresh_token',
                    tokens.refresh_token.toString(),
                    {
                        httpOnly: true,
                        sameSite: 'None',
                        secure: true,
                        maxAge: 2 * 24 * 60 * 60 * 1000, // Set cookie expiration time (2 days)
                        path: '/' // Set a specific path for the refresh token cookie
                    }
                );
                return res.status(200).json(message_info);
            } else {
                // Handle incorrect password case
                if (storedData[0].numOfLoginFailAttempt >= otherConfig[projectName]['verifyUser']['numOfLoginFailAttempt']) {
                    const updateDataTemp = { blockTillLogInTimeStamp: DateTime.now().plus({ minutes: otherConfig[projectName]['verifyUser']['blockedTillEmailMinutes'] }) };
                    await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { '_id': storedData[0]['_id'] }, { '$set': updateDataTemp });
                }
                const numOfLoginFailAttempt = { numOfLoginFailAttempt: storedData[0].numOfLoginFailAttempt + 1 };
                await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { '_id': storedData[0]['_id'] }, { '$set': numOfLoginFailAttempt });
                console.log("Incorrect password");
                let message_error = { message: 'Incorrect password', 'success': false, error: 'Incorrect password' };
                logError({ ...message_error });
                return res.status(401).json(message_error);
            }

        } else {
            return res.status(404).json({ error: 'User does not exist', 'success': false, message: 'User Not Found' });

        }
    } catch (err) {
        console.error('error in login user-->', err);
        const message_error = { message: 'error in login user', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }
}

exports.emailVerifyUser = async (req, res) => {
    try {
        const requestData = req.body;

        const projectName = projectName || '';
        const userFieldsConfig = apiRequirementsConfig[projectName].verifyUser;
        const userFields = Object.keys(userFieldsConfig);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        const tokenInfo = req.tokenInfo;
        const userName = tokenInfo.userName;
        console.log("Verifying user: ", userName, userData);
        if (userName !== userData.userName) {
            message_error = { message: 'userName mismatch', error: 'userName mismatch', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const userDataFromDbArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName].userCol, { 'userName': userData.userName }, {});
        const userDataFromDb = userDataFromDbArr.length > 0 ? userDataFromDbArr[0] : {};

        if (Object.keys(userDataFromDb).length === 0) {
            message_error = { message: 'user not found', error: 'user not found', 'success': false, error: 'user not found' };
            logError({ ...message_error });
            return res.status(404).json(message_error);
        }

        const emailVefData = userDataFromDb.emailVefData || {};

        if (emailVefData.otpTimeStamp < DateTime.now().minus({ minutes: otherConfig[projectName].verifyUser.otpExpiration }).toJSDate()) {
            message_error = { message: 'otp expired', error: 'otp expired', 'success': false, error: 'otp expired' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        if (userDataFromDb.email !== userData.email) {
            message_error = { message: 'email mismatch', error: 'email mismatch', 'success': false, error: 'email mismatch' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        if (emailVefData.blockedTillEmailVefTimeStamp > DateTime.now().toJSDate()) {
            message_error = { message: 'user blocked', error: 'user blocked', 'success': false, error: 'User blocked till' + emailVefData.blockedTillEmailVefTimeStamp };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        if (emailVefData.otp !== userData.otp) {
            if (emailVefData.numOfEmailVefFailAttempt >= otherConfig[projectName].verifyUser.numOfEmailVefFailAttempt) {
                const updateDataTemp = { 'emailVefData.blockedTillEmailVefTimeStamp': DateTime.now().plus({ minutes: otherConfig[projectName].verifyUser.blockedTillEmailMinutes }).toJSDate() };
                await mongoDBManagerObj.updateDocument(mongoConfig[projectName].userCol, { 'userName': userData.userName }, { '$set': updateDataTemp });
                message_error = { message: 'Maximum number of failed attempts reached', error: 'Maximum number of failed attempts reached', 'success': false, error: 'Maximum number of failed attempts reached' };
                logError({ ...message_error });
                return res.status(400).json(message_error);
            }

            const updateDataTemp = { 'emailVefData.numOfEmailVefFailAttempt': userDataFromDb.emailVefData.numOfEmailVefFailAttempt + 1 };
            await mongoDBManagerObj.updateDocument(mongoConfig[projectName].userCol, { 'userName': userData.userName }, { '$set': updateDataTemp });
            message_error = { message: 'Wrong otp', error: 'Wrong otp', 'success': false, error: 'Wrong otp' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        if (emailVefData.otp === userData.otp && userDataFromDb.email === userData.email) {
            if (emailVefData.verified === true) {
                message_error = { message: 'User already verified', error: 'User already verified', 'success': false, error: 'User already verified' };
                logError({ ...message_error });
                return res.status(400).json(message_error);
            } else {
                const updateDataTemp = {
                    'emailVefData.verified': true,
                    'emailVefData.numOfEmailVefFailAttempt': 0,
                    'emailVefData.otpTimeStamp': DateTime.now().toJSDate(),
                    'emailVefData.blockedTillEmailVefTimeStamp': DateTime.now().toJSDate()
                };
                await mongoDBManagerObj.updateDocument(mongoConfig[projectName].userCol, { 'userName': userData.userName }, { '$set': updateDataTemp });
                message_error = { message: 'User verified successfully', error: 'User verified successfully', 'success': true };
                return res.status(200).json(message_error);
            }
        }
    } catch (err) {
        console.error('err--->', err);
        message_error = { message: 'Error in verify user', error: 'Error in verify user', 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }
}

exports.updateUserEmail = async (request, res) => {
    try {
        const projectName = request.body.projectName;
        console.log('-----1', projectName);

        const userFieldsConfig = apiRequirementsConfig[projectName]['changeEmail'];
        const userFields = Object.keys(userFieldsConfig);
        console.log('-----3', userFields);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, request.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        console.log('-----5', userData);

        const tokenInfo = request.tokenInfo;
        console.log('-----4', tokenInfo);
        const userName = tokenInfo.userName;

        if (userName !== userData.userName) {
            message_error = { message: 'wrong token', 'success': false, error: 'user name mismatch/wrong token' };
            return res.status(400).json(message_error);
        }

        console.log('-----5', mongoConfig[projectName]['userCol']);

        const userDataFromDbArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['userCol'], { userName: userData.userName }, {});
        const userDataFromDb = userDataFromDbArr.length > 0 ? userDataFromDbArr[0] : {};
        console.log('-----6', userDataFromDb);

        if (!userDataFromDb) {
            message_error = { message: 'User not found', error: 'User not found', 'success': false };
            return res.status(404).json(message_error);
        }

        if (userDataFromDb.email === userData.newEmail) {
            message_error = { message: 'same  email id cannot update', error: 'same  email id cannot update', 'success': false };
            return res.status(400).json(message_error);
        }

        console.log('-----7');

        const otp = Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join('');
        const updateDataTemp = {
            email: userData.newEmail,
            'emailVefData.verified': false,
            'emailVefData.otp': otp
        };

        await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { userName: userData.userName }, { '$set': updateDataTemp });
        message_info = { message: 'Email added  successfully to verify call verifyUser api', 'success': true };
        logInfo({ ...message_info });
        return res.status(200).json(message_info);

    } catch (err) {
        console.error('err--->', err);
        message_error = { message: 'Error in update email', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }

}

exports.getNewAcessToken = async (request, res) => {
    try {
        if (!request || !request.body || !request.body.projectName) {
            message_error = { message: 'Please provide projectName', error: 'Please provide projectName', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const projectName = request.body.projectName;
        console.log('-----1', projectName);

        if (!apiRequirementsConfig[projectName]) {
            message_error = { message: 'projectName does not exist', error: 'projectName does not exist', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        if (!request.body.refresh_token) {
            message_error = { message: 'Please provide refresh token', error: 'Please provide refresh token', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const refresh_tokenArr = request.body.refresh_token.split('refresh_token=');
        console.log('\n\n-----refresh_tokenArr---', refresh_tokenArr);
        const refresh_token = refresh_tokenArr[refresh_tokenArr.length - 1].split(';')[0];
        console.log('\n\n-----refresh_token---', refresh_token);
        const acessToken = getNewAccessToken(refresh_token, otherConfig[projectName]['tokenConfig']['secretKey'], otherConfig[projectName]['tokenConfig']['acess_expiration_delta']);

        if (!acessToken) {
            message_error = { message: 'Please provide valid refresh token', error: 'Please provide valid refresh token', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }
        res.setHeader('Authorization', `Bearer ${acessToken}`);
        return res.status(200).json({ message: 'Token Refreshed', access_token: acessToken });
    } catch (err) {
        console.log('error in getNewAcessToken-->', err);
        return res.status(500).json({ message: 'Error in getting new Refresh Token' });
    }

}

exports.AssignRoleToUser = async (request, res) => {
    try {
        if (!request || !request.body || !request.body.projectName) {
            message_error = { message: 'Please provide projectName', error: 'Please provide projectName', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const projectName = request.body.projectName;

        if (!apiRequirementsConfig[projectName]) {
            message_error = { message: 'projectName does not exist', error: 'projectName does not exist', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const userFieldsConfig = apiRequirementsConfig[projectName]['AssignRoleToUser'];
        const userFields = Object.keys(userFieldsConfig);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        const userName = request.body.userName;
        const userNameToBeAssignedRole = request.body.userNameToAssignRole;
        const assignedRoleName = request.body.assignedRoleName;

        const rolesArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['apiSettings'], { settingName: "ApisAllowedRoles" }, {});
        if (rolesArr.length === 0 || !rolesArr[0][assignedRoleName]) {
            message_error = { message: `Invalid role name ${assignedRoleName}`, error: `Invalid role name ${assignedRoleName}`, 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        const tokenInfo = request.tokenInfo;
        const tokenUserName = tokenInfo.userName;

        if (tokenUserName !== userData.userName) {
            message_error = { message: 'wrong token', error: 'wrong token', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['apiSettings'], { settingName: "userIdWithRoles" }, { '$push': { 'role': userData.role } });
        message_info = { message: 'Role Assigned', 'success': true };
        logInfo({ ...message_info });
        return res.status(200).json(message_info);
    } catch (err) {
        console.log('err--->', err);
        message_error = { message: 'Error in AssignRoleToUser', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }

}

exports.updateUserBasicData = async (request, res) => {
    try {
        const projectName = request.body['projectName'];
        console.log('-----1', projectName);

        const userFieldsConfig = apiRequirementsConfig[projectName]['changeBasicData'];
        const userFields = Object.keys(userFieldsConfig);
        console.log('-----3', userFields);

        const userData = requestDataInjectionCheck(userFields, userFieldsConfig, req.body);
        if (userData.error) {
            const message_error = { message: 'input error', error: JSON.stringify(userData.error), 'success': false };
            logError({ ...message_error });
            return res.status(500).json(message_error);
        }

        const tokenInfo = request.tokenInfo;
        console.log('-----4', tokenInfo);
        const userName = tokenInfo['userName'];

        if (userName !== userData['userName']) {
            message_error = { message: 'wrong token', error: 'wrong token', 'success': false };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }

        console.log('-----5', mongoConfig[projectName]['userCol']);
        const userDataFromDbArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, {});
        const userDataFromDb = userDataFromDbArr.length > 0 ? userDataFromDbArr[0] : {};

        console.log('-----6', userDataFromDb);
        if (!userDataFromDb) {
            message_error = { message: 'User not found', error: 'User not found', 'success': false };
            logError({ ...message_error });
            return res.status(404).json(message_error);
        }

        console.log('-----7');
        const updateDataTemp = userData;
        await mongoDBManagerObj.updateDocument(mongoConfig[projectName]['userCol'], { 'userName': userData['userName'] }, { '$set': updateDataTemp });
        message_info = { message: 'User Basic data updated successfully', 'success': true, data: userData };
        logInfo({ ...message_info });
        return res.status(200).json(message_info);
    } catch (err) {
        console.log('Error in update basic data-->', err);
        message_error = { message: 'Error in update basic data', error: err.message, 'success': false };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }

}
