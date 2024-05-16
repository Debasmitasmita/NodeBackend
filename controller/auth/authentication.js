
const { readJsonFiles, getNewAccessToken } = require('../../commonServices/commonOperation');
const apiRequirementsConfig = readJsonFiles('./config/apiRequirements.json');
const otherConfig = readJsonFiles('./config/otherFeaturesConfigs.json');
const MongoDBManager = require('../../commonServices/mongoServices');
const mongoDBManagerObj = new MongoDBManager();
const mongoConfig = readJsonFiles('./config/mongoConfig.json');
exports.grantPermission = async (req, res) => {
    try {
        var refresh_token = req.cookies['refresh_token']
        const projectName = req.projectName;
        const newAccessToken = getNewAccessToken(refresh_token, otherConfig[projectName]['tokenConfig']['secretKey'], otherConfig[projectName]['tokenConfig']['acess_expiration_delta']);
        if (newAccessToken) {
          
            var validateTokenInfo = req.validateTokenInfo;
            const Login_info = {
                "message": 'ReLogin successful',
                'success': true,
                "authProvider": "Relogin-web",
                "login_info": {
                    userFullName: validateTokenInfo.userName,
                    email: validateTokenInfo.email,
                    phone: validateTokenInfo.phone,
                    image: validateTokenInfo.image,
                    firstName: validateTokenInfo.firstName,
                    lastName: validateTokenInfo.lastName
                },
                "accessToken": newAccessToken
            };
            return res.status(200).json(Login_info);
        } else {
            message_error = { message: 'Please provide valid refresh token', error: 'Please provide valid refresh token', 'success': false };
            return res.status(400).json(message_error);
        }
    } catch (error) {
        return res.status(400).json({ "message_info": error });
    }
}


exports.newAccessToken = async (req, res) => {
    try {
        var refresh_token = req.cookies['refresh_token']
        const projectName = req.body.projectName;
        const newAccessToken = getNewAccessToken(refresh_token, otherConfig[projectName]['tokenConfig']['secretKey'], otherConfig[projectName]['tokenConfig']['acess_expiration_delta']);
        if (newAccessToken) {
            // var validateTokenInfo = req.validateTokenInfo;
            // const Login_info = {
            //     "message": 'ReLogin successful',
            //     'success': true,
            //     "authProvider":"Relogin-web",
            //     "login_info": {
            //         userFullName: validateTokenInfo.userName,
            //         email: validateTokenInfo.email,
            //         phone: validateTokenInfo.phone,
            //         image:validateTokenInfo.image,
            //         firstName: validateTokenInfo.firstName,
            //         lastName: validateTokenInfo.lastName
            //     },
            //     "accessToken":newAccessToken  
            // };
            return res.status(200).json({ accessToken: newAccessToken });
        } else {
            message_error = { message: 'Please provide valid refresh token', error: 'Please provide valid refresh token', 'success': false };
            return res.status(400).json(message_error);
        }
    } catch (error) {
        return res.status(400).json({ "message_info": error });
    }
}


exports.getuser = async (req, res) => {
    try {
        // var refresh_token = req.cookies['refresh_token']
        // const projectName = req.projectName;
        // const newAccessToken = getNewAccessToken(refresh_token, otherConfig[projectName]['tokenConfig']['secretKey'], otherConfig[projectName]['tokenConfig']['acess_expiration_delta']);
        // if (newAccessToken) {
          
        //     var validateTokenInfo = req.validateTokenInfo;
        //     const Login_info = {
        //         "message": 'ReLogin successful',
        //         'success': true,
        //         "authProvider": "Relogin-web",
        //         "login_info": {
        //             userFullName: validateTokenInfo.userName,
        //             email: validateTokenInfo.email,
        //             phone: validateTokenInfo.phone,
        //             image: validateTokenInfo.image,
        //             firstName: validateTokenInfo.firstName,
        //             lastName: validateTokenInfo.lastName
        //         },
        //         "accessToken": newAccessToken
        //     };
        //     return res.status(200).json(Login_info);
        // } else {
        //     message_error = { message: 'Please provide valid refresh token', error: 'Please provide valid refresh token', 'success': false };
        //     return res.status(400).json(message_error);
        // }
        const users= await mongoDBManagerObj.findDocuments("user",{},{})
        // const products=[{"id":1,"product_name":"T Shirt"}]
        res.json(users);

    } catch (error) {
        return res.status(400).json({ "message_info": error });
    }
}




