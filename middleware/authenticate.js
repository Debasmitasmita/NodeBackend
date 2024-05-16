
const { readJsonFiles, checkValidKeyInDictionary, validateAccessToken, logError, logInfo, logWarning } = require('../commonServices/commonOperation');
const apiRequirementsConfig = readJsonFiles('./config/apiRequirements.json');
const otherConfig = readJsonFiles('./config/otherFeaturesConfigs.json');
const checkSessionMiddleware = async (req, res, next) => {

    try {

        var refresh_token = req.cookies['refresh_token']
        const projectName = req.cookies['projectName']
        if (!refresh_token && !projectName) {
            const requestedDomain = req.hostname;
            res.cookie(
                'callback-url',
                requestedDomain.toString(),
                {
                    httpOnly: true,
                    sameSite: 'None',
                    secure: true,
                    maxAge: 2 * 24 * 60 * 60 * 1000, // Set cookie expiration time (2 days)
                    path: '/' // Set a specific path for the refresh token cookie
                }
            );
            res.cookie(
                'projectName',
                "projectOne",
                {
                    httpOnly: true,
                    sameSite: 'None',
                    secure: true,
                    maxAge: 2 * 24 * 60 * 60 * 1000, // Set cookie expiration time (2 days)
                    path: '/' // Set a specific path for the refresh token cookie
                }
            );
            return res.status(401).json({ success: false, message: "Login State Lost" });
        } else {

            console.log("project Name", projectName);
            const validateTokenInfo = validateAccessToken(refresh_token, otherConfig[projectName].tokenConfig.secretKey);
            if (validateTokenInfo) {
                req.validateTokenInfo = validateTokenInfo;
                req.projectName = projectName;
                return next();
            } else {
                return res.status(401).json({ success: false, message: "Token Not Provided" });
            }
        }

    } catch (error) {

        res.clearCookie('refresh_token', { httpOnly: true });
        return res.status(401).json({ success: false, message: "Unautorization" });
    }
}

const checkAccessTokenMiddleWare = async (req, res, next) => {
    try {
        const accessToken = req.headers.authorization.split('Bearer ').pop();
        if (!accessToken) {
            res.status(403).json({ success: false, message: "Forbidden" })
        }
        const projectName = req.cookies['projectName'] ? req.cookies['projectName'] : req.body.projectName;
        const tokenInfo = validateAccessToken(accessToken, otherConfig[projectName].tokenConfig.secretKey);
        if (tokenInfo) {
            req.tokenInfo = tokenInfo;
            return next();
        } else {
            message_error = { error: 'Invalid or expired access token', 'success': false, message: 'permission error' };
            logError({ ...message_error });
            return res.status(403).json(message_error);
        }


    } catch (error) {
        return res.status(401).json({ success: false, message: "Unautorization" })
    }
}

module.exports = { checkSessionMiddleware, checkAccessTokenMiddleWare };