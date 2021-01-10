const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = function(req, res, next){
    // Get token from header
    const token = req.header('Authorization-Token');

    // Check if not token
    if(!token){
        return res.status(401).json({msg: 'No token, authirication denied'})
    }

    // Verify token
    try {
        const decode = jwt.verify(token, config.get('jwtSecret'))

        req.user = decode.user
        next()
    } catch (err) {
        res.status(401).json({msg: "Token is no valid"})
    }
}