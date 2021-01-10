const express = require('express')
const router = express.Router()
const auth = require('../../middleware/auth')
const bycrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const { check, validationResult } = require('express-validator')

// Model Schema
const User = require('../../models/User')

// @route   POST api/auth
// @desc    Test route
// @access  Public
router.post('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password')

        res.json(user)
    } catch (err) {
        console.log(err.message);
        res.stastus(500).send('Server Error')
    }
})

// @route   POST api/auth
// @desc    Authenticate User & get token
// @access  Public
router.post('/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
],
    async (req, res) => {
        // Checking error from body req
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { email, password } = req.body

        try {
            // See if user doesn't exists
            let user = await User.findOne({ email });
            if (!user) {
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'Invalid Credentials' }] });
            }

            const isMatch = await bycrypt.compare(password, user.password)
            if(!isMatch){
                return res
                    .status(400)
                    .json({erros: [{msg: 'Invalid Credentials'}]})
            }

            // Return jsonwebtoken
            const payload = {
                user: {
                    id: user.id
                }
            }
            jwt.sign(
                payload,
                config.get('jwtSecret'),
                { expiresIn: 36000 },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            )
        } catch (err) {
            console.log(err.message);
            res.status(500).send('Server error');
        }
    })

module.exports = router